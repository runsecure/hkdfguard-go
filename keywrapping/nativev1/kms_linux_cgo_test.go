//go:build linux && cgo

package nativev1

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/runsecure/hkdfguard-go"
)

// The Linux loader against this machine's dynamic linker, and the Linux native library's contract
// against the real KEK provider - on a TPM host, provisioned by scripts/provision-linux-test-key.sh:
//
//	sudo scripts/provision-linux-test-key.sh
//	HKDFGUARD_TEST_SERVICE=com.hkdfguard.native.linux.test \
//	HKDFGUARD_TEST_SERVICE_OTHER=com.hkdfguard.native.linux.test.other \
//	CGO_ENABLED=1 go test ./...
//
// native_test.go covers what every platform shares; these pin down the exact Linux status codes,
// the native library's own input checks (which the KeyWrapper's validation normally keeps it from
// seeing), its zeroing on failure, and the deployment path through hkdfguard-v1-initialize.

const (
	linuxPolicyPath = "/etc/hkdfguard/policy.toml"
	linuxCLI        = "/usr/bin/hkdfguard-v1-initialize"

	// processHardeningVariable opts in to the test that hardens this very test process.
	processHardeningVariable = "HKDFGUARD_TEST_PROCESS_HARDENING"
)

// platformTestEnvironment: the Linux library has no non-prompting way to ask whether a KEK exists
// that the tests rely on, so the round trips run only with the variables the provisioning script
// prints.
func platformTestEnvironment(defaultService string) testEnvironment {
	return testEnvironment{skipReason: fmt.Sprintf("Set %s to a service provisioned with hkdfguard-v1-initialize to run native integration tests. On a Linux TPM host, sudo scripts/provision-linux-test-key.sh provisions %s.", testServiceVariable, defaultService)}
}

// --- The dynamic linker -----------------------------------------------------------------------

func TestLinuxSystem_ThisProcesssLibc_IsLoadedFromATrustedFile(t *testing.T) {
	libc, ok := linuxLoadedPath("libc.so.6")
	if !ok {
		t.Fatal("libc.so.6 is not loaded")
	}

	resolved, err := linuxTrustedFile(libc)

	if err != nil || !strings.HasPrefix(resolved, "/") {
		t.Errorf("libc at %q resolves to %q, %v", libc, resolved, err)
	}
}

func TestLinuxSystem_ANameNothingIsLoadedUnder_HasNoLoadedPath(t *testing.T) {
	if path, ok := linuxLoadedPath("libhkdfguard-never-loaded.so.0"); ok {
		t.Errorf("got %q", path)
	}
}

func TestLinuxSystem_TheInstalledLibrary_LoadsThroughTheVerifiedLoader_AndItsDependenciesAreTrusted(t *testing.T) {
	installed := installedLinuxLibraryPath(t)
	library := installedLibrary(t)

	// Through the binding: a wrap for a service nobody provisioned. Whatever this host's providers
	// say, the answer is a status code the binding can describe.
	status, _ := library.wrapDEK("hkdfguard.loadertest.unprovisioned", make([]byte, DEKLength), make([]byte, hkdfguard.MaxWrappedKeyBytes))
	if status != statusOK && library.describeStatus(status) == "" {
		t.Errorf("undescribed status %d", status)
	}

	// What the dynamic linker mapped is the verified file, and every dependency it pulled in
	// came from a trusted file.
	dl, ok := library.(*dlLibrary)
	if !ok {
		t.Fatalf("loaded library is a %T", library)
	}
	expected, err := linuxTrustedFile(installed)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := linuxTrustedFile(dlImagePath(dl.wrap))
	if err != nil || loaded != expected {
		t.Errorf("the linker mapped %q, %v; want %q", loaded, err, expected)
	}
	if err := linuxVerifyDependencies(expected, elfReadNeededFile, linuxLoadedPath, linuxTrustedFile); err != nil {
		t.Errorf("dependencies: %v", err)
	}
}

// --- The library's contract --------------------------------------------------------------------

func linuxProvisionedLibrary(t *testing.T) (kmsLibrary, string) {
	t.Helper()
	installedLinuxLibraryPath(t)
	w := provisionedWrapper(t)
	return w.library, w.service
}

func linuxWrap(t *testing.T, library kmsLibrary, service string, dek []byte) []byte {
	t.Helper()
	wrapped := make([]byte, hkdfguard.MaxWrappedKeyBytes)
	status, written := library.wrapDEK(service, dek, wrapped)
	if status != statusOK {
		t.Fatalf("wrapDEK = %d (%s)", status, library.describeStatus(status))
	}
	return wrapped[:written]
}

// requireLinuxStatus checks a status, and that the binding describes it.
func requireLinuxStatus(t *testing.T, library kmsLibrary, expected, actual int32) {
	t.Helper()
	if actual != expected {
		t.Errorf("status = %d (%s), want %d (%s)", actual, library.describeStatus(actual), expected, library.describeStatus(expected))
	}
	if library.describeStatus(actual) == "" {
		t.Errorf("status %d has no description", actual)
	}
}

func requireZero(t *testing.T, what string, b []byte) {
	t.Helper()
	if !hkdfguard.IsZero(b) {
		t.Errorf("%s was not zeroed: %v", what, b)
	}
}

func repeat(b byte, n int) []byte { return bytes.Repeat([]byte{b}, n) }

func TestLinuxNative_AWrappedDEK_RoundTrips_AndFitsTheKeyFileLimit(t *testing.T) {
	library, service := linuxProvisionedLibrary(t)
	dek := randomDEK(t)

	wrapped := linuxWrap(t, library, service, dek)
	recovered := make([]byte, DEKLength)
	status, written := library.unwrapDEK(service, wrapped, recovered)

	requireLinuxStatus(t, library, statusOK, status)
	if written != DEKLength || !bytes.Equal(recovered, dek) {
		t.Errorf("unwrapDEK wrote %d bytes; recovered the DEK: %v", written, bytes.Equal(recovered, dek))
	}
	if len(wrapped) <= DEKLength || len(wrapped) > hkdfguard.MaxWrappedKeyBytes {
		t.Errorf("payload is %d bytes", len(wrapped))
	}
}

func TestLinuxNative_WrappingTheSameDEKTwice_GivesDifferentPayloads(t *testing.T) {
	// A fresh salt per payload: equal DEKs must not be recognizable from their wrapped form.
	library, service := linuxProvisionedLibrary(t)
	dek := randomDEK(t)

	if bytes.Equal(linuxWrap(t, library, service, dek), linuxWrap(t, library, service, dek)) {
		t.Error("two wraps of one DEK gave the same payload")
	}
}

func TestLinuxNative_GeneratedDEKs_AreDistinct(t *testing.T) {
	library, service := linuxProvisionedLibrary(t)

	seen := map[string]bool{}
	for i := 0; i < 4; i++ {
		wrapped := make([]byte, hkdfguard.MaxWrappedKeyBytes)
		status, written := library.generateAndWrapDEK(service, wrapped)
		requireLinuxStatus(t, library, statusOK, status)

		dek := make([]byte, DEKLength)
		status, _ = library.unwrapDEK(service, wrapped[:written], dek)
		requireLinuxStatus(t, library, statusOK, status)
		seen[string(dek)] = true
	}
	if len(seen) != 4 {
		t.Errorf("%d distinct DEKs out of 4", len(seen))
	}
}

func TestLinuxNative_UnwrappingUnderAnotherProvisionedService_IsAFingerprintMismatch_AndZeroesTheWholeBuffer(t *testing.T) {
	library, service := linuxProvisionedLibrary(t)
	if os.Getenv(testOtherServiceVariable) == "" {
		t.Skipf("set %s to a second provisioned service", testOtherServiceVariable)
	}

	wrapped := linuxWrap(t, library, service, randomDEK(t))
	destination := repeat(0xAA, 64)
	status, _ := library.unwrapDEK(otherServiceName(), wrapped, destination)

	requireLinuxStatus(t, library, linuxErrFingerprintMismatch, status)
	requireZero(t, "the destination", destination)
}

func TestLinuxNative_AServiceTheAllowlistDoesNotName_HasNoKEK(t *testing.T) {
	library, _ := linuxProvisionedLibrary(t)
	if !linuxPolicyRequiresPinnedNames() {
		t.Skipf("%s does not set tpm.require_pinned_names = true (scripts/provision-linux-test-key.sh does)", linuxPolicyPath)
	}

	status, _ := library.wrapDEK(unprovisionedServiceName, make([]byte, DEKLength), make([]byte, hkdfguard.MaxWrappedKeyBytes))
	requireLinuxStatus(t, library, linuxErrKEKNotFound, status)
	status, _ = library.generateAndWrapDEK(unprovisionedServiceName, make([]byte, hkdfguard.MaxWrappedKeyBytes))
	requireLinuxStatus(t, library, linuxErrKEKNotFound, status)
	if !strings.Contains(library.describeStatus(linuxErrKEKNotFound), "provision") {
		t.Errorf("KEK not found = %q", library.describeStatus(linuxErrKEKNotFound))
	}
}

func linuxPolicyRequiresPinnedNames() bool {
	policy, err := os.ReadFile(linuxPolicyPath)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(policy), "\n") {
		if strings.ReplaceAll(line, " ", "") == "require_pinned_names=true" {
			return true
		}
	}
	return false
}

func TestLinuxNative_ChangingAnyByteOfThePayload_IsRefused_AndRevealsNothing(t *testing.T) {
	// Every byte is either ciphertext or bound into the AEAD's associated data and the HKDF
	// info, so no single-byte change may unwrap - to the original DEK or to any other. Each
	// refusal can cost a TPM ECDH, so this changes the first and last eight bytes and every
	// fifth byte between: a spread that lands in every field of the payload.
	library, service := linuxProvisionedLibrary(t)
	wrapped := linuxWrap(t, library, service, randomDEK(t))

	for i := range wrapped {
		if !(i < 8 || i >= len(wrapped)-8 || i%5 == 0) {
			continue
		}
		tampered := bytes.Clone(wrapped)
		tampered[i] ^= 0x01
		destination := repeat(0xAA, DEKLength)

		status, _ := library.unwrapDEK(service, tampered, destination)

		if status != linuxErrCryptoError && status != linuxErrFingerprintMismatch {
			t.Errorf("byte %d of %d: status %d (%s)", i, len(wrapped), status, library.describeStatus(status))
		}
		requireZero(t, fmt.Sprintf("the destination after changing byte %d", i), destination)
	}
}

func TestLinuxNative_ATruncatedOrExtendedPayload_IsRefused(t *testing.T) {
	library, service := linuxProvisionedLibrary(t)
	wrapped := linuxWrap(t, library, service, randomDEK(t))
	destination := make([]byte, DEKLength)

	for _, payload := range [][]byte{wrapped[:len(wrapped)-1], append(bytes.Clone(wrapped), 0), wrapped[:8]} {
		status, _ := library.unwrapDEK(service, payload, destination)
		requireLinuxStatus(t, library, linuxErrCryptoError, status)
	}
}

func TestLinuxNative_AnEmptyPayload_IsRefused(t *testing.T) {
	library, service := linuxProvisionedLibrary(t)

	status, _ := library.unwrapDEK(service, nil, make([]byte, DEKLength))

	if status != linuxErrInvalidArgument && status != linuxErrCryptoError {
		t.Errorf("status %d (%s)", status, library.describeStatus(status))
	}
}

func TestLinuxNative_ADEKOfTheWrongLength_IsAnInvalidArgument(t *testing.T) {
	library, service := linuxProvisionedLibrary(t)

	for _, length := range []int{0, 16, DEKLength - 1, DEKLength + 1, 64} {
		status, _ := library.wrapDEK(service, make([]byte, length), make([]byte, hkdfguard.MaxWrappedKeyBytes))
		requireLinuxStatus(t, library, linuxErrInvalidArgument, status)
	}
}

func TestLinuxNative_TheLibrary_ChecksServiceNamesItself(t *testing.T) {
	// The KeyWrapper's validation normally stops these before the boundary; the library must
	// refuse them on its own too, for every operation.
	library, _ := linuxProvisionedLibrary(t)

	for _, service := range []string{"", ".leading.dot", "double..dot", "has space", "slash/inside", "dash-inside", "café", strings.Repeat("a", 129)} {
		if hkdfguard.IsValidServiceName(service) {
			t.Errorf("%q is a valid service name", service)
		}
		status, _ := library.wrapDEK(service, make([]byte, DEKLength), make([]byte, hkdfguard.MaxWrappedKeyBytes))
		requireLinuxStatus(t, library, linuxErrInvalidServiceName, status)
		status, _ = library.generateAndWrapDEK(service, make([]byte, hkdfguard.MaxWrappedKeyBytes))
		requireLinuxStatus(t, library, linuxErrInvalidServiceName, status)
		status, _ = library.unwrapDEK(service, make([]byte, 100), make([]byte, DEKLength))
		requireLinuxStatus(t, library, linuxErrInvalidServiceName, status)
	}
}

func TestLinuxNative_AServiceNameOfTheMaximumLength_IsAccepted(t *testing.T) {
	// 128 characters is valid; with the allowlist it simply has no KEK, without one it may.
	library, _ := linuxProvisionedLibrary(t)

	status, _ := library.wrapDEK(strings.Repeat("a", hkdfguard.MaxServiceNameLength), make([]byte, DEKLength), make([]byte, hkdfguard.MaxWrappedKeyBytes))

	if status == linuxErrInvalidServiceName {
		t.Error("a 128-character name was refused as invalid")
	}
}

func TestLinuxNative_ATooSmallBuffer_ReportsACapacityThatSuffices(t *testing.T) {
	// The reported capacity is an upper bound for any payload, not the exact size of this one;
	// it must fit a key file and be enough.
	library, service := linuxProvisionedLibrary(t)
	dek := randomDEK(t)

	status, required := library.wrapDEK(service, dek, make([]byte, 1))
	requireLinuxStatus(t, library, linuxErrBufferTooSmall, status)
	if required <= DEKLength || int(required) > hkdfguard.MaxWrappedKeyBytes {
		t.Fatalf("required capacity = %d", required)
	}

	exact := make([]byte, required)
	status, written := library.wrapDEK(service, dek, exact)
	requireLinuxStatus(t, library, statusOK, status)
	if written <= DEKLength || written > required {
		t.Errorf("wrote %d bytes into %d", written, required)
	}
	exact = exact[:written]

	status, generateRequired := library.generateAndWrapDEK(service, make([]byte, 1))
	requireLinuxStatus(t, library, linuxErrBufferTooSmall, status)
	if generateRequired != required {
		t.Errorf("generate requires %d, wrap required %d", generateRequired, required)
	}

	short := repeat(0xAA, DEKLength-1)
	status, unwrapRequired := library.unwrapDEK(service, exact, short)
	requireLinuxStatus(t, library, linuxErrBufferTooSmall, status)
	if unwrapRequired != DEKLength {
		t.Errorf("unwrap requires %d, want %d", unwrapRequired, DEKLength)
	}
	requireZero(t, "the short destination", short)
}

func TestLinuxNative_ConcurrentCallers_EachGetTheirOwnDEKBack(t *testing.T) {
	library, service := linuxProvisionedLibrary(t)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		dek := randomDEK(t) // on the test goroutine: a failure here may call Fatal
		wg.Add(1)
		go func() {
			defer wg.Done()
			wrapped := make([]byte, hkdfguard.MaxWrappedKeyBytes)
			status, written := library.wrapDEK(service, dek, wrapped)
			if status != statusOK {
				t.Errorf("wrapDEK = %d", status)
				return
			}
			recovered := make([]byte, DEKLength)
			if status, _ := library.unwrapDEK(service, wrapped[:written], recovered); status != statusOK || !bytes.Equal(recovered, dek) {
				t.Errorf("unwrapDEK = %d; recovered the DEK: %v", status, bytes.Equal(recovered, dek))
			}
		}()
	}
	wg.Wait()
}

func linuxRunCLI(t *testing.T, arguments ...string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, linuxCLI, arguments...)
	cmd.Stdin = nil
	output, err := cmd.CombinedOutput()
	if exit, ok := err.(*exec.ExitError); ok {
		return exit.ExitCode(), string(output)
	}
	if err != nil {
		t.Fatalf("%s: %v", linuxCLI, err)
	}
	return 0, string(output)
}

func requireCLI(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(linuxCLI); err != nil {
		t.Skipf("%s is not installed (the hkdfguard package)", linuxCLI)
	}
}

func TestLinuxNative_AKeyFileWrappedByTheProvisioningTool_RevealsItsDEKThroughTheWrapper(t *testing.T) {
	// The deployment path: hkdfguard-v1-initialize wraps a delivered DEK on the host, in its own
	// process, and the application unwraps the key file through this binding.
	_, service := linuxProvisionedLibrary(t)
	requireCLI(t)

	directory := t.TempDir()
	dek := randomDEK(t)
	dekFile := filepath.Join(directory, "dek")
	keyFile := filepath.Join(directory, "key.bin")
	if err := os.WriteFile(dekFile, []byte(base64.StdEncoding.EncodeToString(dek)), 0o600); err != nil {
		t.Fatal(err)
	}

	exitCode, output := linuxRunCLI(t, "wrap", "--key-file-path", keyFile, "--service-name", service, "--dek-file", dekFile)
	if exitCode != 0 {
		t.Fatalf("hkdfguard-v1-initialize wrap exited %d: %s", exitCode, output)
	}
	info, err := os.Stat(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("key file mode = %04o, want 0600", info.Mode().Perm())
	}

	wrapped, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	w, err := New(service)
	if err != nil {
		t.Fatal(err)
	}
	recovered := make([]byte, DEKLength)
	n, err := w.Unwrap(context.Background(), wrapped, recovered)
	if err != nil || n != DEKLength || !bytes.Equal(recovered, dek) {
		t.Errorf("Unwrap = %d, %v; recovered the DEK: %v", n, err, bytes.Equal(recovered, dek))
	}
}

func TestLinuxNative_TheProvisioningTool_ReportsTheTestServiceAsProvisioned(t *testing.T) {
	_, service := linuxProvisionedLibrary(t)
	requireCLI(t)

	if exitCode, output := linuxRunCLI(t, "provision", "--service-name", service); exitCode != 0 {
		t.Errorf("hkdfguard-v1-initialize provision exited %d: %s", exitCode, output)
	}
}

// --- Process hardening -------------------------------------------------------------------------

// Hardens this very test process, so it only runs when asked for: HKDFGUARD_TEST_PROCESS_HARDENING=1
// with the package installed. Afterwards no debugger can attach to the test binary and it writes
// no core dump.
func TestLinuxNative_HardenProcess_DisablesCoreDumpsAndClearsTheDumpableFlag(t *testing.T) {
	if os.Getenv(processHardeningVariable) != "1" {
		t.Skipf("hardens the test process itself; set %s=1 to run it", processHardeningVariable)
	}
	installedLinuxLibraryPath(t)

	if err := HardenProcess(); err != nil {
		t.Fatal(err)
	}

	if dumpable, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0); err != nil || dumpable != 0 {
		t.Errorf("PR_GET_DUMPABLE = %d, %v; want 0", dumpable, err)
	}
	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &limit); err != nil || limit.Cur != 0 || limit.Max != 0 {
		t.Errorf("RLIMIT_CORE = %+v, %v; want 0/0", limit, err)
	}
}
