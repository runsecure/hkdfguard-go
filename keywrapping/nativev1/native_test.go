//go:build (darwin && cgo) || (linux && cgo) || windows

package nativev1

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/runsecure/hkdfguard-go"
)

// Real wrapping and unwrapping against this platform's installed native KMS library (Windows
// Platform Crypto Provider / TPM, Linux TPM2, macOS Secure Enclave). No native library creates a
// KEK during wrap/unwrap, so the round trips run against an operator-provisioned service:
//
//	hkdfguard provision --service-name hkdfguard.integrationtest   (elevated on Windows; hkdfguard-v1-initialize on macOS)
//	HKDFGUARD_TEST_SERVICE=hkdfguard.integrationtest go test ./...
//
// Each platform's script under scripts/ provisions a default test service after checking the
// installed tool: provision-windows-test-key.ps1 (elevated), provision-macos-test-key.sh, and
// provision-linux-test-key.sh (sudo). On Windows and macOS the tests find that service by
// themselves; on Linux they are run with the variables the script prints.
//
// Without the library installed every test here is skipped; without a service the round trips are
// - reported as skipped, never as passed. A library that is installed but fails verification, or a
// service that is named but doesn't answer, fails the run. The tests only use a service's existing
// KEK; they never create or delete one.
//
// macOS: in the library's legacy keychain mode the KEK's access list names the binary that created
// it (the provisioning tool), so the first call from any other binary - every freshly built test
// binary - is answered with a keychain dialog in a logged-in session (click "Always Allow"), or
// with KEK_ACCESS_DENIED (-18) in a session without one. awaitNativeAccess turns a dialog
// nobody answers into a failure that says so, rather than a hang.

// nativeCallTimeout bounds the first native call under the test service.
const nativeCallTimeout = 60 * time.Second

// testEnvironment is the outcome of choosing a service: one to run against, or why not.
type testEnvironment struct {
	service    string // "" when the native round trips are skipped
	skipReason string
}

var (
	resolveTestEnvironmentOnce sync.Once
	resolvedTestEnvironment    testEnvironment

	awaitNativeAccessOnce sync.Once
	nativeAccessErr       error
)

// installedLibrary loads the real library, skipping the test if it isn't installed (or this build
// can't load it); a library that fails verification fails the test.
func installedLibrary(t *testing.T) kmsLibrary {
	t.Helper()
	library, err := hostLibrary()
	if errors.Is(err, ErrNotInstalled) || errors.Is(err, ErrUnsupportedPlatform) {
		t.Skipf("the native library is not installed: %v", err)
	}
	if err != nil {
		t.Fatalf("the installed native library failed to load: %v", err)
	}
	return library
}

// testServiceName is the service the native round trips run against, chosen once per process:
// testServiceVariable if set, otherwise the platform's default test service when the platform can
// confirm it is provisioned (platformTestEnvironment). Skips the test when there is none.
func testServiceName(t *testing.T) string {
	t.Helper()
	resolveTestEnvironmentOnce.Do(func() { resolvedTestEnvironment = resolveTestEnvironment() })
	if resolvedTestEnvironment.service == "" {
		t.Skip(resolvedTestEnvironment.skipReason)
	}
	return resolvedTestEnvironment.service
}

func resolveTestEnvironment() testEnvironment {
	if service := os.Getenv(testServiceVariable); service != "" {
		return testEnvironment{service: service}
	}

	defaultService := defaultTestServices[runtime.GOOS]
	if _, err := hostLibrary(); err != nil {
		if errors.Is(err, ErrNotInstalled) || errors.Is(err, ErrUnsupportedPlatform) {
			return testEnvironment{skipReason: fmt.Sprintf("the native library is not installed: %v", err)}
		}
		// Installed, but it couldn't even be loaded (it failed verification, say): run the tests
		// so that failure is reported.
		return testEnvironment{service: defaultService}
	}
	return platformTestEnvironment(defaultService)
}

// otherServiceName is the second service for the isolation tests: testOtherServiceVariable, or a
// name that is never provisioned.
func otherServiceName() string {
	if other := os.Getenv(testOtherServiceVariable); other != "" {
		return other
	}
	return unprovisionedServiceName
}

// provisionedWrapper returns a KeyWrapper for the test service, skipping the test without one.
func provisionedWrapper(t *testing.T) *KeyWrapper {
	t.Helper()
	service := testServiceName(t)
	w, err := New(service)
	if err != nil {
		t.Fatal(err)
	}
	awaitNativeAccess(t, w)
	return w
}

// awaitNativeAccess makes the first native call under the test service with a deadline, once per
// process, so a keychain dialog nobody answers (see the file comment) fails the run with a message
// that says what to do instead of hanging it. What the call answers is left to each test.
func awaitNativeAccess(t *testing.T, w *KeyWrapper) {
	t.Helper()
	awaitNativeAccessOnce.Do(func() {
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _ = w.GenerateAndWrap(context.Background(), make([]byte, hkdfguard.MaxWrappedKeyBytes))
		}()
		select {
		case <-done:
		case <-time.After(nativeCallTimeout):
			nativeAccessErr = fmt.Errorf("the first native call under service '%s' has not returned after %v. "+
				"On macOS the KEK's keychain item is asking for access in a dialog: click \"Always Allow\" "+
				"(every freshly built test binary asks once). In a session with no UI the library reports "+
				"KEK_ACCESS_DENIED (-18) instead; run the tests from a logged-in session", w.service, nativeCallTimeout)
		}
	})
	if nativeAccessErr != nil {
		t.Fatal(nativeAccessErr)
	}
}

func randomDEK(t *testing.T) []byte {
	t.Helper()
	dek := make([]byte, DEKLength)
	if _, err := rand.Read(dek); err != nil {
		t.Fatal(err)
	}
	return dek
}

func TestTheInstalledLibrary_LoadsOnce_AndAnswersCalls(t *testing.T) {
	first := installedLibrary(t)
	second, err := hostLibrary()
	if err != nil || second != first {
		t.Fatalf("second load = %v, %v; want the same binding", second, err)
	}

	// No KEK is provisioned for this name, so the library answers with an error status - which
	// proves it loaded and ran.
	status, _ := first.wrapDEK(unprovisionedServiceName, make([]byte, DEKLength), make([]byte, hkdfguard.MaxWrappedKeyBytes))
	if status >= 0 {
		t.Errorf("wrap under an unprovisioned service returned status %d", status)
	}
}

func TestTheInstalledLibrary_AnswersOpenFile_WithADescribedRefusal(t *testing.T) {
	// hkdfguard_open_file needs no KEK: a file that isn't there is refused with a status this
	// platform describes - which proves the binding reached it.
	library := installedLibrary(t)
	path := filepath.Join(t.TempDir(), "missing", "dek.bin")

	read, err := openKeyFile(library, path)

	var keyFileErr *KeyFileError
	if read != nil || !errors.As(err, &keyFileErr) {
		t.Fatalf("openKeyFile = %v, %v; want a *KeyFileError", read, err)
	}
	if library.describeStatus(keyFileErr.Status) == "" {
		t.Errorf("undescribed status %d", keyFileErr.Status)
	}
}

func TestNative_WrapAndUnwrap_RoundTripsA32ByteDEK(t *testing.T) {
	w := provisionedWrapper(t)
	ctx := context.Background()

	dek := randomDEK(t)
	wrapped := make([]byte, hkdfguard.MaxWrappedKeyBytes)
	n, err := w.Wrap(ctx, dek, wrapped)
	if err != nil || n == 0 || bytes.Equal(wrapped[:n], dek) {
		t.Fatalf("Wrap = %d, %v", n, err)
	}

	unwrapped := make([]byte, DEKLength)
	m, err := w.Unwrap(ctx, wrapped[:n], unwrapped)
	if err != nil || m != DEKLength || !bytes.Equal(unwrapped, dek) {
		t.Errorf("Unwrap = %d, %v; DEK recovered: %v", m, err, bytes.Equal(unwrapped, dek))
	}
}

func TestNative_GenerateAndWrap_ProducesAStableNonZeroDEK(t *testing.T) {
	w := provisionedWrapper(t)
	ctx := context.Background()

	wrapped := make([]byte, hkdfguard.MaxWrappedKeyBytes)
	n, err := w.GenerateAndWrap(ctx, wrapped)
	if err != nil || n == 0 {
		t.Fatalf("GenerateAndWrap = %d, %v", n, err)
	}

	first, second := make([]byte, DEKLength), make([]byte, DEKLength)
	if _, err := w.Unwrap(ctx, wrapped[:n], first); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Unwrap(ctx, wrapped[:n], second); err != nil {
		t.Fatal(err)
	}
	if hkdfguard.IsZero(first) || !bytes.Equal(first, second) {
		t.Error("the generated DEK is zero, or differs between unwraps")
	}
}

func TestNative_MultipleKeysUnderOneService_WrapAndUnwrapIndependently(t *testing.T) {
	w := provisionedWrapper(t)
	ctx := context.Background()

	deks := [][]byte{randomDEK(t), randomDEK(t)}
	var payloads [][]byte
	for _, dek := range deks {
		wrapped := make([]byte, hkdfguard.MaxWrappedKeyBytes)
		n, err := w.Wrap(ctx, bytes.Clone(dek), wrapped)
		if err != nil {
			t.Fatal(err)
		}
		payloads = append(payloads, wrapped[:n])
	}
	if bytes.Equal(payloads[0], payloads[1]) {
		t.Fatal("two different DEKs wrapped to the same payload")
	}

	for i, payload := range payloads {
		recovered := make([]byte, DEKLength)
		n, err := w.Unwrap(ctx, payload, recovered)
		if err != nil || n != DEKLength || !bytes.Equal(recovered, deks[i]) {
			t.Errorf("key %d: Unwrap = %d, %v; recovered the DEK: %v", i, n, err, bytes.Equal(recovered, deks[i]))
		}
	}
}

func TestNative_APayloadFromAnotherService_RevealsNothing(t *testing.T) {
	// A second provisioned service exercises the "wrong KEK" path; without one, an unprovisioned
	// name exercises "no KEK". Either way the unwrap must fail and reveal nothing.
	a := provisionedWrapper(t)
	b, err := New(otherServiceName())
	if err != nil {
		t.Fatal(err)
	}

	wrapped := make([]byte, hkdfguard.MaxWrappedKeyBytes)
	n, err := a.Wrap(context.Background(), randomDEK(t), wrapped)
	if err != nil {
		t.Fatal(err)
	}

	destination := make([]byte, DEKLength)
	var statusErr *StatusError
	if _, err := b.Unwrap(context.Background(), wrapped[:n], destination); !errors.As(err, &statusErr) {
		t.Errorf("Unwrap under another service: error = %v, want a *StatusError", err)
	}
	if !hkdfguard.IsZero(destination) {
		t.Error("the failed unwrap left bytes in the destination")
	}
}

func TestNative_TheLibraryDirectly_WrapsUnwrapsAndGenerates_WithOKStatuses(t *testing.T) {
	w := provisionedWrapper(t)
	library := w.library

	dek := randomDEK(t)
	wrapped := make([]byte, hkdfguard.MaxWrappedKeyBytes)
	status, written := library.wrapDEK(w.service, dek, wrapped)
	if status != statusOK || written <= 0 {
		t.Fatalf("wrapDEK = %d, %d", status, written)
	}

	recovered := make([]byte, DEKLength)
	status, n := library.unwrapDEK(w.service, wrapped[:written], recovered)
	if status != statusOK || n != DEKLength || !bytes.Equal(recovered, dek) {
		t.Errorf("unwrapDEK = %d, %d; recovered the DEK: %v", status, n, bytes.Equal(recovered, dek))
	}

	generated := make([]byte, hkdfguard.MaxWrappedKeyBytes)
	status, written = library.generateAndWrapDEK(w.service, generated)
	if status != statusOK || written <= 0 {
		t.Fatalf("generateAndWrapDEK = %d, %d", status, written)
	}
	fresh := make([]byte, DEKLength)
	if status, n := library.unwrapDEK(w.service, generated[:written], fresh); status != statusOK || n != DEKLength || hkdfguard.IsZero(fresh) {
		t.Errorf("unwrapDEK of a generated key = %d, %d; zero: %v", status, n, hkdfguard.IsZero(fresh))
	}
}

func TestNative_TooSmallBuffersAndCorruptPayloads_Fail(t *testing.T) {
	w := provisionedWrapper(t)
	ctx := context.Background()

	if _, err := w.Wrap(ctx, make([]byte, DEKLength), make([]byte, 8)); err == nil {
		t.Error("Wrap into 8 bytes succeeded")
	}
	if _, err := w.GenerateAndWrap(ctx, make([]byte, 8)); err == nil {
		t.Error("GenerateAndWrap into 8 bytes succeeded")
	}

	wrapped := make([]byte, hkdfguard.MaxWrappedKeyBytes)
	n, err := w.GenerateAndWrap(ctx, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Unwrap(ctx, wrapped[:n], make([]byte, 8)); err == nil {
		t.Error("Unwrap into 8 bytes succeeded")
	}

	wrapped[0] ^= 0xFF
	wrapped[n/2] ^= 0xFF
	destination := make([]byte, DEKLength)
	if _, err := w.Unwrap(ctx, wrapped[:n], destination); err == nil || !hkdfguard.IsZero(destination) {
		t.Errorf("Unwrap of a corrupted payload: error = %v, destination zeroed = %v", err, hkdfguard.IsZero(destination))
	}
}
