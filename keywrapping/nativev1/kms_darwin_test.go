//go:build darwin && cgo

package nativev1

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// The macOS loader's system-call layer against the real filesystem and Security framework.

func TestDarwin_TheInstalledLibrary_PassesEveryCheck(t *testing.T) {
	home, _ := os.UserHomeDir()
	path, isSystem, err := macChoosePath(darwinProbe, home)
	if err != nil {
		t.Skipf("the native library is not installed: %v", err)
	}

	owners := []uint32{0}
	if !isSystem {
		owners = append(owners, uint32(os.Geteuid()))
	}
	if err := macVerifyLocation(path, darwinStatus, owners); err != nil {
		t.Errorf("location: %v", err)
	}
	if err := macVerifySignature(path, darwinCheckCodeSignature); err != nil {
		t.Errorf("signature: %v", err)
	}
}

func TestDarwin_TheProvisioningTool_IsSignedByTheTeam_ButRefused(t *testing.T) {
	// Installed beside the library and signed by the same team: only the identifier in the code
	// requirement tells them apart.
	tool := filepath.Join(macSystemDirectory, "hkdfguard")
	if _, err := os.Stat(tool); err != nil {
		t.Skipf("%s is not installed", tool)
	}

	requireUntrusted(t, macVerifySignature(tool, darwinCheckCodeSignature), macTeamID)
}

func TestDarwin_AnUnsignedFile_IsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), macFileName)
	if err := os.WriteFile(path, []byte{0xCF, 0xFA, 0xED, 0xFE}, 0o644); err != nil {
		t.Fatal(err)
	}

	requireUntrusted(t, macVerifySignature(path, darwinCheckCodeSignature))
}

func TestDarwin_AUserWritableTemporaryDirectory_FailsTheLocationCheck(t *testing.T) {
	// The planting scenario: a correctly named file somewhere the system install check would
	// refuse. The temp directory is owned by this user, never root, so a system-owner check fails.
	path := filepath.Join(t.TempDir(), macFileName)
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(path) // /var -> /private/var
	if err != nil {
		t.Fatal(err)
	}

	requireUntrusted(t, macVerifyLocation(resolved, darwinStatus, []uint32{0}), "owned by uid")
}

func TestDarwin_ProbeDistinguishesMissingFromPresent(t *testing.T) {
	if errno := darwinProbe("/"); errno != 0 {
		t.Errorf("probe('/') = %d", errno)
	}
	if errno := darwinProbe("/definitely/not/here"); errno != errnoENOENT {
		t.Errorf("probe(missing) = %d, want ENOENT", errno)
	}
}

// --- The test service --------------------------------------------------------------------------

// platformTestEnvironment asks the installed hkdfguard tool, which sits beside the loaded
// library, whether the default test service is provisioned. The tool created the KEK, so it is on
// the keychain item's access list and never prompts; asking the library from this process would.
func platformTestEnvironment() testEnvironment {
	tool, err := darwinProvisioningTool()
	if err != nil {
		return testEnvironment{service: defaultTestService} // run the tests, so the failure is reported
	}
	output, err := exec.Command(tool, "status", "--service-name", defaultTestService).CombinedOutput()
	if err != nil {
		return testEnvironment{service: defaultTestService}
	}

	switch {
	case bytes.Contains(output, []byte("kek: present")):
		return testEnvironment{service: defaultTestService}
	case bytes.Contains(output, []byte("kek: absent")):
		return testEnvironment{skipReason: fmt.Sprintf("The test KEK '%s' is not provisioned. Run scripts/provision-macos-test-key.sh, or set %s to a provisioned service.", defaultTestService, testServiceVariable)}
	default:
		return testEnvironment{service: defaultTestService}
	}
}

// darwinProvisioningTool is the hkdfguard tool installed beside the library the loader
// would choose.
func darwinProvisioningTool() (string, error) {
	home, _ := os.UserHomeDir()
	path, _, err := macChoosePath(darwinProbe, home)
	if err != nil {
		return "", err
	}
	tool := filepath.Join(filepath.Dir(path), "hkdfguard")
	if _, err := os.Stat(tool); err != nil {
		return "", err
	}
	return tool, nil
}

func TestDarwin_TheProvisioningTool_ReportsAnUnprovisionedService_AsAbsent(t *testing.T) {
	tool, err := darwinProvisioningTool()
	if err != nil {
		t.Skipf("the provisioning tool is not installed: %v", err)
	}

	output, err := exec.Command(tool, "status", "--service-name", unprovisionedServiceName).CombinedOutput()

	if err != nil || !bytes.Contains(output, []byte("kek: absent")) {
		t.Errorf("status = %v: %s", err, output)
	}
}

func TestDarwin_TheDefaultTestService_IsFoundOnlyWhenProvisioned(t *testing.T) {
	tool, err := darwinProvisioningTool()
	if err != nil {
		t.Skipf("the provisioning tool is not installed: %v", err)
	}
	output, err := exec.Command(tool, "status", "--service-name", defaultTestService).CombinedOutput()
	if err != nil {
		t.Fatalf("status: %v: %s", err, output)
	}

	env := platformTestEnvironment()

	if provisioned := bytes.Contains(output, []byte("kek: present")); (env.service != "") != provisioned {
		t.Errorf("environment = %+v, but the tool reports provisioned = %v", env, provisioned)
	}
}
