//go:build darwin && cgo

package nativev1

import (
	"os"
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
	tool := filepath.Join(macSystemDirectory, "hkdfguard-v1-initialize")
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
