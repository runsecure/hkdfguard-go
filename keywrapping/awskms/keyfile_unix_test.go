//go:build linux || darwin

package awskms

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/runsecure/hkdfguard-go/securefile"
)

// A key file this user writes must be in a directory whose whole chain is root's or this user's and
// writable by neither group nor others - so never under /tmp, /var/tmp or /dev/shm. This is a copy
// of the securefile module's test helper (separate modules; neither imports the other's tests).

const keyFileRootName = "hkdfguard-tests"

func keyFileDirectory(t *testing.T) string {
	t.Helper()
	root, reason := trustedKeyFileRoot()
	if root == "" {
		t.Skipf("no private directory for key files on this host: %s. Set XDG_RUNTIME_DIR or HOME to a directory only this user (or root) can write", reason)
	}
	directory, err := os.MkdirTemp(root, "awskms-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(directory)
		if filepath.Base(root) == keyFileRootName {
			_ = os.Remove(root)
		}
	})
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := trustedDirectoryChain(directory); err != nil {
		t.Fatalf("the key file directory is not private: %v", err)
	}
	return directory
}

func trustedKeyFileRoot() (root, reason string) {
	var reasons []string
	var candidates []string
	if runtime.GOOS == "darwin" {
		candidates = append(candidates, os.TempDir())
	}
	if xdg := os.Getenv("XDG_RUNTIME_DIR"); xdg != "" {
		candidates = append(candidates, xdg)
	} else {
		reasons = append(reasons, "XDG_RUNTIME_DIR is not set")
	}
	for _, candidate := range candidates {
		resolved, err := filepath.EvalSymlinks(candidate)
		if err == nil {
			err = trustedDirectoryChain(resolved)
		}
		if err == nil {
			return resolved, ""
		}
		reasons = append(reasons, err.Error())
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", strings.Join(append(reasons, fmt.Sprintf("no home directory: %v", err)), "; ")
	}
	resolvedHome, err := filepath.EvalSymlinks(home)
	if err == nil {
		err = trustedDirectoryChain(resolvedHome)
	}
	if err != nil {
		return "", strings.Join(append(reasons, fmt.Sprintf("the home directory: %v", err)), "; ")
	}
	root = filepath.Join(resolvedHome, ".cache", keyFileRootName)
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", strings.Join(append(reasons, err.Error()), "; ")
	}
	if err := trustedDirectoryChain(root); err != nil {
		return "", strings.Join(append(reasons, err.Error()), "; ")
	}
	return root, ""
}

func trustedDirectoryChain(path string) error {
	euid := uint32(os.Geteuid())
	for current := filepath.Clean(path); ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		switch {
		case !ok:
			return fmt.Errorf("%s: no ownership information", current)
		case !info.IsDir():
			return fmt.Errorf("%s is not a directory (mode %v)", current, info.Mode())
		case stat.Uid != 0 && stat.Uid != euid:
			return fmt.Errorf("%s is owned by uid %d, neither root nor this user (%d)", current, stat.Uid, euid)
		case stat.Mode&0o022 != 0:
			return fmt.Errorf("%s is writable by group or others (mode %04o)", current, stat.Mode&0o7777)
		}
		if current == "/" {
			return nil
		}
	}
}

func TestReadKeyFile_ReadsAFileInADirectoryOnlyItsTrustedOwnerCanWrite_AndItReveals_Unix(t *testing.T) {
	directory := keyFileDirectory(t)
	wrapper := newWrapper(t, newFakeKMS(t), Options{
		KeyFileTrust: securefile.NewKeyFileTrust(securefile.KeyFileTrustOptions{UnixUserIDs: []uint32{uint32(os.Geteuid())}}),
	})
	readAndReveal(t, wrapper, filepath.Join(directory, "v1.key"))
}

func TestReadKeyFile_RefusesAFileItsOwnersAccountIsNotTrustedFor_Unix(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("Running as root, whose files are trusted.")
	}
	path := filepath.Join(keyFileDirectory(t), "v1.key")
	if err := os.WriteFile(path, random(184), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := newWrapper(t, newFakeKMS(t)).ReadKeyFile(t.Context(), path)
	requireNotTrusted(t, err)
}
