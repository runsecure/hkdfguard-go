//go:build linux

package nativev1

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// A private directory for the files these tests hand to the native library on Linux. The library
// refuses a key file (HKDFGUARD_ERR_FILE_UNTRUSTED, -39) when any directory above it is writable by
// group or others - sticky or not - so nothing under /tmp, /var/tmp or /dev/shm, where t.TempDir()
// puts its directories, will do. The integration module keeps a copy of this helper (separate
// modules; neither imports the other's tests).

// keyFileDirectory is a fresh 0700 directory under a trusted root - $XDG_RUNTIME_DIR when it is set
// and trusted, else ~/.cache/hkdfguard-tests - every directory up whose chain is owned by root or
// this user and not group/other-writable. It is removed when the test ends. Skips the test, saying
// why, when there is no such root.
func keyFileDirectory(t *testing.T) string {
	t.Helper()
	root, reason := trustedKeyFileRoot()
	if root == "" {
		t.Skipf("no private directory for key files on this host: %s. The native library refuses key files under a group- or other-writable directory (sticky ones such as /tmp included)", reason)
	}
	directory, err := os.MkdirTemp(root, "keys-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(directory)
		if filepath.Base(root) == keyFileRootName {
			_ = os.Remove(root) // only if no other test's directory is left in it
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

// keyFileRootName is the directory, under ~/.cache, that holds each test's key file directory.
const keyFileRootName = "hkdfguard-tests"

// trustedKeyFileRoot is the directory keyFileDirectory creates its directories in, or "" and why
// there is none.
func trustedKeyFileRoot() (root, reason string) {
	var reasons []string
	if xdg := os.Getenv("XDG_RUNTIME_DIR"); xdg == "" {
		reasons = append(reasons, "XDG_RUNTIME_DIR is not set")
	} else if resolved, err := trustedRoot(xdg); err != nil {
		reasons = append(reasons, fmt.Sprintf("XDG_RUNTIME_DIR: %v", err))
	} else {
		return resolved, ""
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", strings.Join(append(reasons, fmt.Sprintf("no home directory: %v", err)), "; ")
	}
	resolvedHome, err := trustedRoot(home)
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

// trustedRoot is path with its symbolic links resolved, when the directory chain there is trusted.
func trustedRoot(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("%q is not an absolute path", path)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	if err := trustedDirectoryChain(resolved); err != nil {
		return "", err
	}
	return resolved, nil
}

// trustedDirectoryChain checks that path and every directory above it is a real directory (not a
// symbolic link), owned by root or this user, and writable by neither group nor others - the sticky
// bit is no exception, as it is none to the native library.
func trustedDirectoryChain(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%q is not an absolute path", path)
	}
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

func TestKeyFileDirectory_IsPrivate_AndOutsideTheSharedTemporaryDirectories(t *testing.T) {
	directory := keyFileDirectory(t)
	t.Logf("key file directory: %s", directory)

	info, err := os.Stat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		t.Errorf("%s: mode %v, owner %d; want 0700, owned by this user", directory, info.Mode(), info.Sys().(*syscall.Stat_t).Uid)
	}
	if err := trustedDirectoryChain(directory); err != nil {
		t.Error(err)
	}
	for _, shared := range []string{os.TempDir(), "/tmp", "/var/tmp", "/dev/shm"} {
		if resolved, err := filepath.EvalSymlinks(shared); err == nil {
			shared = resolved
		}
		if directory == shared || strings.HasPrefix(directory, shared+"/") {
			t.Errorf("%s is under the shared temporary directory %s", directory, shared)
		}
	}

	// A file in it is one the native library would read.
	path := filepath.Join(directory, "key.bin")
	if err := os.WriteFile(path, make([]byte, 132), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestKeyFileDirectory_IsRemovedWhenTheTestEnds(t *testing.T) {
	var directory string
	t.Run("uses it", func(t *testing.T) { directory = keyFileDirectory(t) })

	if _, err := os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("%s still exists after its test: %v", directory, err)
	}
}

func TestTrustedDirectoryChain_RefusesTheStickyTemporaryDirectory(t *testing.T) {
	// /tmp is world-writable with the sticky bit (1777): the native library refuses a key file
	// anywhere under it, even in a private directory of this user's.
	info, err := os.Stat("/tmp")
	if err != nil || info.Mode().Perm()&0o022 == 0 {
		t.Skipf("/tmp is not a shared directory here: %v, %v", info, err)
	}
	private, err := os.MkdirTemp("/tmp", "hkdfguard-chain-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(private) })

	for _, path := range []string{"/tmp", private} {
		if err := trustedDirectoryChain(path); err == nil || !strings.Contains(err.Error(), "writable by group or others") {
			t.Errorf("%s: %v; want it refused", path, err)
		}
	}
}

func TestTrustedDirectoryChain_RefusesAGroupWritableDirectory_AndASymbolicLink(t *testing.T) {
	directory := keyFileDirectory(t)
	open := filepath.Join(directory, "group-writable")
	if err := os.Mkdir(open, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := trustedDirectoryChain(open); err == nil || !strings.Contains(err.Error(), "writable by group or others") {
		t.Errorf("a group-writable directory: %v", err)
	}

	link := filepath.Join(directory, "link")
	if err := os.Symlink(directory, link); err != nil {
		t.Fatal(err)
	}
	if err := trustedDirectoryChain(link); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("a symbolic link: %v", err)
	}
}

func TestTrustedKeyFileRoot_AnUntrustedRuntimeDirectory_FallsBackToTheHomeDirectory(t *testing.T) {
	home := keyFileDirectory(t) // a trusted stand-in for $HOME
	t.Setenv("HOME", home)
	untrusted := t.TempDir()
	if trustedDirectoryChain(untrusted) == nil {
		t.Skipf("%s is trusted here (TMPDIR is private), so it can't stand in for an untrusted runtime directory", untrusted)
	}
	t.Setenv("XDG_RUNTIME_DIR", untrusted)

	root, reason := trustedKeyFileRoot()

	if want := filepath.Join(home, ".cache", keyFileRootName); root != want {
		t.Errorf("root = %q (%s); want %q", root, reason, want)
	}
}

func TestTrustedKeyFileRoot_WithNoTrustedRoot_SaysWhy(t *testing.T) {
	untrusted := t.TempDir()
	if trustedDirectoryChain(untrusted) == nil {
		t.Skipf("%s is trusted here (TMPDIR is private), so it can't stand in for an untrusted home", untrusted)
	}
	t.Setenv("XDG_RUNTIME_DIR", "")
	t.Setenv("HOME", untrusted)

	root, reason := trustedKeyFileRoot()

	if root != "" || !strings.Contains(reason, "XDG_RUNTIME_DIR is not set") || !strings.Contains(reason, "the home directory") {
		t.Errorf("root = %q, reason = %q; want none, and why", root, reason)
	}
}
