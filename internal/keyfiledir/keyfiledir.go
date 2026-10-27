//go:build linux || darwin

// Package keyfiledir gives the tests of every module in this repository a private directory to
// write key files in on Linux and macOS. Both the native library and securefile refuse a key file
// when any directory above it is writable by group or others - sticky or not - so nothing under
// /tmp, /var/tmp or /dev/shm, where t.TempDir() puts its directories on Linux, will do.
//
// Test support only: it is internal to this repository, and nothing outside a _test.go file imports
// it.
package keyfiledir

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

// RootName is the directory, under ~/.cache, that holds each test's key file directory.
const RootName = "hkdfguard-tests"

// New returns a fresh 0700 directory, named with prefix, under a trusted root (see TrustedRoot),
// with its symbolic links resolved. It is removed when the test ends. It skips the test, saying
// why, when there is no trusted root on this host.
func New(t testing.TB, prefix string) string {
	t.Helper()
	root, reason := TrustedRoot()
	if root == "" {
		t.Skipf("no private directory for key files on this host: %s. Key files are refused under a group- or other-writable "+
			"directory (sticky ones such as /tmp included); set XDG_RUNTIME_DIR or HOME to a directory only this user (or root) can write", reason)
	}
	directory, err := os.MkdirTemp(root, prefix)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(directory)
		if filepath.Base(root) == RootName {
			_ = os.Remove(root) // only if no other test's directory is left in it
		}
	})
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := TrustedDirectoryChain(directory); err != nil {
		t.Fatalf("the key file directory is not private: %v", err)
	}
	return directory
}

// TrustedRoot is the directory New creates its directories in - on macOS the per-user temp folder;
// else $XDG_RUNTIME_DIR when it is set and trusted, else ~/.cache/hkdfguard-tests - or "" and why
// there is none.
func TrustedRoot() (root, reason string) {
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
		resolved, err := trustedResolved(candidate)
		if err == nil {
			return resolved, ""
		}
		reasons = append(reasons, fmt.Sprintf("%s: %v", candidate, err))
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", strings.Join(append(reasons, fmt.Sprintf("no home directory: %v", err)), "; ")
	}
	resolvedHome, err := trustedResolved(home)
	if err != nil {
		return "", strings.Join(append(reasons, fmt.Sprintf("the home directory: %v", err)), "; ")
	}
	root = filepath.Join(resolvedHome, ".cache", RootName)
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", strings.Join(append(reasons, err.Error()), "; ")
	}
	if err := TrustedDirectoryChain(root); err != nil {
		return "", strings.Join(append(reasons, err.Error()), "; ")
	}
	return root, ""
}

// trustedResolved is path with its symbolic links resolved, when the directory chain there is trusted.
func trustedResolved(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("%q is not an absolute path", path)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	if err := TrustedDirectoryChain(resolved); err != nil {
		return "", err
	}
	return resolved, nil
}

// TrustedDirectoryChain checks that path and every directory above it is a real directory (not a
// symbolic link), owned by root or this user, and writable by neither group nor others - the sticky
// bit is no exception, as it is none to the native library or securefile.
func TrustedDirectoryChain(path string) error {
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
