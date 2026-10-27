//go:build linux

package keyfiledir

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestNew_IsPrivate_AndOutsideTheSharedTemporaryDirectories(t *testing.T) {
	directory := New(t, "keys-")
	t.Logf("key file directory: %s", directory)

	info, err := os.Stat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		t.Errorf("%s: mode %v, owner %d; want 0700, owned by this user", directory, info.Mode(), info.Sys().(*syscall.Stat_t).Uid)
	}
	if err := TrustedDirectoryChain(directory); err != nil {
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

func TestNew_IsRemovedWhenTheTestEnds(t *testing.T) {
	var directory string
	t.Run("uses it", func(t *testing.T) { directory = New(t, "keys-") })

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
		if err := TrustedDirectoryChain(path); err == nil || !strings.Contains(err.Error(), "writable by group or others") {
			t.Errorf("%s: %v; want it refused", path, err)
		}
	}
}

func TestTrustedDirectoryChain_RefusesAGroupWritableDirectory_AndASymbolicLink(t *testing.T) {
	directory := New(t, "keys-")
	open := filepath.Join(directory, "group-writable")
	if err := os.Mkdir(open, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := TrustedDirectoryChain(open); err == nil || !strings.Contains(err.Error(), "writable by group or others") {
		t.Errorf("a group-writable directory: %v", err)
	}

	link := filepath.Join(directory, "link")
	if err := os.Symlink(directory, link); err != nil {
		t.Fatal(err)
	}
	if err := TrustedDirectoryChain(link); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("a symbolic link: %v", err)
	}
}

func TestTrustedRoot_AnUntrustedRuntimeDirectory_FallsBackToTheHomeDirectory(t *testing.T) {
	home := New(t, "keys-") // a trusted stand-in for $HOME
	t.Setenv("HOME", home)
	untrusted := t.TempDir()
	if TrustedDirectoryChain(untrusted) == nil {
		t.Skipf("%s is trusted here (TMPDIR is private), so it can't stand in for an untrusted runtime directory", untrusted)
	}
	t.Setenv("XDG_RUNTIME_DIR", untrusted)

	root, reason := TrustedRoot()

	if want := filepath.Join(home, ".cache", RootName); root != want {
		t.Errorf("root = %q (%s); want %q", root, reason, want)
	}
}

func TestTrustedRoot_WithNoTrustedRoot_SaysWhy(t *testing.T) {
	untrusted := t.TempDir()
	if TrustedDirectoryChain(untrusted) == nil {
		t.Skipf("%s is trusted here (TMPDIR is private), so it can't stand in for an untrusted home", untrusted)
	}
	t.Setenv("XDG_RUNTIME_DIR", "")
	t.Setenv("HOME", untrusted)

	root, reason := TrustedRoot()

	if root != "" || !strings.Contains(reason, "XDG_RUNTIME_DIR is not set") || !strings.Contains(reason, "the home directory") {
		t.Errorf("root = %q, reason = %q; want none, and why", root, reason)
	}
}
