//go:build linux || darwin

package securefile

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/runsecure/hkdfguard-go"
)

// ReadTrustedKeyFile against real files on Linux and macOS. A key file this user writes must be in
// a directory whose whole chain is root's or this user's and writable by neither group nor others
// - so never under /tmp, /var/tmp or /dev/shm, where t.TempDir() puts its directories on Linux.
// keyFileDirectory finds one, or skips the test saying why.

// keyFileRootName is the directory, under ~/.cache, that holds each test's key file directory.
const keyFileRootName = "hkdfguard-tests"

// keyFileDirectory is a fresh 0700 directory under a trusted root - on macOS the per-user temp
// folder; else $XDG_RUNTIME_DIR when it is set and trusted, else ~/.cache/hkdfguard-tests - with
// its symbolic links resolved. It is removed when the test ends.
func keyFileDirectory(t *testing.T) string {
	t.Helper()
	root, reason := trustedKeyFileRoot()
	if root == "" {
		t.Skipf("no private directory for key files on this host: %s. Set XDG_RUNTIME_DIR or HOME to a directory only this user (or root) can write", reason)
	}
	directory, err := os.MkdirTemp(root, "securefile-")
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

func trustedKeyFileRoot() (root, reason string) {
	var reasons []string
	candidates := []string{}
	if runtime.GOOS == "darwin" {
		candidates = append(candidates, os.TempDir())
	}
	if xdg := os.Getenv("XDG_RUNTIME_DIR"); xdg != "" {
		candidates = append(candidates, xdg)
	} else {
		reasons = append(reasons, "XDG_RUNTIME_DIR is not set")
	}
	for _, candidate := range candidates {
		resolved, err := trustedRoot(candidate)
		if err == nil {
			return resolved, ""
		}
		reasons = append(reasons, err.Error())
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

// trustedDirectoryChain checks that path and every directory above it is a real directory, owned
// by root or this user, and writable by neither group nor others - the sticky bit is no exception.
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

// trustThisUser trusts this process's user and group.
func trustThisUser() KeyFileTrust {
	return NewKeyFileTrust(KeyFileTrustOptions{UnixUserIDs: []uint32{uint32(os.Geteuid())}, UnixGroupIDs: []uint32{uint32(os.Getegid())}})
}

func isRoot() bool { return os.Geteuid() == 0 }

func writeUnixKeyFile(t *testing.T, path string, contents []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, contents, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil { // past the umask
		t.Fatal(err)
	}
}

func readUnix(t *testing.T, path string, trust KeyFileTrust) ([]byte, error) {
	t.Helper()
	return ReadTrustedKeyFile(t.Context(), path, trust)
}

func TestUnixKeyFile_RefusesAFileUnderTheSharedTempDirectory(t *testing.T) {
	// /tmp is writable by everyone (sticky or not), so nothing beneath it is trusted.
	directory, err := os.MkdirTemp("/tmp", "hkdfguard-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	path := filepath.Join(directory, "v1.key")
	writeUnixKeyFile(t, path, wrapped(), 0o600)

	_, err = readUnix(t, path, trustThisUser())
	requireKeyFileError(t, err, ErrUntrusted, "not trusted")
	requireKeyFileError(t, err, fs.ErrPermission)
}

func TestUnixKeyFile_RefusesAFileTheUserOwns_ByDefault(t *testing.T) {
	if isRoot() {
		t.Skip("Running as root, whose files are trusted.")
	}
	path := filepath.Join(keyFileDirectory(t), "v1.key")
	writeUnixKeyFile(t, path, wrapped(), 0o600)

	_, err := readUnix(t, path, AdministratorsOnly())
	requireKeyFileError(t, err, ErrUntrusted, "not trusted", fmt.Sprintf("owned by uid %d, not root or a trusted user", os.Geteuid()))
}

func TestUnixKeyFile_RefusesAFileOwnedByAnAccountTheTrustDoesNotName(t *testing.T) {
	if isRoot() {
		t.Skip("Running as root, whose files are trusted.")
	}
	// Trusting some other user, and this user's group: the file and its directory are owned by an
	// account the trust doesn't name - foreign to it - so they are refused.
	other := uint32(os.Geteuid()) + 1
	path := filepath.Join(keyFileDirectory(t), "v1.key")
	writeUnixKeyFile(t, path, wrapped(), 0o600)

	_, err := readUnix(t, path, NewKeyFileTrust(KeyFileTrustOptions{UnixUserIDs: []uint32{other}, UnixGroupIDs: []uint32{uint32(os.Getegid())}}))
	requireKeyFileError(t, err, ErrUntrusted, fmt.Sprintf("is owned by uid %d", os.Geteuid()))
}

func TestUnixKeyFile_ReportsAMissingFileAsNotFound(t *testing.T) {
	_, err := readUnix(t, fmt.Sprintf("/hkdfguard-missing-%x.key", random(8)), AdministratorsOnly())
	requireKeyFileError(t, err, fs.ErrNotExist)
}

func TestUnixKeyFile_PassesARootOwnedSystemFilesLocation(t *testing.T) {
	// /etc/hosts: root-owned all the way up, and not a key - so it may be refused for its contents
	// (or size), never for where it lives.
	if _, err := os.Stat("/etc/hosts"); err != nil {
		t.Skipf("/etc/hosts: %v", err)
	}
	if _, err := readUnix(t, "/etc/hosts", AdministratorsOnly()); err != nil {
		requireKeyFileError(t, err, hkdfguard.ErrInvalidKeyFile)
	}
}

func TestUnixKeyFile_RefusesARootOwnedDevice(t *testing.T) {
	// /dev/null: root's, under root's /dev - trusted by owner, but refused: it is writable by
	// everyone (0666), and not a regular file either.
	_, err := readUnix(t, "/dev/null", AdministratorsOnly())
	requireKeyFileError(t, err, ErrUntrusted, "/dev/null")
}

func TestUnixKeyFile_ReadsAFileOnlyItsTrustedOwnerCanReplace_AndFollowsALinkToItOnlyWhenTrusted(t *testing.T) {
	directory := keyFileDirectory(t)
	trust := trustThisUser()
	key := wrapped()
	path := filepath.Join(directory, "v1.key")
	writeUnixKeyFile(t, path, key, 0o600)
	link := filepath.Join(directory, "current.key")
	if err := os.Symlink("v1.key", link); err != nil {
		t.Fatal(err)
	}

	for _, spelling := range []string{path, link, directory + "/../" + filepath.Base(directory) + "/./v1.key"} {
		got, err := readUnix(t, spelling, trust)
		if err != nil || !bytes.Equal(got, key) {
			t.Errorf("%s: %x, %v; want the key", spelling, got, err)
		}
	}

	t.Run("relative to the working directory", func(t *testing.T) {
		t.Chdir(directory)
		got, err := readUnix(t, "v1.key", trust)
		if err != nil || !bytes.Equal(got, key) {
			t.Errorf("%x, %v; want the key", got, err)
		}
	})

	if !isRoot() {
		// The same file and link, owned by a user only the first trust names.
		_, err := readUnix(t, link, AdministratorsOnly())
		requireKeyFileError(t, err, ErrUntrusted)
	}
}

func TestUnixKeyFile_FollowsATrustedLinkToARootOwnedFile_AndRefusesAnUntrustedOne(t *testing.T) {
	if _, err := os.Stat("/etc/hosts"); err != nil {
		t.Skipf("/etc/hosts: %v", err)
	}
	link := filepath.Join(keyFileDirectory(t), "hosts")
	if err := os.Symlink("/etc/hosts", link); err != nil {
		t.Fatal(err)
	}

	// Trusted, the link leads to root's /etc/hosts, refused only for its contents.
	if _, err := readUnix(t, link, trustThisUser()); err != nil {
		requireKeyFileError(t, err, hkdfguard.ErrInvalidKeyFile)
	}
	if !isRoot() {
		_, err := readUnix(t, link, AdministratorsOnly())
		requireKeyFileError(t, err, ErrUntrusted, "not root or a trusted user")
	}
}

func TestUnixKeyFile_ReadsAGroupWritableFileOnlyWhenItsGroupIsTrusted(t *testing.T) {
	key := wrapped()
	path := filepath.Join(keyFileDirectory(t), "v1.key")
	writeUnixKeyFile(t, path, key, 0o660)

	got, err := readUnix(t, path, trustThisUser())
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("%x, %v; want the key", got, err)
	}
	_, err = readUnix(t, path, NewKeyFileTrust(KeyFileTrustOptions{UnixUserIDs: []uint32{uint32(os.Geteuid())}}))
	requireKeyFileError(t, err, ErrUntrusted, "writable by group")
}

func TestUnixKeyFile_RefusesAWorldWritableFile_WhateverIsTrusted(t *testing.T) {
	path := filepath.Join(keyFileDirectory(t), "v1.key")
	writeUnixKeyFile(t, path, wrapped(), 0o666)
	_, err := readUnix(t, path, trustThisUser())
	requireKeyFileError(t, err, ErrUntrusted, "writable by every user")
}

func TestUnixKeyFile_RefusesAPlaintextKeyOnceItsLocationPasses(t *testing.T) {
	path := filepath.Join(keyFileDirectory(t), "v1.key")
	writeUnixKeyFile(t, path, []byte(base64.StdEncoding.EncodeToString(random(32))+"\n"), 0o600)
	_, err := readUnix(t, path, trustThisUser())
	requireKeyFileError(t, err, hkdfguard.ErrInvalidKeyFile, "unwrapped")
}

func TestUnixKeyFile_RefusesADirectoryAsNotARegularFile(t *testing.T) {
	_, err := readUnix(t, keyFileDirectory(t), trustThisUser())
	requireKeyFileError(t, err, ErrUntrusted, "not a regular file")
}

func TestUnixKeyFile_RefusesAFileThisAccountMayNotRead(t *testing.T) {
	if isRoot() {
		t.Skip("Running as root, which may read anything.")
	}
	path := filepath.Join(keyFileDirectory(t), "v1.key")
	writeUnixKeyFile(t, path, wrapped(), 0o200) // write-only
	_, err := readUnix(t, path, trustThisUser())
	requireKeyFileError(t, err, fs.ErrPermission, "Could not open key file", "EACCES")
}
