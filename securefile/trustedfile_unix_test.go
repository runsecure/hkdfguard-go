//go:build linux || darwin

package securefile

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// ReadTrustedFile and ParseTrustedFile against real files on Linux and macOS, in a private
// directory as the key file tests use (see keyFileDirectory).

func TestUnixTrustedFile_ReadsARootOwnedSystemFile_ThroughEitherFunction(t *testing.T) {
	// /etc/hosts: root-owned all the way up (through macOS's root-owned /etc link), and any contents
	// at all are accepted.
	expected, err := os.ReadFile("/etc/hosts")
	if err != nil {
		t.Skipf("no /etc/hosts here: %v", err)
	}

	got, err := ReadTrustedFile(t.Context(), "/etc/hosts", AdministratorsOnly(), 1<<20)
	if err != nil || !bytes.Equal(got, expected) {
		t.Errorf("ReadTrustedFile: %d bytes, %v; want /etc/hosts", len(got), err)
	}
	length, err := ParseTrustedFile(t.Context(), "/etc/hosts", AdministratorsOnly(), 1<<20, func(c []byte) (int, error) { return len(c), nil })
	if err != nil || length != len(expected) {
		t.Errorf("ParseTrustedFile: %d, %v; want %d", length, err, len(expected))
	}
}

func TestUnixTrustedFile_RefusesAFileUnderTheSharedTempDirectory(t *testing.T) {
	directory, err := os.MkdirTemp("/tmp", "hkdfguard-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	path := filepath.Join(directory, "secret.enc")
	writeUnixKeyFile(t, path, random(40), 0o600)

	_, err = ReadTrustedFile(t.Context(), path, trustThisUser(), trustedFileLimit)
	requireKeyFileError(t, err, ErrUntrusted, "not trusted")
	requireKeyFileError(t, err, fs.ErrPermission)
}

func TestUnixTrustedFile_ReadsAFileInAPrivateDirectory_WithTheUserTrusted(t *testing.T) {
	directory := keyFileDirectory(t)
	for name, contents := range map[string][]byte{"secret.enc": random(40), "empty.enc": {}, "raw-key.bin": random(PlaintextKeyLength)} {
		path := filepath.Join(directory, name)
		writeUnixKeyFile(t, path, contents, 0o600)
		got, err := ReadTrustedFile(t.Context(), path, trustThisUser(), trustedFileLimit)
		if err != nil || !bytes.Equal(got, contents) {
			t.Errorf("%s: %x, %v; want the contents", name, got, err)
		}
	}
}

func TestUnixTrustedFile_RefusesAFileOverTheLimit(t *testing.T) {
	path := filepath.Join(keyFileDirectory(t), "secret.enc")
	writeUnixKeyFile(t, path, make([]byte, trustedFileLimit+1), 0o600)

	_, err := ReadTrustedFile(t.Context(), path, trustThisUser(), trustedFileLimit)
	requireKeyFileError(t, err, ErrTooLarge, "larger than 64 bytes")
}

func TestUnixTrustedFile_ReportsAMissingFileAsNotFound(t *testing.T) {
	_, err := ReadTrustedFile(t.Context(), "/hkdfguard-missing-file.enc", AdministratorsOnly(), trustedFileLimit)
	requireKeyFileError(t, err, fs.ErrNotExist, "was not found")
}
