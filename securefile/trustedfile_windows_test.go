//go:build windows

package securefile

import (
	"bytes"
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// ReadTrustedFile and ParseTrustedFile against real files on Windows, in a fresh folder under the
// temp folder as the key file tests use (see windowsKeyDirectory).

func TestWindowsTrustedFile_RefusesAFileInTheUsersOwnFolderByDefault(t *testing.T) {
	path := filepath.Join(windowsKeyDirectory(t), "secret.enc")
	writeKeyFile(t, path, random(40))

	_, err := ReadTrustedFile(t.Context(), path, AdministratorsOnly(), trustedFileLimit)
	requireKeyFileError(t, err, ErrUntrusted, "not trusted", "is owned by")
	requireKeyFileError(t, err, fs.ErrPermission)
	if strings.Contains(err.Error(), "Key file") {
		t.Errorf("%q calls it a key file", err)
	}
}

func TestWindowsTrustedFile_ReadsTheFileThroughEitherFunction_WithTheUserTrusted(t *testing.T) {
	contents := random(40)
	path := filepath.Join(windowsKeyDirectory(t), "secret.enc")
	writeKeyFile(t, path, contents)

	got, err := ReadTrustedFile(t.Context(), path, trustCurrentUser(t), trustedFileLimit)
	if err != nil || !bytes.Equal(got, contents) {
		t.Errorf("ReadTrustedFile: %x, %v; want the contents", got, err)
	}
	got, err = ParseTrustedFile(t.Context(), path, trustCurrentUser(t), trustedFileLimit, func(c []byte) ([]byte, error) { return bytes.Clone(c), nil })
	if err != nil || !bytes.Equal(got, contents) {
		t.Errorf("ParseTrustedFile: %x, %v; want the contents", got, err)
	}
}

func TestWindowsTrustedFile_AcceptsAnEmptyFile_AndWhatAKeyFileWouldRefuse(t *testing.T) {
	directory := windowsKeyDirectory(t)
	for name, contents := range map[string][]byte{"empty.enc": {}, "raw-key.bin": random(PlaintextKeyLength)} {
		path := filepath.Join(directory, name)
		writeKeyFile(t, path, contents)
		got, err := ReadTrustedFile(t.Context(), path, trustCurrentUser(t), trustedFileLimit)
		if err != nil || !bytes.Equal(got, contents) {
			t.Errorf("%s: %x, %v; want the contents", name, got, err)
		}
	}
}

func TestWindowsTrustedFile_RefusesAFileOverTheLimit_WithoutParsingIt(t *testing.T) {
	path := filepath.Join(windowsKeyDirectory(t), "secret.enc")
	writeKeyFile(t, path, make([]byte, trustedFileLimit+1))

	_, err := ReadTrustedFile(t.Context(), path, trustCurrentUser(t), trustedFileLimit)
	requireKeyFileError(t, err, ErrTooLarge, "larger than 64 bytes")
	parsed := false
	_, err = ParseTrustedFile(t.Context(), path, trustCurrentUser(t), trustedFileLimit, func([]byte) (bool, error) { parsed = true; return true, nil })
	requireKeyFileError(t, err, ErrTooLarge)
	if parsed {
		t.Error("an oversize file was parsed")
	}
}

func TestWindowsTrustedFile_ReportsAMissingFileOrFolderAsNotFound(t *testing.T) {
	directory := windowsKeyDirectory(t)
	for _, path := range []string{filepath.Join(directory, "missing.enc"), filepath.Join(directory, "missing", "secret.enc")} {
		_, err := ReadTrustedFile(t.Context(), path, trustCurrentUser(t), trustedFileLimit)
		requireKeyFileError(t, err, fs.ErrNotExist, "File '", "was not found")
	}
}

func TestWindowsTrustedFile_AParseError_IsReturnedAsItIs(t *testing.T) {
	path := filepath.Join(windowsKeyDirectory(t), "secret.enc")
	writeKeyFile(t, path, random(3))
	refused := errors.New("not a certificate")

	_, err := ParseTrustedFile(t.Context(), path, trustCurrentUser(t), trustedFileLimit, func([]byte) (int, error) { return 0, refused })
	if err != refused {
		t.Fatalf("got %v; want the parser's error", err)
	}
}
