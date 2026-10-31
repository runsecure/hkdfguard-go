//go:build linux && cgo

package nativev1

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/runsecure/hkdfguard-go"
)

// Reading key files through the real Linux native library's hkdfguard_open_file - the key-file
// half of the .NET LinuxNativeIntegrationTests. Each needs the provisioned test service (see
// kms_linux_cgo_test.go) for a real wrapped payload, and a private folder for key files
// (keyFileDirectory, which skips saying why when this host has none): the library refuses a key
// file under any group- or other-writable directory, so never under t.TempDir() here.

// linuxKeyFileReader is a wrapper for reading key files: any valid service name will do, since
// reading a file never touches a KEK.
func linuxKeyFileReader(t *testing.T) *KeyWrapper {
	t.Helper()
	w, err := New("hkdfguard.keyfile.reader")
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// withLinuxKeyFileFolder skips without the provisioned test service or a private key file folder,
// and otherwise returns a fresh such folder and one real wrapped payload.
func withLinuxKeyFileFolder(t *testing.T) (directory string, wrapped []byte) {
	t.Helper()
	library, service := linuxProvisionedLibrary(t)
	directory = keyFileDirectory(t)
	return directory, linuxWrap(t, library, service, randomDEK(t))
}

// writeLinuxKeyFile writes contents to name in directory as 0600 - explicitly, since a desktop
// session's umask of 002 would otherwise leave it group-writable, and so refused.
func writeLinuxKeyFile(t *testing.T, directory, name string, contents []byte) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// requireLinuxRefused checks that err is a *KeyFileError for path with status, satisfying is (nil:
// no particular sentinel), and that its message names the path, the status and what it means.
func requireLinuxRefused(t *testing.T, err error, path string, status int32, is error) {
	t.Helper()
	var keyFileErr *KeyFileError
	if !errors.As(err, &keyFileErr) {
		t.Fatalf("%s: error = %v; want a *KeyFileError", path, err)
	}
	if keyFileErr.Status != status || keyFileErr.Path != path {
		t.Errorf("refused %q with status %d (%s); want %q, %d", keyFileErr.Path, keyFileErr.Status, keyFileErr.Description, path, status)
	}
	if is != nil && !errors.Is(err, is) {
		t.Errorf("%s: error = %v; want errors.Is(err, %v)", path, err, is)
	}
	for _, want := range []string{"'" + path + "'", fmt.Sprintf("status %d (", status), describeLinuxStatus(status)} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message %q does not contain %q", err.Error(), want)
		}
	}
}

func TestLinuxKeyFile_AKeyFile_ReadsBackExactlyAsWritten(t *testing.T) {
	directory, wrapped := withLinuxKeyFileFolder(t)
	path := writeLinuxKeyFile(t, directory, "key.bin", wrapped)

	read, err := linuxKeyFileReader(t).ReadKeyFile(context.Background(), path)

	if err != nil || !bytes.Equal(read, wrapped) {
		t.Errorf("ReadKeyFile = %d bytes, %v; want the %d written, unchanged", len(read), err, len(wrapped))
	}
}

func TestLinuxKeyFile_AKeyFileOfTheWrongSize_IsRefused_AsTooShortOrTooLong(t *testing.T) {
	directory, wrapped := withLinuxKeyFileFolder(t)
	r := linuxKeyFileReader(t)

	for _, c := range []struct {
		size   int
		status int32
	}{
		{0, errFileTooShort},
		{100, errFileTooShort},
		{len(wrapped) - 1, errFileTooShort},
		{len(wrapped) + 1, errFileTooLong},
		{4096, errFileTooLong},
	} {
		t.Run(fmt.Sprint(c.size), func(t *testing.T) {
			contents := make([]byte, c.size)
			copy(contents, wrapped)
			path := writeLinuxKeyFile(t, directory, fmt.Sprintf("size-%d.bin", c.size), contents)

			_, err := r.ReadKeyFile(context.Background(), path)

			requireLinuxRefused(t, err, path, c.status, hkdfguard.ErrInvalidKeyFile)
		})
	}
}

func TestLinuxKeyFile_AFileHoldingWhatLooksLikeAnUnwrappedDEK_IsRefusedAsAKeyExposure(t *testing.T) {
	directory, _ := withLinuxKeyFileFolder(t)
	r := linuxKeyFileReader(t)
	dek := randomDEK(t)

	forms := map[string][]byte{
		"raw":                 dek,
		"hex":                 []byte(strings.ToUpper(hex.EncodeToString(dek))),
		"lower-hex":           []byte(hex.EncodeToString(dek)),
		"base64":              []byte(base64.StdEncoding.EncodeToString(dek)),
		"base64-with-newline": []byte(base64.StdEncoding.EncodeToString(dek) + "\n"),
	}
	for form, contents := range forms {
		t.Run(form, func(t *testing.T) {
			path := writeLinuxKeyFile(t, directory, "plaintext-"+form+".bin", contents)

			_, err := r.ReadKeyFile(context.Background(), path)

			requireLinuxRefused(t, err, path, errFilePlaintextKey, hkdfguard.ErrInvalidKeyFile)
			if err != nil && !strings.Contains(err.Error(), "key exposure") {
				t.Errorf("message %q does not say it is a key exposure", err)
			}
		})
	}
}

func TestLinuxKeyFile_AChangeToThePayloadsStructure_IsRefusedWhenRead_ButAChangedTagOnlyAtUnwrap(t *testing.T) {
	// The version byte and a byte mid-payload are checked when the file is read; the AEAD tag can
	// only be checked with the KEK, so a changed tag reads fine and fails unwrap.
	directory, wrapped := withLinuxKeyFileFolder(t)
	r := linuxKeyFileReader(t)

	for _, position := range []int{0, len(wrapped) / 2} {
		tampered := bytes.Clone(wrapped)
		tampered[position] ^= 0x01
		path := writeLinuxKeyFile(t, directory, fmt.Sprintf("structure-%d.bin", position), tampered)

		_, err := r.ReadKeyFile(context.Background(), path)

		requireLinuxRefused(t, err, path, errFileMalformed, hkdfguard.ErrInvalidKeyFile)
	}

	tag := bytes.Clone(wrapped)
	tag[len(tag)-1] ^= 0x01
	read, err := r.ReadKeyFile(context.Background(), writeLinuxKeyFile(t, directory, "tag.bin", tag))
	if err != nil {
		t.Fatalf("a changed tag was refused when read: %v", err)
	}
	destination := repeat(0xAA, DEKLength)
	n, err := provisionedWrapper(t).Unwrap(context.Background(), read, destination)

	var statusErr *StatusError
	if n != 0 || !errors.As(err, &statusErr) {
		t.Errorf("Unwrap = %d, %v; want a *StatusError", n, err)
	}
	requireZero(t, "the destination", destination)
}

func TestLinuxKeyFile_AMissingFileOrFolder_IsNotFound_AndAFolderIsNotAKeyFile(t *testing.T) {
	directory, _ := withLinuxKeyFileFolder(t)
	r := linuxKeyFileReader(t)

	for _, path := range []string{filepath.Join(directory, "missing.bin"), filepath.Join(directory, "missing", "key.bin")} {
		_, err := r.ReadKeyFile(context.Background(), path)
		requireLinuxRefused(t, err, path, errFileNotFound, fs.ErrNotExist)
	}

	read, err := r.ReadKeyFile(context.Background(), directory)
	if read != nil {
		t.Errorf("read %d bytes from a folder", len(read))
	}
	requireLinuxRefused(t, err, directory, errFileIO, nil)
}

func TestLinuxKeyFile_ALink_IsFollowed_OnlyWhereItLeadsIsTrustedToo(t *testing.T) {
	// The library judges where a link leads, not the link: within private folders it is followed;
	// into /tmp (sticky, world-writable) it is refused, as is /tmp itself.
	directory, wrapped := withLinuxKeyFileFolder(t)
	r := linuxKeyFileReader(t)

	key := writeLinuxKeyFile(t, directory, "key.bin", wrapped)
	fileLink := filepath.Join(directory, "file-link.bin")
	folderLink := filepath.Join(directory, "folder-link")
	if err := os.Symlink(key, fileLink); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(directory, folderLink); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{fileLink, filepath.Join(folderLink, "key.bin")} {
		if read, err := r.ReadKeyFile(context.Background(), path); err != nil || !bytes.Equal(read, wrapped) {
			t.Errorf("%s: ReadKeyFile = %d bytes, %v; want the key file's", path, len(read), err)
		}
	}

	// Explicitly /tmp, not t.TempDir() (TMPDIR may point elsewhere): the shared folder this refuses.
	if info, err := os.Stat("/tmp"); err != nil || info.Mode().Perm()&0o002 == 0 {
		t.Skipf("/tmp is not a world-writable folder on this host (%v, %v); nothing shared to refuse", info, err)
	}
	shared, err := os.MkdirTemp("/tmp", "hkdfguard-shared-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(shared) })
	exposed := writeLinuxKeyFile(t, shared, "key.bin", wrapped)
	intoShared := filepath.Join(directory, "into-tmp.bin")
	sharedFolderLink := filepath.Join(directory, "tmp-folder")
	if err := os.Symlink(exposed, intoShared); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(shared, sharedFolderLink); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{exposed, intoShared, filepath.Join(sharedFolderLink, "key.bin")} {
		_, err := r.ReadKeyFile(context.Background(), path)
		requireLinuxRefused(t, err, path, errFileUntrusted, fs.ErrPermission)
	}
}

func TestLinuxKeyFile_AKeyFileAnotherAccountCouldRewrite_IsRefused_WhileOwnerOnlyAndGroupReadAreNot(t *testing.T) {
	// A group- or other-writable key file could be replaced by another account, so the library
	// refuses it whatever the folders above it. Group read is fine: hkdfguard wrap --group hands a
	// key file to a service's group as 0640.
	directory, wrapped := withLinuxKeyFileFolder(t)
	path := writeLinuxKeyFile(t, directory, "key.bin", wrapped)
	r := provisionedWrapper(t)

	for _, mode := range []os.FileMode{0o664, 0o646} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}

		_, err := r.ReadKeyFile(context.Background(), path)

		requireLinuxRefused(t, err, path, errFileUntrusted, fs.ErrPermission)
	}

	for _, mode := range []os.FileMode{0o600, 0o640, 0o644} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}

		if read, err := r.ReadKeyFile(context.Background(), path); err != nil || len(read) == 0 {
			t.Errorf("mode %04o: ReadKeyFile = %d bytes, %v; want the key file", mode, len(read), err)
		}
	}
}
