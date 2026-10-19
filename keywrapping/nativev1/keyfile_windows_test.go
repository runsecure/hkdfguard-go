//go:build windows

package nativev1

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/runsecure/hkdfguard-go"
)

// Reading key files through the real native library's hkdfguard_open_file - the port of the .NET
// NativeKeyFileTests. Refusals of a file's size, contents or location need no KEK, so they run
// wherever the library is installed; reading back a real wrapped key needs the provisioned test
// service (see native_test.go).

// keyFileDirectory is a fresh temporary folder for key files, by its long path: hkdfguard_open_file
// refuses an 8.3 short name anywhere in a path, and Windows can hand out %TEMP% in short form (for
// example C:\Users\RUNNER~1\... on GitHub-hosted runners).
func keyFileDirectory(t *testing.T) string {
	t.Helper()
	return longPath(t, t.TempDir())
}

func longPath(t *testing.T, path string) string {
	t.Helper()
	short, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetLongPathName(short, &buffer[0], uint32(len(buffer)))
	if err != nil || n == 0 || int(n) >= len(buffer) {
		t.Fatalf("GetLongPathName(%s) = %d, %v", path, n, err)
	}
	return windows.UTF16ToString(buffer[:n])
}

// keyFileReader is a wrapper for reading key files: any valid service name will do, since reading a
// file never touches a KEK. Skips the test when the library isn't installed.
func keyFileReader(t *testing.T) *KeyWrapper {
	t.Helper()
	installedWindowsLibraryPath(t)
	installedLibrary(t)
	w, err := New("hkdfguard.keyfile.reader")
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func writeKeyFileIn(t *testing.T, directory, name string, contents []byte) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// requireRefused checks that err is a *KeyFileError for path with status, satisfying is, and that
// its message names the path, the status and what it means.
func requireRefused(t *testing.T, err error, path string, status int32, is error) {
	t.Helper()
	var keyFileErr *KeyFileError
	if !errors.As(err, &keyFileErr) {
		t.Fatalf("error = %v; want a *KeyFileError", err)
	}
	if keyFileErr.Status != status || keyFileErr.Path != path {
		t.Errorf("refused %q with status %d (%s); want %q, %d", keyFileErr.Path, keyFileErr.Status, keyFileErr.Description, path, status)
	}
	if is != nil && !errors.Is(err, is) {
		t.Errorf("error = %v; want errors.Is(err, %v)", err, is)
	}
	for _, want := range []string{"'" + path + "'", fmt.Sprintf("status %d", status), describeWindowsStatus(status)} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message %q does not contain %q", err.Error(), want)
		}
	}
}

// wrapToFile wraps a fresh DEK under the test service and writes it as a key file.
func wrapToFile(t *testing.T, w *KeyWrapper, directory string) (path string, wrapped, dekBytes []byte) {
	t.Helper()
	dekBytes = randomDEK(t)
	buffer := make([]byte, hkdfguard.MaxWrappedKeyBytes)
	n, err := w.Wrap(context.Background(), bytes.Clone(dekBytes), buffer)
	if err != nil {
		t.Fatal(err)
	}
	wrapped = buffer[:n]
	return writeKeyFileIn(t, directory, "wrapped-dek.bin", wrapped), wrapped, dekBytes
}

// --- A real key file ----------------------------------------------------------------------------

func TestWindowsKeyFile_AKeyFileTheWrapperWrote_ReadsBackStillWrapped_AndUnwrapsToItsDEK(t *testing.T) {
	w := provisionedWrapper(t)
	path, wrapped, dekBytes := wrapToFile(t, w, keyFileDirectory(t))

	read, err := w.ReadKeyFile(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(read, wrapped) || len(read) != 132 {
		t.Fatalf("read %d bytes, equal to what was written: %v", len(read), bytes.Equal(read, wrapped))
	}

	recovered := make([]byte, DEKLength)
	if n, err := w.Unwrap(context.Background(), read, recovered); err != nil || n != DEKLength || !bytes.Equal(recovered, dekBytes) {
		t.Errorf("Unwrap = %d, %v; recovered the DEK: %v", n, err, bytes.Equal(recovered, dekBytes))
	}
}

func TestWindowsKeyFile_TheKeyRingsKeyFileRead_GoesThroughTheNativeLibrary(t *testing.T) {
	// hkdfguard.ReadKeyFile is what dek.Build calls for each key file; the integration module
	// builds real rings from key files (and refuses a plaintext one) end to end.
	w := provisionedWrapper(t)
	path, wrapped, _ := wrapToFile(t, w, keyFileDirectory(t))

	read, err := hkdfguard.ReadKeyFile(context.Background(), w, path)
	if err != nil || !bytes.Equal(read, wrapped) {
		t.Errorf("ReadKeyFile = %d bytes, %v; want the file's", len(read), err)
	}

	plaintext := writeKeyFileIn(t, filepath.Dir(path), "plaintext.bin", randomDEK(t))
	_, err = hkdfguard.ReadKeyFile(context.Background(), w, plaintext)
	requireRefused(t, err, plaintext, errFilePlaintextKey, hkdfguard.ErrInvalidKeyFile)
}

func TestWindowsKeyFile_AKeyFileOfTheRightSizeWithAnUnknownVersion_IsMalformed(t *testing.T) {
	w := provisionedWrapper(t)
	path, wrapped, _ := wrapToFile(t, w, keyFileDirectory(t))
	wrapped[0] ^= 0xFF // the version byte
	if err := os.WriteFile(path, wrapped, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := keyFileReader(t).ReadKeyFile(context.Background(), path)

	requireRefused(t, err, path, errFileMalformed, hkdfguard.ErrInvalidKeyFile)
}

// --- Files the native library refuses, whatever the KEK ------------------------------------------

func TestWindowsKeyFile_AMissingFile_IsNotFound(t *testing.T) {
	r := keyFileReader(t)
	path := filepath.Join(keyFileDirectory(t), "missing.bin")

	_, err := r.ReadKeyFile(context.Background(), path)

	requireRefused(t, err, path, errFileNotFound, fs.ErrNotExist)
}

func TestWindowsKeyFile_AFileInAMissingFolder_IsNotFound(t *testing.T) {
	r := keyFileReader(t)
	path := filepath.Join(keyFileDirectory(t), "no-such-folder", "dek.bin")

	_, err := r.ReadKeyFile(context.Background(), path)

	requireRefused(t, err, path, errFileNotFound, fs.ErrNotExist)
}

func TestWindowsKeyFile_AFileHoldingWhatLooksLikeAnUnwrappedKey_IsRefusedAsAKeyExposure(t *testing.T) {
	r := keyFileReader(t)
	directory := keyFileDirectory(t)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	forms := map[string][]byte{
		"raw":                 key,
		"hex":                 []byte(strings.ToUpper(hex.EncodeToString(key))),
		"lower-hex":           []byte(hex.EncodeToString(key)),
		"base64":              []byte(base64.StdEncoding.EncodeToString(key)),
		"base64-with-newline": []byte(base64.StdEncoding.EncodeToString(key) + "\n"),
	}
	for form, contents := range forms {
		t.Run(form, func(t *testing.T) {
			path := writeKeyFileIn(t, directory, "plaintext-"+form+".bin", contents)

			_, err := r.ReadKeyFile(context.Background(), path)

			requireRefused(t, err, path, errFilePlaintextKey, hkdfguard.ErrInvalidKeyFile)
			if err != nil && !strings.Contains(err.Error(), "key exposure") {
				t.Errorf("message %q does not say it is a key exposure", err)
			}
		})
	}
}

func TestWindowsKeyFile_AFileOfTheWrongSize_IsRefused(t *testing.T) {
	r := keyFileReader(t)
	directory := keyFileDirectory(t)

	for _, c := range []struct {
		size   int
		status int32
	}{{0, errFileTooShort}, {100, errFileTooShort}, {131, errFileTooShort}, {133, errFileTooLong}, {4096, errFileTooLong}} {
		t.Run(fmt.Sprint(c.size), func(t *testing.T) {
			contents := make([]byte, c.size)
			if c.size > 0 {
				contents[0] = 0x7F // never mistaken for text
			}
			path := writeKeyFileIn(t, directory, fmt.Sprintf("size-%d.bin", c.size), contents)

			_, err := r.ReadKeyFile(context.Background(), path)

			requireRefused(t, err, path, c.status, hkdfguard.ErrInvalidKeyFile)
		})
	}
}

func TestWindowsKeyFile_AFolder_IsNotAKeyFile(t *testing.T) {
	r := keyFileReader(t)
	directory := keyFileDirectory(t)

	read, err := r.ReadKeyFile(context.Background(), directory)

	var keyFileErr *KeyFileError
	if read != nil || !errors.As(err, &keyFileErr) {
		t.Fatalf("ReadKeyFile = %v, %v; want a *KeyFileError", read, err)
	}
	if !strings.Contains(err.Error(), directory) || describeWindowsStatus(keyFileErr.Status) == "" {
		t.Errorf("error = %v", err)
	}
}

func TestWindowsKeyFile_AFileReachedThroughAJunction_IsUntrusted(t *testing.T) {
	r := keyFileReader(t)
	directory := keyFileDirectory(t)
	target := filepath.Join(directory, "real")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	writeKeyFileIn(t, target, "dek.bin", make([]byte, 132))
	junction := filepath.Join(directory, "junction")

	// mklink /J needs no elevation, unlike a symbolic link.
	if output, err := exec.Command("cmd.exe", "/c", "mklink", "/J", junction, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v: %s", err, output)
	}
	// Remove the junction itself, never what it points at, before the temporary folder goes.
	t.Cleanup(func() { _ = os.Remove(junction) })

	path := filepath.Join(junction, "dek.bin")
	_, err := r.ReadKeyFile(context.Background(), path)

	requireRefused(t, err, path, errFileUntrusted, fs.ErrPermission)
}
