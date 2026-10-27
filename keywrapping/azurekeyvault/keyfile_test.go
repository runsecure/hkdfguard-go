package azurekeyvault

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/runsecure/hkdfguard-go/securefile"
)

// keyFilesRead reports whether securefile reads key files on this platform.
func keyFilesRead() bool {
	return runtime.GOOS == "windows" || runtime.GOOS == "linux" || (runtime.GOOS == "darwin" && runtime.GOARCH == "arm64")
}

// userWritableKeyFile is a key file in a folder the user running the tests could replace: under the
// user's temp folder (Windows) or the shared /tmp (Linux and macOS) - neither somewhere only
// administrators can write.
func userWritableKeyFile(t *testing.T) string {
	t.Helper()
	root := "/tmp"
	if runtime.GOOS == "windows" {
		root = os.TempDir()
	}
	directory, err := os.MkdirTemp(root, "hkdfguard-keys-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	path := filepath.Join(directory, "v1.key")
	if err := os.WriteFile(path, random(184), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func requireNotTrusted(t *testing.T, err error) {
	t.Helper()
	var keyFileErr *securefile.KeyFileError
	if !errors.As(err, &keyFileErr) || !errors.Is(err, securefile.ErrUntrusted) || !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("got %v; want a key file refused as not trusted", err)
	}
}

func TestReadKeyFile_RefusesByDefaultAFileTheCurrentUserCouldHaveReplaced(t *testing.T) {
	if !keyFilesRead() {
		t.Skip("Key files are read on Windows, Linux and Apple silicon macOS only.")
	}
	_, err := newWrapper(t, newFakeVault(t), withContext()).ReadKeyFile(t.Context(), userWritableKeyFile(t))
	requireNotTrusted(t, err)
}

func TestReadKeyFile_TrustsAdministratorsOnly_WhenGivenNoTrust(t *testing.T) {
	if !keyFilesRead() {
		t.Skip("Key files are read on Windows, Linux and Apple silicon macOS only.")
	}
	// The same refusal as the default: a zero KeyFileTrust is AdministratorsOnly, never "anyone".
	_, err := newWrapper(t, newFakeVault(t), Options{KeyFileTrust: securefile.KeyFileTrust{}}).ReadKeyFile(t.Context(), userWritableKeyFile(t))
	requireNotTrusted(t, err)
}

func TestReadKeyFile_RefusesAMissingPath(t *testing.T) {
	for _, path := range []string{"", "v1\x00.key"} {
		if _, err := newWrapper(t, newFakeVault(t)).ReadKeyFile(t.Context(), path); !errors.Is(err, fs.ErrInvalid) {
			t.Errorf("%q: %v; want fs.ErrInvalid", path, err)
		}
	}
}

// readAndReveal writes a wrapped DEK generated through the wrapper to path, reads it back through
// the wrapper, and checks it reveals.
func readAndReveal(t *testing.T, wrapper *KeyWrapper, path string) {
	t.Helper()
	wrapped := make([]byte, 512)
	n, err := wrapper.GenerateAndWrap(t.Context(), wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, wrapped[:n], 0o600); err != nil {
		t.Fatal(err)
	}
	read, err := wrapper.ReadKeyFile(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	if string(read) != string(wrapped[:n]) {
		t.Fatal("the key file read back differs from what was written")
	}
	if m, err := wrapper.Unwrap(t.Context(), read, make([]byte, 32)); err != nil || m != 32 {
		t.Fatalf("%d, %v; want the DEK revealed", m, err)
	}
}
