//go:build windows

package integration

import (
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/dek"
	"github.com/runsecure/hkdfguard-go/keywrapping/nativev1"
)

// keyFileDirectory is a fresh temporary folder for key files, by its long path: the native library
// refuses a key file path that uses an 8.3 short name anywhere, and Windows can hand out %TEMP% in
// short form (for example C:\Users\RUNNER~1\... on GitHub-hosted runners).
func keyFileDirectory(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	short, err := syscall.UTF16PtrFromString(directory)
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]uint16, 32767)
	n, err := syscall.GetLongPathName(short, &buffer[0], uint32(len(buffer)))
	if err != nil || n == 0 || int(n) >= len(buffer) {
		t.Fatalf("GetLongPathName(%s) = %d, %v", directory, n, err)
	}
	return syscall.UTF16ToString(buffer[:n])
}

func TestAKeyRing_RefusesToBuildFromAPlaintextKeyFile(t *testing.T) {
	// No KEK is needed: the native library refuses the file before anything is unwrapped.
	wrapper, err := nativev1.New("hkdfguard.keyfile.reader")
	if errors.Is(err, nativev1.ErrNotInstalled) || errors.Is(err, nativev1.ErrUnsupportedPlatform) {
		t.Skipf("the native library can't be used here: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(keyFileDirectory(t), "plaintext.bin")
	if err := os.WriteFile(path, key, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = buildRingWith(t, wrapper, ringOptions{keyFile: path})

	var keyFileErr *nativev1.KeyFileError
	if !errors.Is(err, dek.ErrInvalidKeyFile) || !errors.Is(err, hkdfguard.ErrInvalidKeyFile) || !errors.As(err, &keyFileErr) || keyFileErr.Status != -37 {
		t.Errorf("error = %v; want the native library's plaintext-key refusal (-37)", err)
	}
}
