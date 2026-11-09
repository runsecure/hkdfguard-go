//go:build linux

package systemdcredentials

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A FIFO or device where a credential should be is refused, and promptly: a FIFO with no writer
// would block an ordinary open forever, and /dev/zero would never end.
func TestALoadedCredentialThatIsntARegularFile_IsRefusedWithoutBlocking(t *testing.T) {
	folder := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(folder, "fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/zero", filepath.Join(folder, "device")); err != nil {
		t.Fatal(err)
	}
	source, err := NewSource(nil, nil, folder)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"fifo", "device"} {
		done := make(chan error, 2)
		go func() {
			_, err := ReadLoadedCredential(name, folder)
			done <- err
			_, err = source.Decrypt(context.Background(), name, make([]byte, 16))
			done <- err
		}()
		for range 2 {
			select {
			case err := <-done:
				if !errors.Is(err, ErrInvalidArgument) {
					t.Fatalf("%s: got %v", name, err)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("%s: reading it blocked", name)
			}
		}
	}
}
