package hkdfguard_test

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/runsecure/hkdfguard-go"
)

func writeKeyFile(t *testing.T, contents []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "key.bin")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadWrappedKeyFile_UpToTheLimit_IsReadWhole_AndEmptyOrLargerOnesRefused(t *testing.T) {
	ctx := context.Background()
	for _, length := range []int{1, hkdfguard.MaxWrappedKeyBytes} {
		contents := bytes.Repeat([]byte{7}, length)
		if read, err := hkdfguard.ReadWrappedKeyFile(ctx, writeKeyFile(t, contents)); err != nil || !bytes.Equal(read, contents) {
			t.Errorf("%d bytes: read %d, %v", length, len(read), err)
		}
	}
	for _, length := range []int{0, hkdfguard.MaxWrappedKeyBytes + 1, 1 << 20} {
		if _, err := hkdfguard.ReadWrappedKeyFile(ctx, writeKeyFile(t, make([]byte, length))); !errors.Is(err, hkdfguard.ErrInvalidKeyFile) {
			t.Errorf("%d bytes: %v; want ErrInvalidKeyFile", length, err)
		}
	}
}

func TestReadWrappedKeyFile_WritableByGroupOrOthers_IsRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits are not meaningful on Windows")
	}
	ctx := context.Background()
	contents := []byte{1, 2, 3}

	for _, mode := range []os.FileMode{0o400, 0o600, 0o640, 0o644} {
		path := writeKeyFile(t, contents)
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if read, err := hkdfguard.ReadWrappedKeyFile(ctx, path); err != nil || !bytes.Equal(read, contents) {
			t.Errorf("mode %04o: read %v, %v; want the contents", mode, read, err)
		}
	}
	for _, mode := range []os.FileMode{0o620, 0o660, 0o602, 0o666} {
		path := writeKeyFile(t, contents)
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := hkdfguard.ReadWrappedKeyFile(ctx, path); !errors.Is(err, hkdfguard.ErrInvalidKeyFile) {
			t.Errorf("mode %04o: %v; want ErrInvalidKeyFile", mode, err)
		}
	}
}

func TestReadWrappedKeyFile_ADirectory_IsRefused(t *testing.T) {
	if _, err := hkdfguard.ReadWrappedKeyFile(context.Background(), t.TempDir()); !errors.Is(err, hkdfguard.ErrInvalidKeyFile) {
		t.Errorf("a directory: %v; want ErrInvalidKeyFile", err)
	}
}

func TestReadWrappedKeyFile_AMissingFile_IsNotExist(t *testing.T) {
	_, err := hkdfguard.ReadWrappedKeyFile(context.Background(), filepath.Join(t.TempDir(), "missing.bin"))

	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("error = %v; want fs.ErrNotExist", err)
	}
}

func TestReadWrappedKeyFile_AnEmptyPathOrCancelledContext_IsRefusedBeforeOpening(t *testing.T) {
	if _, err := hkdfguard.ReadWrappedKeyFile(context.Background(), ""); !errors.Is(err, fs.ErrInvalid) {
		t.Errorf("empty path: %v; want fs.ErrInvalid", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := hkdfguard.ReadWrappedKeyFile(ctx, writeKeyFile(t, []byte{1})); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: %v; want context.Canceled", err)
	}
}

// plainWrapper is a KeyWrapper that doesn't read its own key files.
type plainWrapper struct{}

func (plainWrapper) Wrap(context.Context, []byte, []byte) (int, error)   { return 0, nil }
func (plainWrapper) Unwrap(context.Context, []byte, []byte) (int, error) { return 0, nil }
func (plainWrapper) GenerateAndWrap(context.Context, []byte) (int, error) {
	return 0, nil
}

// readingWrapper is a KeyWrapper that reads its own key files.
type readingWrapper struct {
	plainWrapper
	paths    []string
	contents []byte
	err      error
}

func (w *readingWrapper) ReadKeyFile(_ context.Context, path string) ([]byte, error) {
	w.paths = append(w.paths, path)
	return w.contents, w.err
}

func TestReadKeyFile_ThroughAWrapperThatReadsItsOwnKeyFiles_UsesTheWrapper(t *testing.T) {
	wrapper := &readingWrapper{contents: []byte{9, 8, 7}}

	read, err := hkdfguard.ReadKeyFile(context.Background(), wrapper, "/not/opened/here")

	if err != nil || !bytes.Equal(read, wrapper.contents) {
		t.Errorf("ReadKeyFile = %v, %v; want the wrapper's bytes", read, err)
	}
	if len(wrapper.paths) != 1 || wrapper.paths[0] != "/not/opened/here" {
		t.Errorf("the wrapper was asked for %v", wrapper.paths)
	}
}

func TestReadKeyFile_ThroughAWrapperThatReadsItsOwnKeyFiles_SurfacesItsFailure(t *testing.T) {
	refusal := errors.New("refused by the wrapper")
	wrapper := &readingWrapper{err: refusal}

	// The file exists and is valid: only the wrapper could have refused it.
	_, err := hkdfguard.ReadKeyFile(context.Background(), wrapper, writeKeyFile(t, []byte{1, 2, 3}))

	if !errors.Is(err, refusal) {
		t.Errorf("error = %v; want the wrapper's", err)
	}
}

func TestReadKeyFile_ThroughAnyOtherWrapper_ReadsTheFileItself(t *testing.T) {
	contents := []byte{4, 5, 6}

	read, err := hkdfguard.ReadKeyFile(context.Background(), plainWrapper{}, writeKeyFile(t, contents))

	if err != nil || !bytes.Equal(read, contents) {
		t.Errorf("ReadKeyFile = %v, %v; want the file's contents", read, err)
	}
	if _, err := hkdfguard.ReadKeyFile(context.Background(), plainWrapper{}, writeKeyFile(t, nil)); !errors.Is(err, hkdfguard.ErrInvalidKeyFile) {
		t.Errorf("an empty file: %v; want ErrInvalidKeyFile", err)
	}
}
