package hkdfguard

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"runtime"
)

// ErrInvalidKeyFile reports a key file that can't hold a wrapped key: empty, larger than
// MaxWrappedKeyBytes, not a regular file, or writable by its group or by others (Unix). A key
// wrapper that reads its own key files (KeyFileReader) wraps it too for a file it refuses as the
// wrong size, as holding what looks like an unwrapped key, or as not a valid wrapped key.
var ErrInvalidKeyFile = errors.New("hkdfguard: invalid key file")

// keyFileForbiddenPerm is the group- and other-write bits a key file must not have.
const keyFileForbiddenPerm = 0o022

// KeyFileReader is implemented by a KeyWrapper that reads its own key files - the Go form of the
// .NET IKeyWrapper.ReadKeyFileAsync. A key ring reads every key file through its KeyWrapper when the
// wrapper implements this, so a wrapper backed by a native KMS can read through that KMS's own
// checks (the native library refuses a file another account could have replaced, or one holding
// what looks like an unwrapped key). A KeyWrapper without it has its key files read by
// ReadWrappedKeyFile.
type KeyFileReader interface {
	// ReadKeyFile reads a key file holding a key this wrapper wrapped, returning its bytes still
	// wrapped - ready for Unwrap. A missing file's error satisfies errors.Is(err, fs.ErrNotExist);
	// one this account may not read, or whose location the wrapper doesn't trust,
	// errors.Is(err, fs.ErrPermission); one that is not a wrapped key, errors.Is(err,
	// ErrInvalidKeyFile).
	ReadKeyFile(ctx context.Context, path string) ([]byte, error)
}

// ReadKeyFile reads the key file at path through wrapper when it implements KeyFileReader, and
// with ReadWrappedKeyFile otherwise. Either way the bytes come back still wrapped.
func ReadKeyFile(ctx context.Context, wrapper KeyWrapper, path string) ([]byte, error) {
	if reader, ok := wrapper.(KeyFileReader); ok {
		return reader.ReadKeyFile(ctx, path)
	}
	return ReadWrappedKeyFile(ctx, path)
}

// ReadWrappedKeyFile reads a wrapped-DEK key file with ordinary file I/O - for key wrappers with no
// native library of their own to read through (a remote KMS, say, or a test double). It refuses
// anything but a regular file (on Unix, one only its owner can write), an empty file, or one over
// MaxWrappedKeyBytes, each with an error wrapping ErrInvalidKeyFile. It never reads more than one
// byte past the limit, whatever the file's size, so a wrong path (a log, a device) or a file still
// growing can't make startup allocate an unbounded buffer. The checks are made on the opened file,
// so they describe what is read, not a path that may have changed in between.
func ReadWrappedKeyFile(ctx context.Context, path string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if path == "" {
		return nil, fmt.Errorf("hkdfguard: the key file path is empty: %w", fs.ErrInvalid)
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: key file '%s' is not a regular file", ErrInvalidKeyFile, path)
	}
	// Windows reports no meaningful Unix permission bits; its ACLs are the file owner's to set.
	if runtime.GOOS != "windows" && info.Mode().Perm()&keyFileForbiddenPerm != 0 {
		return nil, fmt.Errorf("%w: key file '%s' is writable by its group or by others (mode %04o); only its owner may write it", ErrInvalidKeyFile, path, info.Mode().Perm())
	}

	buffer := make([]byte, MaxWrappedKeyBytes+1)
	n, err := io.ReadFull(file, buffer)
	switch {
	case err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF):
		return nil, err
	case n == 0:
		return nil, fmt.Errorf("%w: key file '%s' is empty", ErrInvalidKeyFile, path)
	case n > MaxWrappedKeyBytes:
		return nil, fmt.Errorf("%w: key file '%s' is larger than %d bytes (hkdfguard.MaxWrappedKeyBytes); a wrapped key never is", ErrInvalidKeyFile, path, MaxWrappedKeyBytes)
	}
	return buffer[:n:n], nil
}
