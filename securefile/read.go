package securefile

import (
	"context"
	"fmt"
	"io/fs"
	"runtime"
	"strings"
)

// ReadTrustedKeyFile reads the key file at path, still wrapped, refusing it unless only the
// operating system's administrators and trust could have written or replaced it, and refusing
// contents that aren't a wrapped key: the Go equivalent of the native library's
// hkdfguard_open_file, for a hkdfguard.KeyWrapper's ReadKeyFile with no native library to read
// through - a network KMS's key wrapper, say. See the package documentation for the rules.
//
// path is absolute or relative to the working directory. trust is who besides administrators is
// trusted; AdministratorsOnly() (the zero KeyFileTrust) for no one. ctx is checked before anything
// is examined; a key file is a few hundred bytes on a local drive, so the checks and the read are
// not otherwise interruptible.
//
// It returns the file's contents, still wrapped, in a slice the caller owns. A refusal is a
// *KeyFileError (see its documentation for what it unwraps to). An empty path, or one holding a
// NUL, fails with an error wrapping fs.ErrInvalid; a trust naming a Windows principal that can't
// be trusted, ErrInvalidTrust; a platform other than Windows, Linux or Apple silicon macOS,
// ErrUnsupportedPlatform.
func ReadTrustedKeyFile(ctx context.Context, path string, trust KeyFileTrust) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if path == "" {
		return nil, fmt.Errorf("securefile: a key file path is required: %w", fs.ErrInvalid)
	}
	if strings.IndexByte(path, 0) >= 0 {
		return nil, fmt.Errorf("securefile: a key file path can't contain a NUL character: %w", fs.ErrInvalid)
	}
	if err := platformSupport(runtime.GOOS, runtime.GOARCH); err != nil {
		return nil, err
	}
	return readOnPlatform(path, trust)
}

// platformSupport refuses every platform but Windows, Linux and Apple silicon macOS. The .NET and
// Java ports read struct stat at arm64 offsets on macOS; Go's own Lstat has no such limit, but the
// supported platforms are kept the same in every port.
func platformSupport(goos, goarch string) error {
	switch goos {
	case "windows", "linux":
		return nil
	case "darwin":
		if goarch != "arm64" {
			return unsupported("Key files are read on Apple silicon Macs only; this process is %s.", goarch)
		}
		return nil
	default:
		return unsupported("Key files are read on Windows, Linux and macOS only.")
	}
}
