package securefile

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"

	"github.com/runsecure/hkdfguard-go"
)

// ReadTrustedFile reads the file at path, refusing it unless only the operating system's
// administrators and trust could have written or replaced it - the same symbolic-link, ownership
// and permission checks ReadTrustedKeyFile makes - or if it is longer than maxBytes, but with none
// of a key file's rules about its contents: for secret files, certificates and anything else that
// must come from where only administrators and the trusted principals could have put it. What the
// contents must look like is the caller's to check. It is the Go port of the .NET TrustedFile.
//
// For contents that are not themselves secret - a value encrypted elsewhere, a public certificate;
// use ParseTrustedFile for anything that is.
//
// path is absolute or relative to the working directory. trust is who besides administrators is
// trusted; AdministratorsOnly() for no one. maxBytes is the longest file accepted: at most one byte
// past it is read, whatever the file reports as its length, so a wrong path (a log, a device) can't
// make it read without end. The read buffer is allocated at that size up front, so keep it close to
// the largest file expected. ctx is checked before anything is examined, and once the file is read.
//
// It returns the file's contents, which may be empty, in a slice the caller owns. A refusal is a
// *KeyFileError: fs.ErrNotExist for a file, or a folder on its path, that doesn't exist;
// fs.ErrPermission (with ErrUntrusted for a location that isn't trusted) for one this account may
// not read; ErrTooLarge for one longer than maxBytes; ErrBusy for one another process has open for
// writing (Windows). An empty path, one holding a NUL, or a maxBytes that isn't positive (or is
// math.MaxInt) fails with an error wrapping fs.ErrInvalid; a trust naming a Windows principal that
// can't be trusted, ErrInvalidTrust; a platform other than Windows, Linux or Apple silicon macOS,
// ErrUnsupportedPlatform.
func ReadTrustedFile(ctx context.Context, path string, trust KeyFileTrust, maxBytes int) ([]byte, error) {
	return ParseTrustedFile(ctx, path, trust, maxBytes, func(contents []byte) ([]byte, error) {
		// Copied straight from the read buffer: no intermediate copy outlives its zeroing.
		result := make([]byte, len(contents))
		copy(result, contents)
		return result, nil
	})
}

// ParseTrustedFile reads the file at path as ReadTrustedFile does and hands the contents to parse -
// for contents that are themselves secret, such as a PFX or a PEM private key - returning what parse
// returns. The buffer parse is given is zeroed once it returns (or panics), so parse must not keep
// the slice, and should zero any copy it makes. Go's collector never moves a heap buffer, so there
// is no copy of it elsewhere to zero.
//
// It fails as ReadTrustedFile does, and with an error wrapping fs.ErrInvalid when parse is nil; an
// error parse returns is returned as it is. parse isn't called for a file it refuses.
func ParseTrustedFile[T any](ctx context.Context, path string, trust KeyFileTrust, maxBytes int, parse func(contents []byte) (T, error)) (T, error) {
	var result T
	if err := checkMaxBytes(maxBytes); err != nil {
		return result, err
	}
	if parse == nil {
		return result, fmt.Errorf("securefile: a parse function is required: %w", fs.ErrInvalid)
	}
	if err := checkReadable(ctx, path, trustedFileNoun); err != nil {
		return result, err
	}
	err := openOnPlatform(path, trust, trustedFileNoun, func(read readFunc, name string) error {
		return readBounded(read, name, maxBytes, func(contents []byte) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			var err error
			result, err = parse(contents)
			return err
		})
	})
	if err != nil {
		var zero T
		return zero, err
	}
	return result, nil
}

// checkMaxBytes refuses a limit that isn't positive, or that one byte can't be added to.
func checkMaxBytes(maxBytes int) error {
	if maxBytes <= 0 || maxBytes == math.MaxInt {
		return fmt.Errorf("securefile: the most a file may hold must be positive and less than %d, got %d: %w", math.MaxInt, maxBytes, fs.ErrInvalid)
	}
	return nil
}

// readBounded reads at most one byte past maxBytes through read into a buffer of its own, refusing
// a longer file with ErrTooLarge, and hands use what was read - which may be nothing. The buffer is
// zeroed once use returns, or the read fails.
func readBounded(read readFunc, path string, maxBytes int, use func([]byte) error) error {
	buffer := make([]byte, maxBytes+1)
	defer hkdfguard.Wipe(buffer)

	total, err := readAtMost(read, buffer)
	if err != nil {
		return err
	}
	if total > maxBytes {
		return keyFileError(ErrTooLarge, path, "'%s' is larger than %d bytes, the most it may be.", path, maxBytes)
	}
	return use(buffer[:total])
}

// readAtMost fills buffer through read as far as the file goes, returning how much it read; filled
// means the file is at least that long. An error read returns is passed on as it is.
func readAtMost(read readFunc, buffer []byte) (int, error) {
	total := 0
	for total < len(buffer) {
		count, err := read(buffer[total:])
		if count > 0 {
			total += count
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return 0, err
		}
		if count <= 0 {
			break
		}
	}
	return total, nil
}
