package securefile

import (
	"errors"
	"fmt"
	"io/fs"
)

var (
	// ErrUntrusted reports a key file whose location is not trusted: it, or a folder above it, is
	// owned or modifiable by an account that is neither an administrator nor named by the
	// KeyFileTrust, or its path runs through something that could redirect it. A *KeyFileError
	// carrying it also matches fs.ErrPermission, as every port reports such a file.
	ErrUntrusted = errors.New("securefile: key file is not trusted")

	// ErrBusy reports a key file another process has open for writing (Windows).
	ErrBusy = errors.New("securefile: key file is open for writing by another process")

	// ErrUnsupportedPlatform reports a platform key files are not read on: anything but Windows,
	// Linux and Apple silicon macOS.
	ErrUnsupportedPlatform = errors.New("securefile: unsupported platform")

	// ErrInvalidTrust reports a KeyFileTrust naming a Windows principal that is not a security
	// identifier, or one every account (or every signed-in one) is in.
	ErrInvalidTrust = errors.New("securefile: invalid key file trust")
)

// KeyFileError reports a key file ReadTrustedKeyFile refused or could not read. It unwraps to the
// error a caller can act on, so errors.Is works without parsing the message:
//
//   - fs.ErrNotExist: the file, or a folder on its path, does not exist.
//   - fs.ErrPermission: this account may not read it - or, together with ErrUntrusted, its location
//     is not trusted (the message says "is not trusted" and names what).
//   - hkdfguard.ErrInvalidKeyFile: it is empty, larger than hkdfguard.MaxWrappedKeyBytes, or holds
//     what looks like an unwrapped key.
//   - ErrBusy: another process has it open for writing (Windows).
//   - anything else: the system's own error (a syscall.Errno).
type KeyFileError struct {
	// Path is the key file's path, as given or as resolved - whichever the message names.
	Path string

	// Message describes the refusal.
	Message string

	// Err is the error the refusal unwraps to.
	Err error
}

func (e *KeyFileError) Error() string { return e.Message }

// Unwrap returns Err - and fs.ErrPermission too when Err is ErrUntrusted.
func (e *KeyFileError) Unwrap() []error {
	switch {
	case e.Err == nil:
		return nil
	case errors.Is(e.Err, ErrUntrusted):
		return []error{e.Err, fs.ErrPermission}
	default:
		return []error{e.Err}
	}
}

// keyFileError returns a *KeyFileError unwrapping to err, with a formatted message.
func keyFileError(err error, path, format string, args ...any) *KeyFileError {
	return &KeyFileError{Path: path, Message: fmt.Sprintf(format, args...), Err: err}
}

// invalidTrust returns an error wrapping ErrInvalidTrust with a formatted reason.
func invalidTrust(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidTrust, fmt.Sprintf(format, args...))
}

// unsupported returns an error wrapping ErrUnsupportedPlatform with a formatted reason.
func unsupported(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrUnsupportedPlatform, fmt.Sprintf(format, args...))
}
