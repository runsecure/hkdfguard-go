package nativev1

import (
	"errors"
	"fmt"
)

var (
	// ErrNotInstalled reports that the native KMS library is not installed at any location it is
	// loaded from.
	ErrNotInstalled = errors.New("nativev1: native KMS library not installed")

	// ErrUntrusted reports that the installed library, its location, its dependencies, or the
	// process environment failed verification, so it was not loaded.
	ErrUntrusted = errors.New("nativev1: native KMS library failed verification")

	// ErrUnsupportedPlatform reports a platform (OS, architecture, OS version, or a build without
	// cgo on macOS/Linux) the native library can't be used on, or an operation it doesn't offer.
	ErrUnsupportedPlatform = errors.New("nativev1: unsupported platform")
)

// StatusError reports a native call that returned a non-zero status. Status codes differ between
// platforms; Description is this platform's meaning of Status, or "" when it is unknown.
type StatusError struct {
	// Op is the operation that failed: "wrap", "unwrap", "generate-and-wrap", or
	// "process hardening".
	Op string

	// Service is the service name the operation ran under; "" for process hardening.
	Service string

	// Status is the native library's status code.
	Status int32

	// Description is what Status means on this platform, or "".
	Description string
}

func (e *StatusError) Error() string {
	meaning := ""
	if e.Description != "" {
		meaning = " (" + e.Description + ")"
	}
	if e.Service == "" {
		return fmt.Sprintf("Native %s failed with status %d%s.", e.Op, e.Status, meaning)
	}
	return fmt.Sprintf("Native KMS %s failed for service '%s' with status %d%s.", e.Op, e.Service, e.Status, meaning)
}

// untrusted returns an error wrapping ErrUntrusted with a formatted reason.
func untrusted(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrUntrusted, fmt.Sprintf(format, args...))
}

// untrustedCause is untrusted, also wrapping cause so errors.Is/As still reach it.
func untrustedCause(cause error, format string, args ...any) error {
	return fmt.Errorf("%w: %s: %w", ErrUntrusted, fmt.Sprintf(format, args...), cause)
}

// notInstalled returns an error wrapping ErrNotInstalled with a formatted reason.
func notInstalled(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrNotInstalled, fmt.Sprintf(format, args...))
}

// unsupported returns an error wrapping ErrUnsupportedPlatform with a formatted reason.
func unsupported(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrUnsupportedPlatform, fmt.Sprintf(format, args...))
}

// classify returns err unchanged if it already wraps one of this package's sentinel errors, and
// otherwise wraps it in ErrUntrusted: any failure while verifying the library - including a path
// that couldn't be examined - is a reason not to load it.
func classify(err error) error {
	if err == nil || errors.Is(err, ErrNotInstalled) || errors.Is(err, ErrUntrusted) || errors.Is(err, ErrUnsupportedPlatform) {
		return err
	}
	return fmt.Errorf("%w: %w", ErrUntrusted, err)
}
