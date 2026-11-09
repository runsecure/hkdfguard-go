package certificate

import (
	"errors"
	"strings"
)

var (
	// ErrInvalidOptions reports options the Validator refuses; the error is a *ValidationError.
	ErrInvalidOptions = errors.New("certificate: invalid options")

	// ErrInvalidArgument reports a nil Options.
	ErrInvalidArgument = errors.New("certificate: invalid argument")

	// ErrNotFound reports a store holding no certificate with the subject named that is valid now
	// (and has its private key, when one is required).
	ErrNotFound = errors.New("certificate: no usable certificate found")

	// ErrNotValidNow reports a certificate that is expired or not yet valid.
	ErrNotValidNow = errors.New("certificate: not valid now")

	// ErrNoPrivateKey reports a certificate without the private key that is required.
	ErrNoPrivateKey = errors.New("certificate: no private key")

	// ErrNoPasswordSource reports a key file with a password and a Loader with no password source.
	ErrNoPasswordSource = errors.New("certificate: no password source")

	// ErrPasswordNotFound reports a password source holding no secret by the name given.
	ErrPasswordNotFound = errors.New("certificate: password not found")

	// ErrInvalidFile reports a file that isn't a certificate or key in the format named.
	ErrInvalidFile = errors.New("certificate: invalid certificate or key file")

	// ErrWrongPassword reports a key file the password doesn't open: a PKCS#12 file whose
	// integrity check fails, or a key that doesn't decrypt.
	ErrWrongPassword = errors.New("certificate: wrong password or corrupt file")

	// ErrUnsupported reports what the Go port can't open: an OpenSSL provider key, a store on a
	// platform or build without one, or a legacy or unknown algorithm in a key file.
	ErrUnsupported = errors.New("certificate: unsupported")

	// ErrClosed reports a key used after its Certificate was closed.
	ErrClosed = errors.New("certificate: closed")
)

// ValidationError is the Validator's refusal of an Options: every failure found, so they can all
// be fixed at once. It matches ErrInvalidOptions.
type ValidationError struct {
	// Name is the options' name, for named options; empty for the default.
	Name string

	// Failures says what is wrong, one failure each.
	Failures []string
}

func (e *ValidationError) Error() string { return strings.Join(e.Failures, "; ") }

// Is reports whether target is ErrInvalidOptions.
func (e *ValidationError) Is(target error) bool { return target == ErrInvalidOptions }
