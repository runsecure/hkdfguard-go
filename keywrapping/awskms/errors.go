package awskms

import (
	"errors"
	"fmt"
)

var (
	// ErrKMS matches every *Error: an AWS KMS call that failed, or that answered with something no
	// wrapped DEK can be, or a wrapped DEK refused before KMS was called.
	ErrKMS = errors.New("awskms: AWS KMS operation failed")

	// ErrInvalidArgument reports an argument the wrapper refuses before calling KMS: an empty key
	// ID, an empty encryption context key, a plaintext KMS would refuse, or a result too small for
	// what KMS returned.
	ErrInvalidArgument = errors.New("awskms: invalid argument")
)

// Error reports an AWS KMS call that failed - KMS refused it, or it could not be made (no
// credentials, KMS unreachable) - or that answered with something no wrapped DEK can be, or a
// wrapped DEK refused before KMS was called because no ciphertext this wrapper produced is that
// size. The message names the operation, the key, and - for a refusal - KMS's error code and the
// HTTP status.
//
// It matches ErrKMS with errors.Is, and unwraps to the AWS SDK's own error, when there is one, so
// errors.As reaches a *types.IncorrectKeyException, a smithy.APIError, and so on.
type Error struct {
	// Op is the operation that failed: "wrap", "unwrap" or "generate-and-wrap".
	Op string

	// KeyID is the key the wrapper was created for, as given.
	KeyID string

	// Message describes the failure.
	Message string

	// Err is the AWS SDK's error, or nil when the failure was found here.
	Err error
}

func (e *Error) Error() string { return e.Message }

// Unwrap returns the AWS SDK's error, if any.
func (e *Error) Unwrap() error { return e.Err }

// Is reports whether target is ErrKMS.
func (e *Error) Is(target error) bool { return target == ErrKMS }

func (w *KeyWrapper) kmsError(op string, cause error, format string, args ...any) *Error {
	return &Error{Op: op, KeyID: w.keyID, Message: fmt.Sprintf(format, args...), Err: cause}
}

// invalidArgument returns an error wrapping ErrInvalidArgument with a formatted reason.
func invalidArgument(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidArgument, fmt.Sprintf(format, args...))
}
