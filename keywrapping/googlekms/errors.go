package googlekms

import (
	"errors"
	"fmt"
)

var (
	// ErrCloudKMS matches every *Error: a Cloud KMS call that failed, or that answered with something
	// no wrapped DEK can be, or a wrapped DEK refused before Cloud KMS was called.
	ErrCloudKMS = errors.New("googlekms: Google Cloud KMS operation failed")

	// ErrInvalidArgument reports an argument the wrapper refuses before calling Cloud KMS: no client,
	// a resource name that isn't a key's, a context too long or not UTF-8, a plaintext Cloud KMS
	// would refuse, or a result too small for what it would hold.
	ErrInvalidArgument = errors.New("googlekms: invalid argument")
)

// Error reports a Cloud KMS call that failed - Cloud KMS refused it, or it could not be made (a
// credential that can't get a token, an unreachable service, retries that ran out of time) - or that
// answered with something no wrapped DEK can be: a response corrupted in transit, or for another key.
// Also a wrapped DEK refused before Cloud KMS was called because no ciphertext this wrapper produced
// is that size. The message names the operation, the key, and - for a refusal - the gRPC status and
// Google's description ("INVALID_ARGUMENT: Decryption failed.").
//
// It matches ErrCloudKMS with errors.Is, and unwraps to the client's own error, when there is one, so
// errors.As reaches an *apierror.APIError, and status.Code reads its gRPC status.
type Error struct {
	// Op is the operation that failed: "wrap" (for Wrap and GenerateAndWrap) or "unwrap".
	Op string

	// KeyName is the key the wrapper was created for: its resource name.
	KeyName string

	// Message describes the failure.
	Message string

	// Err is the client's error, or nil when the failure was found here.
	Err error
}

func (e *Error) Error() string { return e.Message }

// Unwrap returns the client's error, if any.
func (e *Error) Unwrap() error { return e.Err }

// Is reports whether target is ErrCloudKMS.
func (e *Error) Is(target error) bool { return target == ErrCloudKMS }

func (w *KeyWrapper) cloudKMSError(op string, cause error, format string, args ...any) *Error {
	return &Error{Op: op, KeyName: w.keyName, Message: fmt.Sprintf(format, args...), Err: cause}
}

// invalidArgument returns an error wrapping ErrInvalidArgument with a formatted reason.
func invalidArgument(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidArgument, fmt.Sprintf(format, args...))
}
