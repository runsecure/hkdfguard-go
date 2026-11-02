package hashicorpvault

import (
	"errors"
	"fmt"
)

var (
	// ErrVault matches every *Error: a Vault transit call that failed, or that answered with
	// something no wrapped DEK can be, or a wrapped DEK refused before Vault was called.
	ErrVault = errors.New("hashicorpvault: Vault transit operation failed")

	// ErrInvalidArgument reports an argument the wrapper refuses before calling Vault: no client, a
	// client that would send the token in the clear or follow redirects, a key name or mount path
	// that isn't one, a context too long or not UTF-8, a plaintext out of bounds, or a result too
	// small for what it would hold.
	ErrInvalidArgument = errors.New("hashicorpvault: invalid argument")
)

// Error reports a Vault transit call that failed - Vault refused it, or it could not be made (an
// unreachable address, retries that ran out, the client's timeout) - or that answered with
// something no wrapped DEK can be: a body that isn't Vault's, a redirect, a ciphertext that isn't
// one, a parameter Vault says it ignored. Also a wrapped DEK refused before Vault was called because
// no ciphertext Vault produces is that size or shape. The message names the operation, the key,
// and - for a refusal - the HTTP status and Vault's errors ("Vault answered 400 Bad Request: cipher:
// message authentication failed").
//
// It matches ErrVault with errors.Is, and unwraps to the client's own error, when there is one, so
// errors.As reaches the *api.ResponseError carrying Vault's StatusCode and Errors.
type Error struct {
	// Op is the operation that failed: "wrap", "unwrap" or "generate-and-wrap" (GenerateAndWrap
	// with a context wraps a DEK it generated, so fails as "wrap").
	Op string

	// KeyName is the transit key the wrapper was created for.
	KeyName string

	// Message describes the failure.
	Message string

	// Err is the client's error, or nil when the failure was found here.
	Err error
}

func (e *Error) Error() string { return e.Message }

// Unwrap returns the client's error, if any.
func (e *Error) Unwrap() error { return e.Err }

// Is reports whether target is ErrVault.
func (e *Error) Is(target error) bool { return target == ErrVault }

func (w *KeyWrapper) vaultError(op string, cause error, format string, args ...any) *Error {
	return &Error{Op: op, KeyName: w.keyName, Message: fmt.Sprintf(format, args...), Err: cause}
}

// contextError is a call that failed because its context ended: it matches the context's error, and
// unwraps to the client's too.
type contextError struct {
	ctxErr error
	err    error
}

func (e *contextError) Error() string   { return e.err.Error() }
func (e *contextError) Unwrap() []error { return []error{e.ctxErr, e.err} }

// invalidArgument returns an error wrapping ErrInvalidArgument with a formatted reason.
func invalidArgument(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidArgument, fmt.Sprintf(format, args...))
}
