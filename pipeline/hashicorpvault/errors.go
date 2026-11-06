package hashicorpvault

import (
	"errors"
	"fmt"
)

var (
	// ErrVault matches every *Error: a read Vault refused or answered with anything but the secret
	// or its absence, or that could not be made at all.
	ErrVault = errors.New("hashicorpvault: HashiCorp Vault read failed")

	// ErrInvalidArgument reports something New refuses before any call is made: no client, a client
	// whose address would send the token in the clear or that would follow redirects, a mount path
	// that isn't a Vault path, or a KV version that isn't one - and, matching
	// pipeline.ErrInvalidArgument too, whatever pipeline.New refuses of the protector, the secret
	// names and the default key.
	ErrInvalidArgument = errors.New("hashicorpvault: invalid argument")
)

// Error reports a read of one secret that failed: Vault answered with an error other than "nothing
// here" (403 for a token that is invalid or not allowed to read the path, a 404 naming an error
// such as a mount that doesn't exist, 503 while sealed), answered with a redirect that wasn't
// followed, or could not be reached (the client's retries ran out, its timeout passed, or the
// caller's context ended). The message names the secret's path and - for an answer - Vault's status
// and the errors it listed; it never holds the token, nor a secret value.
//
// It matches ErrVault with errors.Is, and unwraps to the Vault client's own error, when there is
// one, so errors.As reaches an *api.ResponseError, and errors.Is a context error.
type Error struct {
	// Path is the secret's path within the KV engine, as read (without its key).
	Path string

	// StatusCode is the HTTP status Vault answered with, or 0 when there was no answer.
	StatusCode int

	// Errors are the errors Vault listed in its answer; nil when it listed none, or its answer
	// wasn't Vault's JSON (a proxy's page, say).
	Errors []string

	// Message describes the failure.
	Message string

	// Err is the Vault client's error, or nil when the failure was found here.
	Err error
}

func (e *Error) Error() string { return e.Message }

// Unwrap returns the Vault client's error, if any.
func (e *Error) Unwrap() error { return e.Err }

// Is reports whether target is ErrVault.
func (e *Error) Is(target error) bool { return target == ErrVault }

// invalidArgument returns an error wrapping ErrInvalidArgument with a formatted reason.
func invalidArgument(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidArgument, fmt.Sprintf(format, args...))
}

// argumentError is what pipeline.New refused, matching both ErrInvalidArgument and
// pipeline.ErrInvalidArgument, with pipeline.New's message.
type argumentError struct{ err error }

func (e *argumentError) Error() string   { return e.err.Error() }
func (e *argumentError) Unwrap() []error { return []error{ErrInvalidArgument, e.err} }
