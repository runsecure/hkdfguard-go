package azurekeyvault

import (
	"errors"
	"fmt"
)

var (
	// ErrKeyVault matches every *Error: an Azure Key Vault call that failed, or that answered with
	// something no wrapped DEK can be made of, or a wrapped DEK refused before or after Key Vault
	// was called.
	ErrKeyVault = errors.New("azurekeyvault: Azure Key Vault operation failed")

	// ErrInvalidArgument reports an argument the wrapper refuses before calling Key Vault: a key
	// identifier that isn't one, the same key to wrap and sign, no credential, a context too long or
	// not UTF-8, a plaintext RSA-OAEP-256 can't wrap, or a result too small for what it would hold.
	ErrInvalidArgument = errors.New("azurekeyvault: invalid argument")
)

// Error reports an Azure Key Vault call that failed - Key Vault refused it, or it could not be made
// (no token, the vault unreachable) - or that answered with something no wrapped DEK can be made
// of, or a wrapped DEK refused because it isn't one this wrapper wrote or its signature doesn't
// verify. The message names the operation, the key, and - for a refusal - Key Vault's error code
// and the HTTP status.
//
// It matches ErrKeyVault with errors.Is, and unwraps to the Azure SDK's own error, when there is
// one, so errors.As reaches an *azcore.ResponseError, an azidentity error, and so on.
type Error struct {
	// Op is the operation that failed: "wrap", "sign", "verify" or "unwrap".
	Op string

	// KeyID is the key it failed for: its identifier, with the version when it is known.
	KeyID string

	// Message describes the failure.
	Message string

	// Err is the Azure SDK's error, or nil when the failure was found here.
	Err error
}

func (e *Error) Error() string { return e.Message }

// Unwrap returns the Azure SDK's error, if any.
func (e *Error) Unwrap() error { return e.Err }

// Is reports whether target is ErrKeyVault.
func (e *Error) Is(target error) bool { return target == ErrKeyVault }

func keyVaultError(op string, key keyID, cause error, format string, args ...any) *Error {
	return &Error{Op: op, KeyID: key.String(), Message: fmt.Sprintf(format, args...), Err: cause}
}

// invalidArgument returns an error wrapping ErrInvalidArgument with a formatted reason.
func invalidArgument(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidArgument, fmt.Sprintf(format, args...))
}
