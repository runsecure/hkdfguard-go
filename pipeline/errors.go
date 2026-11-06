package pipeline

import (
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrInvalidArgument reports something New or WriteProtectedSecretFiles refuses before anything
	// is read or written: no protector or store, no secret names, a name the store can't hold (with
	// a key), one whose file name isn't one cache/filepersecret can read, two with the same file
	// name in any case, a default key that isn't one, or an empty folder path.
	ErrInvalidArgument = errors.New("pipeline: invalid argument")

	// ErrSecretNotFound matches the *MissingSecretsError PullSecrets returns when a secret doesn't
	// exist, or has no such key, or its value there is empty or isn't a value - the .NET
	// KeyNotFoundException.
	ErrSecretNotFound = errors.New("pipeline: the secret store holds no value for a secret")

	// ErrInvalidSecretData reports a secret, or a response holding one, that can't be protected: a
	// value that isn't UTF-8 text (the protector encrypts text), a JSON object holding a key more
	// than once, a response body that isn't a JSON object or is MaxBodyLength bytes or more, or one
	// holding more than one value for a secret. The message never quotes the data - the .NET
	// InvalidDataException.
	ErrInvalidSecretData = errors.New("pipeline: invalid secret data")

	// ErrNotPulled reports WriteProtectedSecretFiles called before a pull has completed - the .NET
	// InvalidOperationException.
	ErrNotPulled = errors.New("pipeline: no secrets have been pulled: call PullSecrets first")
)

// MissingSecretsError reports every secret name PullSecrets found no value for, once every other
// secret has been kept. It matches ErrSecretNotFound with errors.Is.
type MissingSecretsError struct {
	// SecretNames are the names as they were given, key and all, in the order the writer read them.
	SecretNames []string
}

func (e *MissingSecretsError) Error() string {
	return "pipeline: the secret store holds no value for: " + strings.Join(e.SecretNames, ", ")
}

// Is reports whether target is ErrSecretNotFound.
func (e *MissingSecretsError) Is(target error) bool { return target == ErrSecretNotFound }

func invalidArgument(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidArgument, fmt.Sprintf(format, args...))
}

func invalidData(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidSecretData, fmt.Sprintf(format, args...))
}
