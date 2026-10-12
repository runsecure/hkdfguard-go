// Package hkdfguard holds the abstractions every HkdfGuard library is built against - the Go port
// of the .NET HkdfGuard.Abstractions library. It defines the interfaces implementations satisfy
// (KeyWrapper, CryptoProvider, DataEncryptionKey, KeyRing, ...), the shared rules every port
// applies identically (configuration purposes, service names), and the limits and defaults they
// share.
//
// Implementation packages (crypto providers, key wrappers, key rings) import this package and
// never each other, so any one of them can be swapped for another implementation of the same
// interface without touching the rest.
//
// Operations that may perform I/O or emit telemetry take a context.Context first, which carries
// cancellation and the parent span. Pure computations (allocation lengths) and accessors don't.
package hkdfguard

import "errors"

// Sentinel errors shared across implementations. Implementations wrap them with detail
// (fmt.Errorf("...: %w", ErrKeyNotFound)); callers test for them with errors.Is.
var (
	// ErrKeyNotFound reports that no key is registered for a requested key version.
	ErrKeyNotFound = errors.New("hkdfguard: no key is registered for this version")

	// ErrNoCurrentKey reports that a KeyRing has no key registered yet.
	ErrNoCurrentKey = errors.New("hkdfguard: no key has been registered")

	// ErrAlreadyExists reports that a ProtectedCache already holds a value under a name.
	ErrAlreadyExists = errors.New("hkdfguard: a value is already stored under this name")

	// ErrInvalidConfigurationKey reports a configuration key that is empty or not valid UTF-8.
	ErrInvalidConfigurationKey = errors.New("hkdfguard: invalid configuration key")

	// ErrInvalidServiceName reports a service name that breaks a ValidateServiceName rule.
	ErrInvalidServiceName = errors.New("hkdfguard: invalid service name")

	// ErrInvalidRefreshFailurePolicy reports a fail-closed policy with a limit below 1.
	ErrInvalidRefreshFailurePolicy = errors.New("hkdfguard: invalid refresh-failure policy")

	// ErrAuthenticationFailed reports ciphertext that failed AEAD authentication: it was altered,
	// or is being decrypted with a different key or Additional Authenticated Data than it was
	// encrypted with. Every CryptoProvider reports it, whatever its cipher.
	ErrAuthenticationFailed = errors.New("hkdfguard: message authentication failed")

	// ErrKeyAccessSuspended reports a CryptoProvider that has failed closed under its
	// RefreshFailurePolicy: its key is zeroed and every operation fails until a background
	// refresh succeeds again.
	ErrKeyAccessSuspended = errors.New("hkdfguard: key access is suspended")

	// ErrEncryptionLimitReached reports a key that has performed as many encryptions as its cipher
	// safely allows; it must be rotated. Decryption under it still works.
	ErrEncryptionLimitReached = errors.New("hkdfguard: the key's encryption limit has been reached")

	// ErrClosed reports an operation on a CryptoProvider or protector that has been closed.
	ErrClosed = errors.New("hkdfguard: closed")
)
