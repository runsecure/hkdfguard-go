// Package kmswrap holds what the key wrappers that call a cloud key service in place of the native
// library - keywrapping/azurekeyvault and keywrapping/googlekms - do alike around each call: refuse
// an ended context without calling, wrap only a copy of the key they own and zero it once the call
// returns, generate a DEK in this process, and zero the caller's result when an unwrap fails.
//
// Internal to this repository: its API changes with the modules that use it.
package kmswrap

import (
	"bytes"
	"context"
	"crypto/rand"

	"github.com/runsecure/hkdfguard-go"
)

// WrapFunc wraps key - a slice the wrapper owns, which the caller zeroes once it returns - writing
// the wrapped DEK into result and returning its length.
type WrapFunc func(ctx context.Context, key, result []byte) (int, error)

// UnwrapFunc reveals wrapped, writing the key into result and returning its length.
type UnwrapFunc func(ctx context.Context, wrapped, result []byte) (int, error)

// Service is a cloud key service's limits, and how a wrapper over it refuses an argument.
type Service struct {
	// Name is the service, as messages name it: "Cloud KMS", "Azure Key Vault".
	Name string

	// MaxPlaintextLength is the largest key the service wraps, in bytes.
	MaxPlaintextLength int

	// InvalidArgument makes the wrapper's argument error (one matching its ErrInvalidArgument).
	InvalidArgument func(format string, args ...any) error
}

// Wrap refuses an ended context, then a plaintext that isn't 1-MaxPlaintextLength bytes, and wraps
// a copy of plaintext with wrapOwned. plaintext is not modified - it is the caller's to zero.
//
// The copy is the wrapper's own, so it can be zeroed whatever the caller does with theirs
// meanwhile. The SDKs serialize the request inside the call, so it has been sent - or failed - once
// the call returns, and the copy is zeroed then.
func (s Service) Wrap(ctx context.Context, plaintext, result []byte, wrapOwned WrapFunc) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if len(plaintext) == 0 || len(plaintext) > s.MaxPlaintextLength {
		return 0, s.InvalidArgument("%s wraps 1-%d bytes; got %d.", s.Name, s.MaxPlaintextLength, len(plaintext))
	}
	buffer := bytes.Clone(plaintext)
	defer hkdfguard.Wipe(buffer)
	return wrapOwned(ctx, buffer, result)
}

// Reveal copies revealed - the key a service returned - into result. It fails with InvalidArgument
// when result is too small. Zeroing revealed is the caller's.
func (s Service) Reveal(revealed, result []byte) (int, error) {
	if len(revealed) > len(result) {
		return 0, s.InvalidArgument("The revealed key is %d bytes; result holds %d.", len(revealed), len(result))
	}
	return copy(result, revealed), nil
}

// GenerateAndWrap refuses an ended context, then generates a fresh length-byte DEK in this process
// and wraps it with wrapOwned. The DEK itself is never returned, and is zeroed once wrapped.
func GenerateAndWrap(ctx context.Context, length int, result []byte, wrapOwned WrapFunc) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	dek := make([]byte, length)
	defer hkdfguard.Wipe(dek)
	_, _ = rand.Read(dek) // never fails; it crashes the program first
	return wrapOwned(ctx, dek, result)
}

// Unwrap refuses an ended context, then reveals wrapped with unwrap. On any failure result is
// zeroed: whatever a failed call left in the DEK buffer is erased.
func Unwrap(ctx context.Context, wrapped, result []byte, unwrap UnwrapFunc) (n int, err error) {
	defer func() {
		if err != nil {
			hkdfguard.Wipe(result)
		}
	}()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return unwrap(ctx, wrapped, result)
}
