package hkdfguard

import (
	"context"
	"fmt"
	"io"
	"time"
)

// CryptoProvider owns one revealed DEK - how it is revealed, refreshed and eventually zeroed - and
// performs the AEAD encrypt/decrypt with it. Close zeroes the key and stops any background
// refresh.
//
// Implementations must zero plaintext in every Encrypt, before returning and on every failure path
// - including when the key is unavailable (suspended or closed) and the call fails before any
// encryption happens. DataEncryptionKey promises its callers exactly this and relies on the
// provider to keep it. Decrypt never modifies its ciphertext.
//
// A nil aad means no Additional Authenticated Data; for AEAD ciphers that is identical to an
// empty one.
type CryptoProvider interface {
	io.Closer

	// Encrypt encrypts plaintext under this provider's key, bound to aad, writing the ciphertext
	// into result and returning the number of bytes written. plaintext is zeroed before this
	// returns, whether or not it succeeds.
	Encrypt(ctx context.Context, plaintext, aad, result []byte) (int, error)

	// Decrypt decrypts and authenticates ciphertext encrypted with the same aad, writing the
	// plaintext into result and returning the number of bytes written.
	Decrypt(ctx context.Context, ciphertext, aad, result []byte) (int, error)

	// EncryptedAllocationLength returns how many bytes result must hold to encrypt a plaintext of
	// plaintextLength bytes.
	EncryptedAllocationLength(plaintextLength int) int

	// DecryptedAllocationLength returns how many bytes result must hold to decrypt a ciphertext of
	// ciphertextLength bytes; never negative.
	DecryptedAllocationLength(ciphertextLength int) int
}

// CryptoProviderFactory mints CryptoProviders for a KeyRing. Creating a provider reveals its first
// key through the KeyWrapper, which for a network-backed key wrapper is a remote call, so ctx
// cancels it. Every provider then refreshes its revealed key every expiry (1s to 300s), applying
// policy when refreshes fail.
type CryptoProviderFactory interface {
	// Create builds a provider for an existing wrapped DEK (e.g. a key file's bytes), revealed
	// through wrapper. The provider owns wrapped from here on and zeroes it when it's closed.
	Create(ctx context.Context, wrapper KeyWrapper, wrapped []byte, expiry time.Duration, policy RefreshFailurePolicy) (CryptoProvider, error)

	// CreateEphemeral generates and wraps a fresh DEK through wrapper (KeyWrapper.GenerateAndWrap),
	// then builds a provider that reveals it.
	CreateEphemeral(ctx context.Context, wrapper KeyWrapper, expiry time.Duration, policy RefreshFailurePolicy) (CryptoProvider, error)
}

// DefaultMaxRefreshFailures is the consecutive failed refreshes tolerated before a provider fails
// closed, unless configured otherwise.
const DefaultMaxRefreshFailures = 3

// MaxAllowedRefreshFailures is the largest fail-closed limit accepted. 100 failures at the longest,
// 300-second refresh interval is about 8 h 20 min before a revoked KEK suspends key access; a larger
// value would quietly turn fail-closed into fail-open. To fail open, say so explicitly with FailOpen.
const MaxAllowedRefreshFailures = 100

// RefreshFailurePolicy says what a CryptoProvider does when re-revealing its key through the KEK
// keeps failing. Failing closed after n consecutive failures zeroes the key and refuses every
// operation until a refresh succeeds, so revoking the KEK reaches a running process; failing open
// keeps serving on the last good key no matter how many refreshes fail.
//
// The zero value fails closed after DefaultMaxRefreshFailures, so a policy left unset is the safe
// one. Failing open must be chosen explicitly with FailOpen.
type RefreshFailurePolicy struct {
	maxFailures int
	failOpen    bool
	set         bool
}

// FailClosedAfter returns a policy that fails closed once maxFailures consecutive refreshes have
// failed. maxFailures must be 1 to MaxAllowedRefreshFailures; Validate reports it otherwise.
func FailClosedAfter(maxFailures int) RefreshFailurePolicy {
	return RefreshFailurePolicy{maxFailures: maxFailures, set: true}
}

// FailOpen returns a policy that keeps serving on the last good key however many refreshes fail.
func FailOpen() RefreshFailurePolicy {
	return RefreshFailurePolicy{failOpen: true, set: true}
}

// MaxFailures returns the consecutive failed refreshes tolerated before failing closed, and false
// when the policy fails open.
func (p RefreshFailurePolicy) MaxFailures() (int, bool) {
	switch {
	case p.failOpen:
		return 0, false
	case !p.set:
		return DefaultMaxRefreshFailures, true
	default:
		return p.maxFailures, true
	}
}

// Validate reports a fail-closed policy whose limit is not 1 to MaxAllowedRefreshFailures.
func (p RefreshFailurePolicy) Validate() error {
	if limit, failsClosed := p.MaxFailures(); failsClosed && (limit < 1 || limit > MaxAllowedRefreshFailures) {
		return fmt.Errorf("%w: MaxRefreshFailures must be between 1 and %d, got %d", ErrInvalidRefreshFailurePolicy, MaxAllowedRefreshFailures, limit)
	}
	return nil
}

// String describes the policy for logs - e.g. diagnostics.KeyRefreshFailed's policy argument.
func (p RefreshFailurePolicy) String() string {
	if limit, failsClosed := p.MaxFailures(); failsClosed {
		return fmt.Sprintf("fail closed after %d consecutive failures", limit)
	}
	return "fail open (the last good key stays in use)"
}
