// Package dek is the data-encryption-key layer every HkdfGuard store sits on - the Go port of the
// .NET HkdfGuard.DataEncryptionKey library: Key (one DEK over a CryptoProvider), KeyRing (keys by
// version, with optional ephemeral-key rotation), its DataProtectors, DefaultFormatProvider (the
// enc::v<version>::<base64> wire format), and Build, which assembles a KeyRing from key files and
// ephemeral keys.
//
// It depends only on the hkdfguard interfaces: the cipher (a hkdfguard.CryptoProviderFactory) and
// the KEK (a hkdfguard.KeyWrapper) are supplied by the caller, so either can be swapped without
// touching this package.
package dek

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/diagnostics"
)

// EncryptionDeadline is a wall-clock point after which a Key stops encrypting, and an earlier one
// from which that is announced. Decryption is never limited. Build gives every key-file key one,
// from the file's age, so a key file that is never rotated stops encrypting rather than encrypting
// without bound: the per-process encryption budget can't see earlier runs of the process.
type EncryptionDeadline struct {
	// WarnAt is when OnWarning is called, once.
	WarnAt time.Time

	// RefuseAt is when Encrypt starts failing with hkdfguard.ErrEncryptionLimitReached.
	RefuseAt time.Time

	// Reason is the text the hkdfguard.ErrEncryptionLimitReached error carries.
	Reason string

	// OnWarning, when set, is called once, the first time the deadline is checked at or after
	// WarnAt but before RefuseAt.
	OnWarning func()

	// OnExpired, when set, is called once, the first time the deadline is checked at or after
	// RefuseAt.
	OnExpired func()
}

// Key is a hkdfguard.DataEncryptionKey backed by a hkdfguard.CryptoProvider, which owns the key
// material - how it is revealed and refreshed - and performs the AEAD. Key sizes the output via the
// provider, trims it to exactly what was written, and records telemetry for every operation. It
// owns its provider: Close closes it, stopping any background refresh and zeroing its key.
type Key struct {
	provider hkdfguard.CryptoProvider
	closed   atomic.Bool

	deadline *EncryptionDeadline
	warned   atomic.Bool
	expired  atomic.Bool
	now      func() time.Time // test hook: the clock Encrypt checks the deadline against; time.Now when nil
}

var _ hkdfguard.DataEncryptionKey = (*Key)(nil)

// NewKey returns a Key that owns provider.
func NewKey(provider hkdfguard.CryptoProvider) *Key {
	return &Key{provider: provider}
}

// NewKeyWithDeadline returns a Key that owns provider and stops encrypting at deadline.RefuseAt.
func NewKeyWithDeadline(provider hkdfguard.CryptoProvider, deadline EncryptionDeadline) *Key {
	return &Key{provider: provider, deadline: &deadline}
}

// Deadline returns when k stops encrypting, and false when it encrypts without a time limit.
func (k *Key) Deadline() (EncryptionDeadline, bool) {
	if k.deadline == nil {
		return EncryptionDeadline{}, false
	}
	return *k.deadline, true
}

// CheckDeadline checks k's deadline against now, announcing a warning or expiry the first time
// each is reached, and reports whether k has stopped encrypting. Each callback is called at most
// once, even under concurrent calls, and one that panics is ignored, so a faulty logger never
// decides whether a value is encrypted. Build also calls it, so a current key file nearing or past
// its age is reported at startup.
func (k *Key) CheckDeadline(now time.Time) bool {
	deadline := k.deadline
	if deadline == nil {
		return false
	}
	if !now.Before(deadline.RefuseAt) {
		if !k.expired.Swap(true) {
			k.warned.Store(true) // a skipped warning is never announced later
			callIgnoringPanics(deadline.OnExpired)
		}
		return true
	}
	if !now.Before(deadline.WarnAt) && k.warned.CompareAndSwap(false, true) {
		callIgnoringPanics(deadline.OnWarning)
	}
	return false
}

func (k *Key) clock() time.Time {
	if k.now != nil {
		return k.now()
	}
	return time.Now()
}

func callIgnoringPanics(callback func()) {
	if callback == nil {
		return
	}
	defer func() { _ = recover() }()
	callback()
}

// Encrypt encrypts plaintext bound to aad (nil for none) and returns the ciphertext. plaintext is
// zeroed before Encrypt returns, whether or not it succeeds. Once k has passed its deadline, it
// fails with hkdfguard.ErrEncryptionLimitReached: rotate the key; decryption still works.
func (k *Key) Encrypt(ctx context.Context, plaintext, aad []byte) ([]byte, error) {
	telemetry := diagnostics.DataProtection
	ctx, span := telemetry.Start(ctx, diagnostics.SpanDataProtectionKeyWrappedKeyEncrypt)
	defer span.End()
	telemetry.LogSensitiveOperation(span, diagnostics.SpanDataProtectionKeyWrappedKeyEncrypt,
		diagnostics.AttrPlaintextLength.Int(len(plaintext)), diagnostics.AttrAADLength.Int(len(aad)))

	if k.deadline != nil && k.CheckDeadline(k.clock()) {
		hkdfguard.Wipe(plaintext) // the provider never sees it, so honor the contract here
		err := fmt.Errorf("%w: %s", hkdfguard.ErrEncryptionLimitReached, k.deadline.Reason)
		diagnostics.RecordError(span, err)
		return nil, err
	}
	buffer := make([]byte, k.provider.EncryptedAllocationLength(len(plaintext)))
	n, err := k.provider.Encrypt(ctx, plaintext, aad, buffer)
	if err != nil {
		diagnostics.RecordError(span, err)
		return nil, err
	}
	// Providers that size exactly (e.g. AES-GCM) need no trim; others may over-allocate.
	return buffer[:n:n], nil
}

// Decrypt decrypts ciphertext encrypted with the same aad into result and returns the number of
// bytes written. It is never limited by the deadline.
func (k *Key) Decrypt(ctx context.Context, ciphertext, aad, result []byte) (int, error) {
	telemetry := diagnostics.DataProtection
	ctx, span := telemetry.Start(ctx, diagnostics.SpanDataProtectionKeyWrappedKeyDecrypt)
	defer span.End()
	telemetry.LogSensitiveOperation(span, diagnostics.SpanDataProtectionKeyWrappedKeyDecrypt,
		diagnostics.AttrCiphertextLength.Int(len(ciphertext)), diagnostics.AttrAADLength.Int(len(aad)))

	n, err := k.provider.Decrypt(ctx, ciphertext, aad, result)
	if err != nil {
		diagnostics.RecordError(span, err)
	}
	return n, err
}

// Close closes the provider. Safe to call more than once; only the first call reaches it.
func (k *Key) Close() error {
	if k.closed.Swap(true) {
		return nil
	}
	return k.provider.Close()
}
