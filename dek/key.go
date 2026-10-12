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
	"sync/atomic"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/diagnostics"
)

// Key is a hkdfguard.DataEncryptionKey backed by a hkdfguard.CryptoProvider, which owns the key
// material - how it is revealed and refreshed - and performs the AEAD. Key sizes the output via the
// provider, trims it to exactly what was written, and records telemetry for every operation. It
// owns its provider: Close closes it, stopping any background refresh and zeroing its key.
type Key struct {
	provider hkdfguard.CryptoProvider
	closed   atomic.Bool
}

var _ hkdfguard.DataEncryptionKey = (*Key)(nil)

// NewKey returns a Key that owns provider.
func NewKey(provider hkdfguard.CryptoProvider) *Key {
	return &Key{provider: provider}
}

// Encrypt encrypts plaintext bound to aad (nil for none) and returns the ciphertext. plaintext is
// zeroed before Encrypt returns, whether or not it succeeds.
func (k *Key) Encrypt(ctx context.Context, plaintext, aad []byte) ([]byte, error) {
	telemetry := diagnostics.DataProtection
	ctx, span := telemetry.Start(ctx, diagnostics.SpanDataProtectionKeyWrappedKeyEncrypt)
	defer span.End()
	telemetry.LogSensitiveOperation(span, diagnostics.SpanDataProtectionKeyWrappedKeyEncrypt,
		diagnostics.AttrPlaintextLength.Int(len(plaintext)), diagnostics.AttrAADLength.Int(len(aad)))

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
// bytes written.
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
