package aesgcm256

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/diagnostics"
)

// PipelineDataProtector is the AES-256-GCM hkdfguard.PipelineDataProtector: it generates a random
// 32-byte key in memory and uses it for its whole life - no key wrapper, no KeyRing, no refresh.
// Each Encrypt/Decrypt binds the secret identifier as Additional Authenticated Data (via
// hkdfguard.ConfigurationAAD); output is formatted by the supplied hkdfguard.EncryptedFormatProvider
// and stamped with the key version. Close zeroes the key and its base64 form; every later
// operation fails with hkdfguard.ErrClosed. Safe for concurrent use.
type PipelineDataProtector struct {
	formatProvider hkdfguard.EncryptedFormatProvider
	keyVersion     int
	key            []byte
	budget         *encryptionBudget
	session        *session

	mu       sync.Mutex
	base64   []byte
	isClosed bool
}

var _ hkdfguard.PipelineDataProtector = (*PipelineDataProtector)(nil)

// NewPipelineDataProtector returns a protector with a fresh random key that stamps every value
// with keyVersion - the version this key will be registered under once wrapped.
func NewPipelineDataProtector(formatProvider hkdfguard.EncryptedFormatProvider, keyVersion int) (*PipelineDataProtector, error) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return newPipelineDataProtector(formatProvider, keyVersion, key, defaultBudget())
}

// newPipelineDataProtector takes ownership of key, which it zeroes on Close.
func newPipelineDataProtector(formatProvider hkdfguard.EncryptedFormatProvider, keyVersion int, key []byte, budget *encryptionBudget) (*PipelineDataProtector, error) {
	if formatProvider == nil {
		hkdfguard.Wipe(key)
		return nil, errors.New("aesgcm256: a format provider is required")
	}
	s, err := newSession(key, budget, nil)
	if err != nil {
		hkdfguard.Wipe(key)
		return nil, err
	}
	return &PipelineDataProtector{formatProvider: formatProvider, keyVersion: keyVersion, key: key, budget: budget, session: s}, nil
}

// KeyVersion is the version stamped on every value.
func (p *PipelineDataProtector) KeyVersion() int { return p.keyVersion }

// EncryptionCount is the number of encryptions performed under this key so far - see
// MaxEncryptionsPerKey.
func (p *PipelineDataProtector) EncryptionCount() int64 { return p.budget.count.Load() }

// KeyBase64 returns the key, base64-encoded, for handing to the native platform's wrap process at
// the end of the pipeline. It is encoded once, into a buffer this protector owns and zeroes on
// Close, and the same slice is returned on every call; nil after Close. Never convert it to a
// string, and pass it to the wrap tool on standard input, never as an argument or environment
// variable.
func (p *PipelineDataProtector) KeyBase64() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.isClosed {
		return nil
	}
	if p.base64 == nil {
		p.base64 = make([]byte, base64.StdEncoding.EncodedLen(len(p.key)))
		base64.StdEncoding.Encode(p.base64, p.key)
	}
	return p.base64
}

// Encrypt encrypts plaintext bound to secretIdentifier (the configuration key the value will be
// stored under) and formats the result. plaintext is not zeroed: the caller owns it.
func (p *PipelineDataProtector) Encrypt(ctx context.Context, plaintext []byte, secretIdentifier string) (string, error) {
	telemetry := diagnostics.DataProtection
	ctx, span := telemetry.Start(ctx, diagnostics.SpanDataProtectionProtectorEncrypt)
	defer span.End()
	telemetry.LogSensitiveOperation(span, diagnostics.SpanDataProtectionProtectorEncrypt,
		diagnostics.AttrName.String(secretIdentifier), diagnostics.AttrPlaintextLength.Int(len(plaintext)))

	formatted, err := p.encrypt(ctx, plaintext, secretIdentifier)
	if err != nil {
		diagnostics.RecordError(span, err)
	}
	return formatted, err
}

func (p *PipelineDataProtector) encrypt(ctx context.Context, plaintext []byte, secretIdentifier string) (string, error) {
	aad, err := hkdfguard.ConfigurationAAD(secretIdentifier)
	if err != nil {
		return "", err
	}

	// The session zeroes what it encrypts; the caller's plaintext is theirs to keep.
	scratch := make([]byte, len(plaintext))
	copy(scratch, plaintext)
	defer hkdfguard.Wipe(scratch)

	ciphertext := make([]byte, len(plaintext)+Overhead)
	n, ok, err := p.session.tryEncrypt(ctx, scratch, aad, ciphertext)
	if !ok {
		return "", hkdfguard.ErrClosed
	}
	if err != nil {
		return "", err
	}
	return p.formatProvider.Format(ctx, hkdfguard.KeyTrackingValue{KeyVersion: p.keyVersion, Value: ciphertext[:n]})
}

// Decrypt parses encrypted and decrypts it into result, verifying it was encrypted for
// secretIdentifier, and returns the number of bytes written. A value stamped with another key
// version fails with hkdfguard.ErrKeyNotFound; one encrypted for another identifier with
// hkdfguard.ErrAuthenticationFailed.
func (p *PipelineDataProtector) Decrypt(ctx context.Context, encrypted, secretIdentifier string, result []byte) (int, error) {
	telemetry := diagnostics.DataProtection
	ctx, span := telemetry.Start(ctx, diagnostics.SpanDataProtectionProtectorDecrypt)
	defer span.End()
	telemetry.LogSensitiveOperation(span, diagnostics.SpanDataProtectionProtectorDecrypt,
		diagnostics.AttrName.String(secretIdentifier), diagnostics.AttrEncryptedLength.Int(len(encrypted)))

	n, err := p.decrypt(ctx, encrypted, secretIdentifier, result)
	if err != nil {
		diagnostics.RecordError(span, err)
	}
	return n, err
}

func (p *PipelineDataProtector) decrypt(ctx context.Context, encrypted, secretIdentifier string, result []byte) (int, error) {
	aad, err := hkdfguard.ConfigurationAAD(secretIdentifier)
	if err != nil {
		return 0, err
	}
	value, err := p.formatProvider.Parse(ctx, encrypted)
	if err != nil {
		return 0, err
	}
	if value.KeyVersion != p.keyVersion {
		return 0, fmt.Errorf("%w: version %d", hkdfguard.ErrKeyNotFound, value.KeyVersion)
	}

	n, ok, err := p.session.tryDecrypt(ctx, value.Value, aad, result)
	if !ok {
		return 0, hkdfguard.ErrClosed
	}
	return n, err
}

// MaxDecryptedLength is an upper bound on how many bytes Decrypt will write for encrypted.
func (p *PipelineDataProtector) MaxDecryptedLength(ctx context.Context, encrypted string) (int, error) {
	return p.formatProvider.MaxDecryptedLength(ctx, encrypted)
}

// Close zeroes the key and its base64 form. Safe to call more than once.
func (p *PipelineDataProtector) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.isClosed {
		return nil
	}
	p.isClosed = true
	p.session.close() // zeroes p.key
	hkdfguard.Wipe(p.base64)
	return nil
}
