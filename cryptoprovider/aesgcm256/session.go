package aesgcm256

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/diagnostics"
	"go.opentelemetry.io/otel/trace"
)

const (
	// KeySize is the AES-256 key length, in bytes.
	KeySize = 32

	// NonceSize and TagSize are the random nonce prepended to, and the GCM tag appended to, every
	// ciphertext: [nonce | ciphertext | tag].
	NonceSize = 12
	TagSize   = 16

	// Overhead is how many bytes longer a ciphertext is than its plaintext.
	Overhead = NonceSize + TagSize
)

// ErrInvalidLength reports a buffer of the wrong size: a result too small for the output, a
// ciphertext too short to hold a nonce and tag, or a key that isn't KeySize bytes.
var ErrInvalidLength = errors.New("aesgcm256: invalid length")

// session is an AES-256-GCM cipher bound to one 32-byte key, held until it is closed - by a
// Provider until its next background refresh, or by a PipelineDataProtector for its whole life.
//
// Go's AES-GCM keeps no per-call state, so one cipher.AEAD serves every concurrent operation; the
// read lock only keeps close (which zeroes the key) from overlapping an operation. Go can't zero
// the AES key schedule the cipher derives from the key: it stays in the heap until collected.
type session struct {
	mu     sync.RWMutex
	closed bool
	key    []byte
	aead   cipher.AEAD
	budget *encryptionBudget
	logger *slog.Logger
}

// newSession takes ownership of key, which it zeroes on close.
func newSession(key []byte, budget *encryptionBudget, logger *slog.Logger) (*session, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("%w: an AES-256 key must be exactly %d bytes, got %d", ErrInvalidLength, KeySize, len(key))
	}
	if hkdfguard.IsZero(key) {
		return nil, errors.New("aesgcm256: an AES key must not be all zero")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, err
	}
	return &session{key: key, aead: aead, budget: budget, logger: logger}, nil
}

// tryEncrypt encrypts plaintext into result as [nonce | ciphertext | tag], unless the session is
// closed - then it reports ok == false having touched nothing (no encryption counted, plaintext
// intact), so a caller holding a session that was retired under it can retry on the current one.
// Once it starts, it zeroes plaintext on success and on every failure.
func (s *session) tryEncrypt(ctx context.Context, plaintext, aad, result []byte) (n int, ok bool, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return 0, false, nil
	}
	defer hkdfguard.Wipe(plaintext)

	telemetry := diagnostics.CryptoProviderAESGCM256
	ctx, span := telemetry.Start(ctx, diagnostics.SpanCryptoProviderAESGCM256Encrypt)
	defer span.End()
	telemetry.LogSensitiveOperation(span, diagnostics.SpanCryptoProviderAESGCM256Encrypt,
		diagnostics.AttrPlaintextLength.Int(len(plaintext)), diagnostics.AttrAADLength.Int(len(aad)))

	if len(result) < len(plaintext)+Overhead {
		err := fmt.Errorf("%w: the result buffer holds %d bytes; encrypting %d bytes needs %d", ErrInvalidLength, len(result), len(plaintext), len(plaintext)+Overhead)
		diagnostics.RecordError(span, err)
		return 0, true, err
	}

	warn, err := s.budget.consume()
	if err != nil {
		diagnostics.RecordError(span, err)
		return 0, true, err
	}
	if warn {
		count, limit := s.budget.count.Load(), s.budget.limit
		span.AddEvent(diagnostics.EventEncryptionBudgetWarning, trace.WithAttributes(
			diagnostics.AttrEncryptionCount.Int64(count), diagnostics.AttrEncryptionLimit.Int64(limit)))
		// A span event alone is lost without a tracer provider; the log is not.
		diagnostics.EncryptionBudgetWarning(ctx, s.logger, count, limit)
	}

	// result has room, so Seal writes into it rather than allocating.
	return len(s.aead.Seal(result[:0], nil, plaintext, aad)), true, nil
}

// tryDecrypt decrypts ciphertext into result, unless the session is closed - then it reports
// ok == false, having done nothing. On an authentication failure result is zeroed.
func (s *session) tryDecrypt(ctx context.Context, ciphertext, aad, result []byte) (n int, ok bool, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return 0, false, nil
	}

	telemetry := diagnostics.CryptoProviderAESGCM256
	_, span := telemetry.Start(ctx, diagnostics.SpanCryptoProviderAESGCM256Decrypt)
	defer span.End()
	telemetry.LogSensitiveOperation(span, diagnostics.SpanCryptoProviderAESGCM256Decrypt,
		diagnostics.AttrCiphertextLength.Int(len(ciphertext)), diagnostics.AttrAADLength.Int(len(aad)))

	if len(ciphertext) < Overhead {
		err := fmt.Errorf("%w: a ciphertext of %d bytes is shorter than the %d-byte nonce and tag", ErrInvalidLength, len(ciphertext), Overhead)
		diagnostics.RecordError(span, err)
		return 0, true, err
	}
	if plaintextLength := len(ciphertext) - Overhead; len(result) < plaintextLength {
		err := fmt.Errorf("%w: the result buffer holds %d bytes; this ciphertext decrypts to %d", ErrInvalidLength, len(result), plaintextLength)
		diagnostics.RecordError(span, err)
		return 0, true, err
	}

	// Open zeroes what it wrote if authentication fails.
	plaintext, err := s.aead.Open(result[:0], nil, ciphertext, aad)
	if err != nil {
		err = hkdfguard.ErrAuthenticationFailed
		diagnostics.RecordError(span, err)
		return 0, true, err
	}
	return len(plaintext), true, nil
}

// close zeroes the key and drops the cipher, waiting for any operation in progress to finish.
// Safe to call more than once.
func (s *session) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	hkdfguard.Wipe(s.key)
	s.aead = nil
}
