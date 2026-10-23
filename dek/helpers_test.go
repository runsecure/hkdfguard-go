package dek

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/runsecure/hkdfguard-go"
)

// testProvider is a real AES-256-GCM hkdfguard.CryptoProvider without any refresh machinery, so
// these tests exercise this package against working crypto without depending on a cipher module.
type testProvider struct {
	aead       cipher.AEAD
	overhead   int // extra bytes EncryptedAllocationLength over-allocates
	closeCount int
	closeErr   error
	mu         sync.Mutex
}

func newTestProvider(t *testing.T) *testProvider {
	t.Helper()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	block, _ := aes.NewCipher(key)
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		t.Fatal(err)
	}
	return &testProvider{aead: aead}
}

func (p *testProvider) Encrypt(_ context.Context, plaintext, aad, result []byte) (int, error) {
	defer hkdfguard.Wipe(plaintext)
	if p.isClosed() {
		return 0, hkdfguard.ErrClosed
	}
	return len(p.aead.Seal(result[:0], nil, plaintext, aad)), nil
}

func (p *testProvider) Decrypt(_ context.Context, ciphertext, aad, result []byte) (int, error) {
	if p.isClosed() {
		return 0, hkdfguard.ErrClosed
	}
	out, err := p.aead.Open(result[:0], nil, ciphertext, aad)
	if err != nil {
		return 0, hkdfguard.ErrAuthenticationFailed
	}
	return len(out), nil
}

func (p *testProvider) EncryptedAllocationLength(n int) int {
	return n + p.aead.Overhead() + p.overhead
}
func (p *testProvider) DecryptedAllocationLength(n int) int { return max(0, n-p.aead.Overhead()) }

func (p *testProvider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closeCount++
	return p.closeErr
}

func (p *testProvider) isClosed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closeCount > 0
}

func (p *testProvider) closes() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closeCount
}

func newTestKey(t *testing.T) (*Key, *testProvider) {
	t.Helper()
	provider := newTestProvider(t)
	return NewKey(provider), provider
}

// recordingFactory creates testProviders, recording what it was asked for.
type recordingFactory struct {
	t *testing.T

	mu         sync.Mutex
	created    []*testProvider
	wrapped    [][]byte
	expiries   []time.Duration
	policies   []hkdfguard.RefreshFailurePolicy
	ephemerals int
	failNext   error
	onCreate   func() // called inside CreateEphemeral, before it returns
}

func (f *recordingFactory) record(expiry time.Duration, policy hkdfguard.RefreshFailurePolicy) (hkdfguard.CryptoProvider, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.failNext; err != nil {
		f.failNext = nil
		return nil, err
	}
	provider := newTestProvider(f.t)
	f.created = append(f.created, provider)
	f.expiries = append(f.expiries, expiry)
	f.policies = append(f.policies, policy)
	return provider, nil
}

func (f *recordingFactory) Create(ctx context.Context, _ hkdfguard.KeyWrapper, wrapped []byte, expiry time.Duration, policy hkdfguard.RefreshFailurePolicy) (hkdfguard.CryptoProvider, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.wrapped = append(f.wrapped, wrapped)
	f.mu.Unlock()
	return f.record(expiry, policy)
}

func (f *recordingFactory) CreateEphemeral(ctx context.Context, _ hkdfguard.KeyWrapper, expiry time.Duration, policy hkdfguard.RefreshFailurePolicy) (hkdfguard.CryptoProvider, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.ephemerals++
	onCreate := f.onCreate
	f.mu.Unlock()
	if onCreate != nil {
		onCreate()
	}
	return f.record(expiry, policy)
}

func (f *recordingFactory) providers() []*testProvider {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*testProvider(nil), f.created...)
}

func (f *recordingFactory) fail(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failNext = err
}

// nopKeyWrapper satisfies Config.KeyWrapper; the recording factory never calls it.
type nopKeyWrapper struct{}

func (nopKeyWrapper) Wrap(context.Context, []byte, []byte) (int, error) {
	return 0, errors.New("unused")
}
func (nopKeyWrapper) Unwrap(context.Context, []byte, []byte) (int, error) {
	return 0, errors.New("unused")
}
func (nopKeyWrapper) GenerateAndWrap(context.Context, []byte) (int, error) {
	return 0, errors.New("unused")
}

// ReadKeyFile reads the file as it is: test key files are written by the test itself, and a real
// key wrapper's trust checks are its own tests' concern.
func (nopKeyWrapper) ReadKeyFile(_ context.Context, path string) ([]byte, error) {
	return os.ReadFile(path)
}

// capturingHandler records slog records.
type capturingHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *capturingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *capturingHandler) WithAttrs([]slog.Attr) slog.Handler       { return h }
func (h *capturingHandler) WithGroup(string) slog.Handler            { return h }
func (h *capturingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r)
	return nil
}

func (h *capturingHandler) withEventID(id int64) []slog.Record {
	h.mu.Lock()
	defer h.mu.Unlock()
	var matched []slog.Record
	for _, r := range h.records {
		r.Attrs(func(a slog.Attr) bool {
			if a.Key == "event.id" && a.Value.Int64() == id {
				matched = append(matched, r)
				return false
			}
			return true
		})
	}
	return matched
}

func newCapturingLogger() (*slog.Logger, *capturingHandler) {
	h := &capturingHandler{}
	return slog.New(h), h
}

func protect(t *testing.T, p hkdfguard.DataProtector, plaintext string) string {
	t.Helper()
	formatted, err := p.Encrypt(context.Background(), []byte(plaintext))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	return formatted
}

func unprotect(p hkdfguard.DataProtector, formatted string) (string, error) {
	n, err := p.MaxDecryptedLength(context.Background(), formatted)
	if err != nil {
		return "", err
	}
	result := make([]byte, n)
	n, err = p.Decrypt(context.Background(), formatted, result)
	return string(result[:n]), err
}
