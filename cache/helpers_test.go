package cache

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"log/slog"
	"sync"
	"testing"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/dek"
)

var bg = context.Background()

// recordingKey is a real AES-256-GCM hkdfguard.DataEncryptionKey that also records the AAD of
// every call, so tests can check which name each value is bound to.
type recordingKey struct {
	aead cipher.AEAD

	mu          sync.Mutex
	encryptAADs [][]byte
	decryptAADs [][]byte
}

func newRecordingKey(t *testing.T) *recordingKey {
	t.Helper()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	block, _ := aes.NewCipher(key)
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		t.Fatal(err)
	}
	return &recordingKey{aead: aead}
}

func (k *recordingKey) Encrypt(_ context.Context, plaintext, aad []byte) ([]byte, error) {
	defer hkdfguard.Wipe(plaintext)
	k.mu.Lock()
	k.encryptAADs = append(k.encryptAADs, bytes.Clone(aad))
	k.mu.Unlock()
	return k.aead.Seal(nil, nil, plaintext, aad), nil
}

func (k *recordingKey) Decrypt(_ context.Context, ciphertext, aad, result []byte) (int, error) {
	k.mu.Lock()
	k.decryptAADs = append(k.decryptAADs, bytes.Clone(aad))
	k.mu.Unlock()
	if len(ciphertext) < k.aead.Overhead() {
		return 0, hkdfguard.ErrAuthenticationFailed
	}
	if len(result) < len(ciphertext)-k.aead.Overhead() {
		return 0, hkdfguard.ErrInvalidConfigurationKey // any error: the result is too small
	}
	out, err := k.aead.Open(result[:0], nil, ciphertext, aad)
	if err != nil {
		return 0, hkdfguard.ErrAuthenticationFailed
	}
	return len(out), nil
}

// newRing returns a ring holding one fresh key at each version, the highest current.
func newRing(t *testing.T, versions ...int) (*dek.KeyRing, map[int]*recordingKey) {
	t.Helper()
	ring := dek.NewKeyRing(nil)
	keys := map[int]*recordingKey{}
	for _, v := range versions {
		keys[v] = newRecordingKey(t)
		if err := ring.Add(bg, v, keys[v]); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _ = ring.Close() })
	return ring, keys
}

func newCache(t *testing.T, opts ...Option) *Cache {
	t.Helper()
	ring, _ := newRing(t, 1)
	return New(ring, opts...)
}

// get decrypts name's value, sized by MaxDecryptedLength; "" and false when nothing is stored.
func get(t *testing.T, c hkdfguard.ProtectedReadOnlyCache, name string) (string, bool) {
	t.Helper()
	n, ok, err := c.MaxDecryptedLength(bg, name)
	if err != nil {
		t.Fatalf("MaxDecryptedLength(%q): %v", name, err)
	}
	if !ok {
		return "", false
	}
	result := make([]byte, n)
	written, err := c.Decrypt(bg, name, result)
	if err != nil {
		t.Fatalf("Decrypt(%q): %v", name, err)
	}
	return string(result[:written]), true
}

func mustAdd(t *testing.T, c *Cache, name, value string) {
	t.Helper()
	if err := c.Add(bg, name, []byte(value)); err != nil {
		t.Fatalf("Add(%q): %v", name, err)
	}
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

// fakeSource serves values from a map, counting fetches.
type fakeSource struct {
	mu      sync.Mutex
	values  map[string]string
	err     error
	fetches int
	served  [][]byte // every plaintext handed to the cache, to check it was zeroed
}

func (s *fakeSource) Fetch(_ context.Context, name string) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fetches++
	if s.err != nil {
		return nil, false, s.err
	}
	value, ok := s.values[name]
	if !ok {
		return nil, false, nil
	}
	plaintext := []byte(value)
	s.served = append(s.served, plaintext)
	return plaintext, true, nil
}

func (s *fakeSource) fetchCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fetches
}
