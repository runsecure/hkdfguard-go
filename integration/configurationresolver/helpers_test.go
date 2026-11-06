package configurationresolver

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"slices"
	"sync"
	"testing"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/cache"
	"github.com/runsecure/hkdfguard-go/dek"
)

var bg = context.Background()

// gcmKey is a real AES-256-GCM hkdfguard.DataEncryptionKey, so values cached in these tests are
// encrypted and authenticated against their names as in production.
type gcmKey struct{ aead cipher.AEAD }

func (k gcmKey) Encrypt(_ context.Context, plaintext, aad []byte) ([]byte, error) {
	defer hkdfguard.Wipe(plaintext)
	return k.aead.Seal(nil, nil, plaintext, aad), nil
}

func (k gcmKey) Decrypt(_ context.Context, ciphertext, aad, result []byte) (int, error) {
	if len(ciphertext) < k.aead.Overhead() {
		return 0, hkdfguard.ErrAuthenticationFailed
	}
	if len(result) < len(ciphertext)-k.aead.Overhead() {
		return 0, errors.New("test key: the result is too small")
	}
	out, err := k.aead.Open(result[:0], nil, ciphertext, aad)
	if err != nil {
		return 0, hkdfguard.ErrAuthenticationFailed
	}
	return len(out), nil
}

// newRing returns a ring holding one fresh AES-256-GCM key, as version 1, its current version.
func newRing(t *testing.T) *dek.KeyRing {
	t.Helper()
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	block, err := aes.NewCipher(secret)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		t.Fatal(err)
	}
	ring := dek.NewKeyRing(nil)
	if err := ring.Add(bg, 1, gcmKey{aead: aead}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ring.Close() })
	return ring
}

// newCache returns a cache.Cache holding namesAndValues, a name then its value.
func newCache(t *testing.T, namesAndValues ...string) *cache.Cache {
	t.Helper()
	c := cache.New(newRing(t))
	for i := 0; i < len(namesAndValues); i += 2 {
		if err := c.Add(bg, namesAndValues[i], []byte(namesAndValues[i+1])); err != nil {
			t.Fatal(err)
		}
	}
	return c
}

// decryptString sizes a buffer with MaxDecryptedLength, as a caller would, and decrypts name.
func decryptString(t *testing.T, c hkdfguard.ProtectedReadOnlyCache, name string) string {
	t.Helper()
	maxLength, ok, err := c.MaxDecryptedLength(bg, name)
	if err != nil || !ok {
		t.Fatalf("MaxDecryptedLength(%q) = %d, %v, %v", name, maxLength, ok, err)
	}
	result := make([]byte, maxLength)
	n, err := c.Decrypt(bg, name, result)
	if err != nil {
		t.Fatalf("Decrypt(%q): %v", name, err)
	}
	return string(result[:n])
}

// plainSource is a hkdfguard.ProtectedReadOnlyCache over plain strings, names matched exactly,
// that counts every lookup by name and can run a callback the first time it decrypts a name. Its
// bound is the value's length. A real cache never holds plaintext like this.
type plainSource struct {
	mu            sync.Mutex
	values        map[string]string
	decrypts      map[string]int
	lengthLookups map[string]int
	hookName      string
	hook          func()
}

func newPlainSource(namesAndValues ...string) *plainSource {
	s := &plainSource{values: map[string]string{}, decrypts: map[string]int{}, lengthLookups: map[string]int{}}
	for i := 0; i < len(namesAndValues); i += 2 {
		s.values[namesAndValues[i]] = namesAndValues[i+1]
	}
	return s
}

func (s *plainSource) set(name, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.values[name] = value
}

// onFirstDecrypt runs action, once, the first time name is decrypted - before its value is read.
func (s *plainSource) onFirstDecrypt(name string, action func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hookName, s.hook = name, action
}

func (s *plainSource) decryptCount(name string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.decrypts[name]
}

func (s *plainSource) lengthLookupCount(name string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lengthLookups[name]
}

func (s *plainSource) Decrypt(_ context.Context, name string, result []byte) (int, error) {
	s.mu.Lock()
	s.decrypts[name]++
	var hook func()
	if s.hook != nil && s.hookName == name {
		hook, s.hook = s.hook, nil
	}
	s.mu.Unlock()
	if hook != nil {
		hook()
	}

	s.mu.Lock()
	value, ok := s.values[name]
	s.mu.Unlock()
	if !ok {
		return 0, nil
	}
	if len(value) > len(result) {
		return 0, errors.New("plain source: the result is too small")
	}
	return copy(result, value), nil
}

func (s *plainSource) MaxDecryptedLength(_ context.Context, name string) (int, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lengthLookups[name]++
	value, ok := s.values[name]
	return len(value), ok, nil
}

// failingSource fails every lookup with err, as a remote store that refuses access does.
type failingSource struct{ err error }

func (s failingSource) Decrypt(context.Context, string, []byte) (int, error) { return 0, s.err }

func (s failingSource) MaxDecryptedLength(context.Context, string) (int, bool, error) {
	return 0, false, s.err
}

// testSecretStore is a cache.SecretStore over plain values, for a real cache.RemoteCache: it
// records every fetch, and hands over a value holding a JSON object with its keys too.
type testSecretStore struct {
	mu      sync.Mutex
	values  map[string]string
	fetches []string
}

func (s *testSecretStore) IsValidName(string) bool { return true }

func (s *testSecretStore) Fetch(ctx context.Context, name string, sink *cache.SecretSink) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	s.fetches = append(s.fetches, name)
	value, ok := s.values[name]
	s.mu.Unlock()
	if !ok {
		return nil
	}
	return sink.SetBytesWithJSONKeys([]byte(value))
}

func (s *testSecretStore) fetched() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.fetches)
}

// newRemote returns a cache.RemoteCache, matching names exactly, over a testSecretStore holding
// namesAndValues.
func newRemote(t *testing.T, namesAndValues ...string) (*cache.RemoteCache, *testSecretStore) {
	t.Helper()
	store := &testSecretStore{values: map[string]string{}}
	for i := 0; i < len(namesAndValues); i += 2 {
		store.values[namesAndValues[i]] = namesAndValues[i+1]
	}
	remote, err := cache.NewRemote(newRing(t), store, cache.RemoteOptions{Matching: cache.Exact})
	if err != nil {
		t.Fatal(err)
	}
	return remote, store
}

// settingsProvider is a ValueProvider over plain strings, as an application's provider of
// settings that aren't secret would be.
type settingsProvider map[string]string

func newSettingsProvider(namesAndValues ...string) ValueProviderBase {
	values := settingsProvider{}
	for i := 0; i < len(namesAndValues); i += 2 {
		values[namesAndValues[i]] = namesAndValues[i+1]
	}
	return ValueProviderBase{ByteValueProvider: values}
}

func (s settingsProvider) TryGetBytes(_ context.Context, key string, destination []byte) (int, ValueStatus, error) {
	value, ok := s[key]
	if !ok {
		return 0, NotFound, nil
	}
	if len(value) > len(destination) {
		return 0, DestinationTooSmall, nil
	}
	return copy(destination, value), Found, nil
}

func (s settingsProvider) TryGetByteCount(_ context.Context, key string) (int, bool, error) {
	value, ok := s[key]
	return len(value), ok, nil
}

// templateResolver returns a resolver for template's items over providers, with the default token.
func templateResolver(t *testing.T, template string, providers ...ValueProvider) *ConfigurationItemResolver {
	t.Helper()
	token := NewDefaultToken()
	reader, err := NewConfigurationItemReader(token)
	if err != nil {
		t.Fatal(err)
	}
	reader.ReadKeysString(template)
	resolver, err := NewConfigurationItemResolver(token, reader, providers...)
	if err != nil {
		t.Fatal(err)
	}
	return resolver
}

// cacheProvider returns a ProtectedCacheValueProvider over c.
func cacheProvider(t *testing.T, c hkdfguard.ProtectedReadOnlyCache) *ProtectedCacheValueProvider {
	t.Helper()
	provider, err := NewProtectedCacheValueProvider(c)
	if err != nil {
		t.Fatal(err)
	}
	return provider
}
