package configurationresolver

import (
	"context"
	"errors"

	"github.com/runsecure/hkdfguard-go"
)

// ProtectedCacheValueProvider is a ValueProvider over a hkdfguard.ProtectedReadOnlyCache, so the
// items in a template - "Password=${db-password}" - resolve from HkdfGuard's protected caches: a
// cache.Cache, a cache.Collection, a cache/filepersecret cache, an encryptedconfig.Reader, or a
// remote secret store's cache (AWS Secrets Manager, Azure Key Vault, Google Secret Manager,
// HashiCorp Vault). A template's key is the cache's name as it is, so a remote cache's
// "app-config#api-key" form works unchanged.
//
// Each value is decrypted straight into the resolver's destination when the cache's upper bound on
// its length fits there, and otherwise into a scratch buffer that is wiped once the value has been
// copied out. It is never a string: TryGetValue, the one member that returns one, fails with
// ErrStringValuesNotAllowed unless WithAllowStringValues is set. A resolver never calls it.
//
// Every lookup passes the caller's context to the cache, so a remote cache's fetch of a value it
// hasn't cached yet is bounded by it. Prefetch fetches a template's keys up front, so Resolve then
// reads only from memory. Safe for concurrent use.
type ProtectedCacheValueProvider struct {
	cache             hkdfguard.ProtectedReadOnlyCache
	allowStringValues bool
}

var (
	_ ValueProvider     = (*ProtectedCacheValueProvider)(nil)
	_ ByteValueProvider = (*ProtectedCacheValueProvider)(nil)
)

// NewProtectedCacheValueProvider returns a provider that reads values from cache. It fails when
// cache is nil.
func NewProtectedCacheValueProvider(cache hkdfguard.ProtectedReadOnlyCache) (*ProtectedCacheValueProvider, error) {
	if cache == nil {
		return nil, errors.New("configurationresolver: a cache is required")
	}
	return &ProtectedCacheValueProvider{cache: cache}, nil
}

// Cache is the cache values are read from.
func (p *ProtectedCacheValueProvider) Cache() hkdfguard.ProtectedReadOnlyCache { return p.cache }

// AllowStringValues reports whether TryGetValue may return a value as a string, which can't be
// wiped. False by default, when it fails with ErrStringValuesNotAllowed instead.
func (p *ProtectedCacheValueProvider) AllowStringValues() bool { return p.allowStringValues }

// WithAllowStringValues returns a copy of p with AllowStringValues set to allow.
func (p *ProtectedCacheValueProvider) WithAllowStringValues(allow bool) *ProtectedCacheValueProvider {
	copied := *p
	copied.allowStringValues = allow
	return &copied
}

// Prefetch fetches every key reader has read, so a later Resolve doesn't fetch. A key the cache
// doesn't have is skipped; Resolve reports it. A cache's error stops the prefetch and is returned.
func (p *ProtectedCacheValueProvider) Prefetch(ctx context.Context, reader KeyReader) error {
	if reader == nil {
		return errors.New("configurationresolver: a reader is required")
	}
	return p.PrefetchKeys(ctx, reader.Keys())
}

// PrefetchKeys fetches each of keys, one at a time, so a later Resolve doesn't fetch. A key listed
// twice is fetched once; a key the cache doesn't have is skipped. A cache's error stops the
// prefetch and is returned.
func (p *ProtectedCacheValueProvider) PrefetchKeys(ctx context.Context, keys []string) error {
	seen := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		if _, _, err := p.cache.MaxDecryptedLength(ctx, key); err != nil {
			return err
		}
	}
	return nil
}

// TryGetBytes decrypts key's value into destination.
func (p *ProtectedCacheValueProvider) TryGetBytes(ctx context.Context, key string, destination []byte) (int, ValueStatus, error) {
	maxLength, found, err := p.cache.MaxDecryptedLength(ctx, key)
	if err != nil || !found {
		return 0, NotFound, err
	}

	if maxLength <= len(destination) {
		written, err := p.cache.Decrypt(ctx, key, destination)
		if err != nil || written == 0 {
			return 0, NotFound, err
		}
		return written, Found, nil
	}

	// The bound is above the room left, but the value itself may still fit.
	plaintext := make([]byte, maxLength)
	defer hkdfguard.Wipe(plaintext)

	length, err := p.cache.Decrypt(ctx, key, plaintext)
	if err != nil || length == 0 {
		return 0, NotFound, err
	}
	if length > len(destination) {
		return 0, DestinationTooSmall, nil
	}
	return copy(destination, plaintext[:length]), Found, nil
}

// TryGetValue returns key's value as a string, when AllowStringValues is set; otherwise it fails
// with ErrStringValuesNotAllowed.
func (p *ProtectedCacheValueProvider) TryGetValue(ctx context.Context, key string) (string, ValueStatus, error) {
	if !p.allowStringValues {
		return "", NotFound, ErrStringValuesNotAllowed
	}
	return ValueProviderBase{ByteValueProvider: p}.TryGetValue(ctx, key)
}

// TryGetByteCount returns the cache's upper bound on key's value's length.
func (p *ProtectedCacheValueProvider) TryGetByteCount(ctx context.Context, key string) (int, bool, error) {
	return p.cache.MaxDecryptedLength(ctx, key)
}
