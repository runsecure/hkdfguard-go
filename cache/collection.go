package cache

import (
	"context"
	"sync"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/diagnostics"
)

// Collection puts several read-only caches behind one lookup: Decrypt and MaxDecryptedLength ask
// each source in the order it was added and return the first match. It never stores a value of its
// own - Add registers a source - so writing stays with whichever sources support it (a Cache can
// be one of them). Safe for concurrent use.
type Collection struct {
	mu      sync.RWMutex
	sources []hkdfguard.ProtectedReadOnlyCache
}

var _ hkdfguard.ProtectedReadOnlyCache = (*Collection)(nil)

// NewCollection returns a Collection over sources, checked in order.
func NewCollection(sources ...hkdfguard.ProtectedReadOnlyCache) *Collection {
	return &Collection{sources: append([]hkdfguard.ProtectedReadOnlyCache(nil), sources...)}
}

// Add registers source, checked after every source already added, and returns c for chaining.
func (c *Collection) Add(source hkdfguard.ProtectedReadOnlyCache) *Collection {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sources = append(c.sources, source)
	return c
}

func (c *Collection) snapshot() []hkdfguard.ProtectedReadOnlyCache {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.sources
}

// Decrypt decrypts name's value from the first source that has it, or returns 0 if none does. A
// source's error stops the search and is returned.
func (c *Collection) Decrypt(ctx context.Context, name string, result []byte) (int, error) {
	telemetry := diagnostics.Cache
	ctx, span := telemetry.Start(ctx, diagnostics.SpanCacheDecrypt)
	defer span.End()
	telemetry.LogSensitiveOperation(span, diagnostics.SpanCacheDecrypt, diagnostics.AttrName.String(name))

	for _, source := range c.snapshot() {
		n, err := source.Decrypt(ctx, name, result)
		if err != nil {
			diagnostics.RecordError(span, err)
			return 0, err
		}
		if n > 0 {
			return n, nil
		}
	}
	return 0, nil
}

// MaxDecryptedLength returns the bound from the first source that has name; ok is false if none
// does.
func (c *Collection) MaxDecryptedLength(ctx context.Context, name string) (int, bool, error) {
	for _, source := range c.snapshot() {
		n, ok, err := source.MaxDecryptedLength(ctx, name)
		if err != nil || ok {
			return n, ok, err
		}
	}
	return 0, false, nil
}
