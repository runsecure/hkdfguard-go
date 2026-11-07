package configurationresolver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/diagnostics"
)

// DefaultMaxResolvedLength is the default ResolvingOptions.MaxResolvedLength: 1 MiB.
const DefaultMaxResolvedLength = 1 << 20

// ResolvingOptions configures a ResolvingProtectedCacheCollection. The zero value is the default.
type ResolvingOptions struct {
	// Token marks an item; nil means NewDefaultToken: "${", "}" and the escape "$".
	Token *ConfigurationItemToken

	// MaxResolvedLength is the most UTF-8 bytes a resolved value may hold; 0 means
	// DefaultMaxResolvedLength. A template that resolves to more fails its lookup with
	// ErrResolvedValueTooLong.
	MaxResolvedLength int
}

// ResolvingProtectedCacheCollection is a cache.Collection with templates: it aggregates
// hkdfguard.ProtectedReadOnlyCache sources, checked in the order they were added, and resolves a
// value holding configuration items - "Host=db;Password=${db-password}" - on its first lookup,
// from those same sources (then any value providers added with AddValueProvider). The resolved
// value is encrypted under the ring's current key, bound to its name with hkdfguard.CacheAAD as
// every cache entry is, and kept, so later lookups only decrypt it. A value without items is
// answered by its source, unchanged. The port of ResolvingProtectedCacheCollection.
//
// Templates are trusted. A template's items may name any value in any source, so every source
// must be as trusted as the secrets it can reach: a template comes from whichever source holds its
// name, and nothing marks one source as templates only. Items are resolved one level deep: an item
// whose value is itself a template inserts that template's text unresolved. A value that is a
// template but names a value no source or provider has fails its lookup with a
// *ConfigurationKeyError, rather than reporting the name missing. One that resolves to nothing is
// reported missing, as an empty value can't be cached.
//
// Resolved values are kept until invalidated. When a value a template uses changes - a
// cache.Cache AddOrUpdate, a rotated remote secret - call Invalidate for the template's name, or
// Clear; the next lookup resolves it again. A resolution already under way when either is called
// doesn't keep its result. Which source holds a value without items is remembered too, and
// forgotten the same way. Add every source and provider before the first lookup.
//
// Names match exactly, as the sources' own names may: "Db" and "db" are two names here, though
// HkdfGuard's caches otherwise ignore ASCII case.
//
// A source that fails fails the lookup, as in cache.Collection, and the same advice holds: add
// local sources before remote ones. Every lookup passes the caller's context to each source.
//
// Telemetry: Decrypt is a diagnostics.SpanCacheDecrypt span on diagnostics.Cache, with the name
// logged while sensitive logging is on. Safe for concurrent use.
type ResolvingProtectedCacheCollection struct {
	token             *ConfigurationItemToken
	maxResolvedLength int

	mu             sync.RWMutex
	sources        []hkdfguard.ProtectedReadOnlyCache
	valueProviders []ValueProvider

	resolved resolvedStore
	plain    sync.Map // name -> the hkdfguard.ProtectedReadOnlyCache holding its value, which has no items

	gate       sync.Mutex // held to change generation, and to keep a result only for the generation it was read under
	generation atomic.Int64
}

var _ hkdfguard.ProtectedReadOnlyCache = (*ResolvingProtectedCacheCollection)(nil)

// NewResolvingProtectedCacheCollection returns an empty collection. ring encrypts each resolved
// value under its current key, and decrypts it under the version it recorded; it is the caller's,
// and never closed here. It fails when ring is nil or options.MaxResolvedLength is negative.
func NewResolvingProtectedCacheCollection(ring hkdfguard.KeyRing, options ResolvingOptions) (*ResolvingProtectedCacheCollection, error) {
	if ring == nil {
		return nil, errors.New("configurationresolver: a key ring is required")
	}
	if options.MaxResolvedLength < 0 {
		return nil, fmt.Errorf("configurationresolver: MaxResolvedLength must be at least 1, not %d", options.MaxResolvedLength)
	}
	token := options.Token
	if token == nil {
		token = NewDefaultToken()
	}
	maxResolvedLength := options.MaxResolvedLength
	if maxResolvedLength == 0 {
		maxResolvedLength = DefaultMaxResolvedLength
	}
	return &ResolvingProtectedCacheCollection{
		token:             token,
		maxResolvedLength: maxResolvedLength,
		resolved:          resolvedStore{ring: ring},
	}, nil
}

// Token is the token that marks an item.
func (c *ResolvingProtectedCacheCollection) Token() *ConfigurationItemToken { return c.token }

// MaxResolvedLength is the most UTF-8 bytes a resolved value may hold.
func (c *ResolvingProtectedCacheCollection) MaxResolvedLength() int { return c.maxResolvedLength }

// Add registers source, checked after every source already added - for names and for the items
// in templates alike - and returns c for chaining. It panics when source is nil.
func (c *ResolvingProtectedCacheCollection) Add(source hkdfguard.ProtectedReadOnlyCache) *ResolvingProtectedCacheCollection {
	if source == nil {
		panic("configurationresolver: ResolvingProtectedCacheCollection.Add was given a nil source")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sources = append(c.sources, source)
	return c
}

// AddValueProvider registers a value provider for the items in templates only, asked after every
// source and every provider already added, and returns c for chaining. Its values are never
// answered by name on their own. A provider that holds its values as strings is no place for
// secrets. It panics when valueProvider is nil.
func (c *ResolvingProtectedCacheCollection) AddValueProvider(valueProvider ValueProvider) *ResolvingProtectedCacheCollection {
	if valueProvider == nil {
		panic("configurationresolver: ResolvingProtectedCacheCollection.AddValueProvider was given a nil value provider")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.valueProviders = append(c.valueProviders, valueProvider)
	return c
}

// Invalidate forgets name's resolved value, or which source holds it, so the next lookup reads it
// again. It reports whether anything was remembered for name.
func (c *ResolvingProtectedCacheCollection) Invalidate(name string) bool {
	c.gate.Lock()
	defer c.gate.Unlock()
	c.generation.Add(1)
	resolved := c.resolved.remove(storeKey(name))
	_, plain := c.plain.LoadAndDelete(name)
	return resolved || plain
}

// Clear forgets every resolved value, and every source a value was found in.
func (c *ResolvingProtectedCacheCollection) Clear() {
	c.gate.Lock()
	defer c.gate.Unlock()
	c.generation.Add(1)
	c.resolved.clear()
	c.plain.Clear()
}

// Decrypt decrypts name's value into result and returns the number of bytes written, or 0 if no
// source has name or its template resolves to nothing. A template naming a value nothing has
// fails with a *ConfigurationKeyError, and one resolving to more than MaxResolvedLength with
// ErrResolvedValueTooLong.
func (c *ResolvingProtectedCacheCollection) Decrypt(ctx context.Context, name string, result []byte) (int, error) {
	telemetry := diagnostics.Cache
	ctx, span := telemetry.Start(ctx, diagnostics.SpanCacheDecrypt)
	defer span.End()
	telemetry.LogSensitiveOperation(span, diagnostics.SpanCacheDecrypt, diagnostics.AttrName.String(name))

	n, err := c.decrypt(ctx, name, result)
	if err != nil {
		diagnostics.RecordError(span, telemetry.LoggedError(err, name))
	}
	return n, err
}

func (c *ResolvingProtectedCacheCollection) decrypt(ctx context.Context, name string, result []byte) (int, error) {
	key := storeKey(name)
	for {
		written, err := c.resolved.decrypt(ctx, key, result)
		if err != nil || written > 0 {
			return written, err
		}

		where, source, err := c.locate(ctx, name)
		if err != nil {
			return 0, err
		}
		if where != locatedResolved {
			if source == nil {
				return 0, nil
			}
			return source.Decrypt(ctx, name, result)
		}
	}
}

// MaxDecryptedLength is an upper bound on how many bytes Decrypt will write for name; ok is false
// if no source has name or its template resolves to nothing. It resolves a template it hasn't
// yet, failing as Decrypt does.
func (c *ResolvingProtectedCacheCollection) MaxDecryptedLength(ctx context.Context, name string) (int, bool, error) {
	key := storeKey(name)
	for {
		if maxLength, ok := c.resolved.maxDecryptedLength(key); ok {
			return maxLength, true, nil
		}

		where, source, err := c.locate(ctx, name)
		if err != nil {
			return 0, false, err
		}
		if where != locatedResolved {
			if source == nil {
				return 0, false, nil
			}
			return source.MaxDecryptedLength(ctx, name)
		}
	}
}

// location is where locate found a name's value.
type location int

const (
	// locatedMissing: no source holds the name, or its template resolved to nothing.
	locatedMissing location = iota

	// locatedSource: a source holds the name, and its value has no items: that source answers.
	locatedSource

	// locatedResolved: the name's template was resolved: look in the resolved store again. If an
	// Invalidate or Clear kept the result out of it, the lookup resolves it again.
	locatedResolved
)

func (c *ResolvingProtectedCacheCollection) snapshot() ([]hkdfguard.ProtectedReadOnlyCache, []ValueProvider) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.sources, c.valueProviders
}

// locate finds name's value outside the resolved store, resolving and keeping it on the way when
// it is a template.
func (c *ResolvingProtectedCacheCollection) locate(ctx context.Context, name string) (location, hkdfguard.ProtectedReadOnlyCache, error) {
	if source, ok := c.plain.Load(name); ok {
		return locatedSource, source.(hkdfguard.ProtectedReadOnlyCache), nil
	}

	generation := c.generation.Load()
	sources, valueProviders := c.snapshot()
	source, maxLength, err := findSource(ctx, sources, name)
	if err != nil || source == nil {
		return locatedMissing, nil, err
	}

	template, length, reader, err := c.readTemplate(ctx, source, name, maxLength)
	if err != nil {
		return locatedMissing, nil, err
	}
	if template == nil {
		return c.remember(name, source, generation), source, nil
	}
	defer hkdfguard.Wipe(template)

	bound := int64(length)
	for _, key := range reader.Keys() {
		_, keyLength, err := findSource(ctx, sources, key)
		if err != nil {
			return locatedMissing, nil, err
		}
		bound += int64(keyLength)
	}

	where, err := c.resolve(ctx, name, template[:length], reader, bound, generation, sources, valueProviders)
	return where, nil, err
}

// findSource returns the first source holding name, as cache.Collection finds it, with its bound
// on the value's length.
func findSource(ctx context.Context, sources []hkdfguard.ProtectedReadOnlyCache, name string) (hkdfguard.ProtectedReadOnlyCache, int, error) {
	for _, source := range sources {
		maxLength, ok, err := source.MaxDecryptedLength(ctx, name)
		if err != nil {
			return nil, 0, err
		}
		if ok {
			return source, maxLength, nil
		}
	}
	return nil, 0, nil
}

// readTemplate reads name's value from source, returning it with a reader that has read its items
// - or nil, the value already wiped, when it holds none.
func (c *ResolvingProtectedCacheCollection) readTemplate(ctx context.Context, source hkdfguard.ProtectedReadOnlyCache, name string, maxLength int) ([]byte, int, *ConfigurationItemReader, error) {
	value := make([]byte, maxLength)
	length, err := source.Decrypt(ctx, name, value)
	if err != nil {
		hkdfguard.Wipe(value)
		return nil, 0, nil, err
	}

	reader := &ConfigurationItemReader{token: c.token}
	if len(reader.ReadKeys(value[:length])) > 0 {
		return value, length, reader, nil
	}
	hkdfguard.Wipe(value)
	return nil, 0, nil, nil
}

func (c *ResolvingProtectedCacheCollection) remember(name string, source hkdfguard.ProtectedReadOnlyCache, generation int64) location {
	c.gate.Lock()
	defer c.gate.Unlock()
	if generation == c.generation.Load() {
		c.plain.Store(name, source)
	}
	return locatedSource
}

// resolve resolves template and keeps the result under name - unless Invalidate or Clear was
// called since generation was read, when the result is dropped for the lookup to resolve again.
func (c *ResolvingProtectedCacheCollection) resolve(ctx context.Context, name string, template []byte, reader KeyReader, bound, generation int64,
	sources []hkdfguard.ProtectedReadOnlyCache, valueProviders []ValueProvider) (location, error) {
	providers := make([]ValueProvider, 0, len(sources)+len(valueProviders))
	for _, source := range sources {
		providers = append(providers, &ProtectedCacheValueProvider{cache: source})
	}
	providers = append(providers, valueProviders...)
	resolver, err := NewConfigurationItemResolver(c.token, reader, providers...)
	if err != nil {
		return locatedMissing, err
	}

	// The sources' bounds cover their values; a value provider's can't be known up front, so a
	// value from one may need a larger buffer.
	capacity := int(min(max(bound, 1), int64(c.maxResolvedLength)))
	for {
		resolved := make([]byte, capacity)
		written, err := resolver.Resolve(ctx, template, resolved)
		if errors.Is(err, ErrDestinationTooSmall) {
			hkdfguard.Wipe(resolved)
			if capacity >= c.maxResolvedLength {
				return locatedMissing, fmt.Errorf("%w (%d bytes)", ErrResolvedValueTooLong, c.maxResolvedLength)
			}
			capacity = int(min(2*int64(capacity), int64(c.maxResolvedLength)))
			continue
		}
		if err != nil || written == 0 {
			hkdfguard.Wipe(resolved)
			return locatedMissing, err
		}
		return locatedResolved, c.keep(ctx, name, resolved, written, generation)
	}
}

// keep encrypts resolved[:written] into the resolved store under name, if generation is still
// current, and wipes resolved.
func (c *ResolvingProtectedCacheCollection) keep(ctx context.Context, name string, resolved []byte, written int, generation int64) error {
	defer hkdfguard.Wipe(resolved)
	c.gate.Lock()
	defer c.gate.Unlock()
	if generation != c.generation.Load() {
		return nil
	}
	return c.resolved.set(ctx, storeKey(name), resolved[:written])
}

// storeKey is name's key in the resolved store. hkdfguard.CacheAAD upper-cases ASCII letters, as
// every cache matches names ignoring ASCII case; this collection matches them exactly, as its
// sources may. So each name is stored under a spelling with no upper-case ASCII - '!' becomes
// "!!", and an upper-case letter '!' and its lower-case form - whose AAD no other name shares.
func storeKey(name string) string {
	if !strings.ContainsAny(name, "!ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
		return name
	}
	var key strings.Builder
	key.Grow(len(name) + 8)
	for i := 0; i < len(name); i++ {
		switch b := name[i]; {
		case b == '!':
			key.WriteString("!!")
		case 'A' <= b && b <= 'Z':
			key.WriteByte('!')
			key.WriteByte(b + ('a' - 'A'))
		default:
			key.WriteByte(b)
		}
	}
	return key.String()
}

// resolvedStore holds the resolved values, each encrypted under its ring's current key and bound
// to its store key with hkdfguard.CacheAAD, as cache.Cache stores its values.
type resolvedStore struct {
	ring    hkdfguard.KeyRing
	entries sync.Map // store key -> *hkdfguard.KeyTrackingValue
}

// set encrypts plaintext and stores it under key. plaintext is wiped, whether or not it succeeds.
func (s *resolvedStore) set(ctx context.Context, key string, plaintext []byte) error {
	defer hkdfguard.Wipe(plaintext)
	aad, err := hkdfguard.CacheAAD(key)
	if err != nil {
		return err
	}
	version, dataKey, err := s.ring.Current(ctx)
	if err != nil {
		return err
	}
	ciphertext, err := dataKey.Encrypt(ctx, plaintext, aad)
	if err != nil {
		return err
	}
	s.entries.Store(key, &hkdfguard.KeyTrackingValue{KeyVersion: version, Value: ciphertext})
	return nil
}

// decrypt decrypts the value stored under key into result, or returns 0 if there is none.
func (s *resolvedStore) decrypt(ctx context.Context, key string, result []byte) (int, error) {
	entry, ok := s.entries.Load(key)
	if !ok {
		return 0, nil
	}
	value := entry.(*hkdfguard.KeyTrackingValue)
	aad, err := hkdfguard.CacheAAD(key)
	if err != nil {
		return 0, err
	}
	dataKey, err := s.ring.Get(ctx, value.KeyVersion)
	if err != nil {
		return 0, err
	}
	return dataKey.Decrypt(ctx, value.Value, aad, result)
}

// maxDecryptedLength is the stored ciphertext's length - an upper bound on the plaintext's.
func (s *resolvedStore) maxDecryptedLength(key string) (int, bool) {
	entry, ok := s.entries.Load(key)
	if !ok {
		return 0, false
	}
	return len(entry.(*hkdfguard.KeyTrackingValue).Value), true
}

func (s *resolvedStore) remove(key string) bool {
	_, ok := s.entries.LoadAndDelete(key)
	return ok
}

func (s *resolvedStore) clear() {
	s.entries.Clear()
}
