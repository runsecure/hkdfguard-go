// Package cache holds HkdfGuard's protected caches - the Go port of the .NET HkdfGuard.Cache
// library and the ProtectedCacheBase from HkdfGuard.Abstractions:
//
//   - Cache: the read/write hkdfguard.ProtectedCache - values are added by the application.
//   - ReadOnlyCache: a hkdfguard.ProtectedReadOnlyCache filled on demand from a Source, one value
//     per name, with concurrent misses on a name sharing one fetch. A backend supplies only the
//     Source; encryption, name binding and telemetry stay here.
//   - RemoteCache: a hkdfguard.ProtectedReadOnlyCache over a remote secret store, filled one
//     secret per fetch - its whole value and every key it holds ("name#key") - with concurrent
//     misses sharing one fetch. A store supplies only a SecretStore; the modules
//     cache/awssecretsmanager, cache/azurekeyvault, cache/googlesecretmanager and
//     cache/hashicorpvault are the stores HkdfGuard ships. CaptureJSONBody and CaptureJSONKeys take
//     a secret out of a JSON response body before an SDK can turn it into a string.
//   - Collection: several read-only caches behind one lookup, checked in order.
//
// The module cache/filepersecret is a read-only cache of another kind: a folder of one already
// encrypted file per secret, read through securefile, each value bound to its file name with
// hkdfguard.ConfigurationAAD and cached exactly as its file holds it. It is a module of its own
// because securefile is one, which depends on this one.
//
// Every value is encrypted under its KeyRing's current key when stored, and its entry records that
// key's version, so a cache follows key rotation while earlier values stay readable. Every value
// is bound to its name (see hkdfguard.CacheAAD): a ciphertext that ends up under another name fails
// authentication rather than decrypting as that name's value. Names match ignoring ASCII case
// only. Nothing here holds plaintext beyond a single call; only ciphertext is retained.
package cache

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/diagnostics"
	"github.com/runsecure/hkdfguard-go/internal/cachevalue"
	"go.opentelemetry.io/otel/metric"
)

// ErrEmptyValue reports an attempt to cache an empty value: Decrypt reports a missing name as 0
// bytes, so an empty value would be indistinguishable from no value.
var ErrEmptyValue = errors.New("cache: an empty value cannot be cached")

// Source supplies values a cache doesn't hold yet - e.g. a client for a remote secret store. A
// cache calls Fetch on a miss, encrypts what it returns under the requested name, stores it, and
// zeroes the returned plaintext. Concurrent misses on one name (in any ASCII case) share one
// Fetch, made with the context of the lookup that started it, so Fetch is never running twice for
// the same name; a name the source lacks isn't remembered, and is fetched again on the next miss.
type Source interface {
	// Fetch returns the plaintext value for name, and found == false when the source has none.
	// The cache takes ownership of plaintext and zeroes it. It must honour ctx.
	Fetch(ctx context.Context, name string) (plaintext []byte, found bool, err error)
}

// SourceFunc adapts a function to a Source.
type SourceFunc func(ctx context.Context, name string) ([]byte, bool, error)

// Fetch calls f.
func (f SourceFunc) Fetch(ctx context.Context, name string) ([]byte, bool, error) {
	return f(ctx, name)
}

// store is the plumbing every cache here shares: a KeyRing to encrypt and decrypt through, the
// encrypted entries keyed by name, an optional Source - or populate - consulted on a miss, and an
// optional logger for every failed operation.
type store struct {
	ring   hkdfguard.KeyRing
	source Source
	logger *slog.Logger

	// populate, when set, is consulted on a miss instead of source: it stores whatever it fetches
	// itself (a RemoteCache stores several entries per fetch, sharing one fetch between concurrent
	// misses on one secret) and reports whether it stored anything, after which the name is looked
	// up again.
	populate func(ctx context.Context, name string) (bool, error)

	// fetches shares one Source fetch between concurrent misses on one name.
	fetches sharedFetches

	// names, when set, is every name a failure looking up an entry name could quote (see namesIn).
	names func(name string) []string

	// Entries keyed by matchKey(name), each a *hkdfguard.KeyTrackingValue that was encrypted for
	// that same name. Keying by the ASCII-upper-cased name is exactly the rule CacheAAD applies,
	// so every spelling that reaches an entry also authenticates against it.
	entries sync.Map
}

// matchKey is the map key for name: its ASCII letters upper-cased, every other byte unchanged.
func matchKey(name string) string {
	for i := 0; i < len(name); i++ {
		if 'a' <= name[i] && name[i] <= 'z' {
			b := []byte(name)
			for j := i; j < len(b); j++ {
				if 'a' <= b[j] && b[j] <= 'z' {
					b[j] -= 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return name
}

// encrypt encrypts plaintext under the ring's current key, bound to name, and returns the entry
// to store under that same name. plaintext is zeroed, whether or not it succeeds.
func (s *store) encrypt(ctx context.Context, name string, plaintext []byte) (*hkdfguard.KeyTrackingValue, error) {
	// Normally the key zeroes it; this covers every failure before it gets that far.
	defer hkdfguard.Wipe(plaintext)

	if len(plaintext) == 0 {
		return nil, fmt.Errorf("%w: Decrypt reports a missing name as 0 bytes", ErrEmptyValue)
	}
	aad, err := hkdfguard.CacheAAD(name)
	if err != nil {
		return nil, err
	}
	// Resolved on every call, so a value stored after a rotation uses the new key.
	version, key, err := s.ring.Current(ctx)
	if err != nil {
		return nil, err
	}
	ciphertext, err := key.Encrypt(ctx, plaintext, aad)
	if err != nil {
		return nil, err
	}
	return &hkdfguard.KeyTrackingValue{KeyVersion: version, Value: ciphertext}, nil
}

// lookup returns the entry for name, consulting populate or the Source on a miss. found is false
// when neither holds the name.
func (s *store) lookup(ctx context.Context, name string) (entry *hkdfguard.KeyTrackingValue, found bool, err error) {
	key := matchKey(name)
	if e, ok := s.entries.Load(key); ok {
		return e.(*hkdfguard.KeyTrackingValue), true, nil
	}
	populated, err := s.populateMiss(ctx, key, name)
	if err != nil || !populated {
		return nil, false, err
	}
	e, ok := s.entries.Load(key)
	if !ok {
		return nil, false, nil
	}
	return e.(*hkdfguard.KeyTrackingValue), true, nil
}

// populateMiss fills the entry for name - stored under key - from populate or the Source, and
// reports whether anything was stored. Concurrent misses on one key share one Source fetch.
func (s *store) populateMiss(ctx context.Context, key, name string) (bool, error) {
	if s.populate != nil {
		return s.populate(ctx, name)
	}
	if s.source == nil {
		return false, nil
	}
	return s.fetches.do(ctx, key, func(ctx context.Context) (bool, error) {
		return s.fetchFromSource(ctx, key, name)
	})
}

// fetchFromSource fetches name from the Source, encrypts it bound to name and stores it under key,
// reporting whether it did. Each fetch is a diagnostics.SpanCachePopulate span, counted in
// diagnostics.CacheOperations; with sensitive logging on, the name is logged once the fetch has
// returned. A failure - a Source error, an empty value, or a Source that panics - is logged and
// returned, and nothing is stored.
func (s *store) fetchFromSource(ctx context.Context, key, name string) (bool, error) {
	telemetry := diagnostics.Cache
	ctx, span := telemetry.Start(ctx, diagnostics.SpanCachePopulate)
	defer span.End()
	telemetry.LogSensitiveOperation(span, diagnostics.SpanCachePopulate, diagnostics.AttrName.String(name))

	populated, err := s.storeFromSource(ctx, key, name)
	if err != nil {
		logged := telemetry.LoggedError(err, s.namesIn(name)...)
		diagnostics.RecordError(span, logged)
		diagnostics.OperationFailed(ctx, s.logger, diagnostics.SpanCachePopulate, logged)
		cachevalue.RecordPopulate(ctx, diagnostics.ResultError)
		return false, err
	}
	if telemetry.SensitiveLoggingEnabled() {
		diagnostics.SensitiveOperationLogged(ctx, s.logger, diagnostics.SpanCachePopulate, name)
	}
	if !populated {
		cachevalue.RecordPopulate(ctx, diagnostics.ResultNotFound)
		return false, nil
	}
	cachevalue.RecordPopulate(ctx, diagnostics.ResultSuccess)
	return true, nil
}

func (s *store) storeFromSource(ctx context.Context, key, name string) (populated bool, err error) {
	plaintext, found, err := s.callSource(ctx, name)
	if err != nil || !found {
		hkdfguard.Wipe(plaintext)
		return false, err
	}
	fresh, err := s.encrypt(ctx, name, plaintext)
	if err != nil {
		return false, err
	}
	// Another caller may have stored this name meanwhile; theirs wins, so every reader sees one value.
	s.entries.LoadOrStore(key, fresh)
	return true, nil
}

// callSource calls the Source's Fetch, turning a panic into an error so the lookups sharing the
// fetch are released with it rather than told the name is missing.
func (s *store) callSource(ctx context.Context, name string) (plaintext []byte, found bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			plaintext, found, err = nil, false, fmt.Errorf("cache: the source's Fetch panicked: %v", r)
		}
	}()
	return s.source.Fetch(ctx, name)
}

// decrypt decrypts the value stored under name into result, returning 0 (and no error) if no value
// is stored under it. The ciphertext is authenticated against name's AAD, so a value stored under
// another name fails with hkdfguard.ErrAuthenticationFailed. Each call is a
// diagnostics.SpanCacheDecrypt span, counted in diagnostics.CacheOperations as ResultSuccess,
// ResultNotFound or ResultError. A failure to decrypt a stored entry - an authentication failure,
// or a key version the ring no longer holds - is logged; a failure to fetch a missing name is
// logged by the fetch that failed.
func (s *store) decrypt(ctx context.Context, name string, result []byte) (int, error) {
	telemetry := diagnostics.Cache
	ctx, span := telemetry.Start(ctx, diagnostics.SpanCacheDecrypt)
	defer span.End()
	telemetry.LogSensitiveOperation(span, diagnostics.SpanCacheDecrypt, diagnostics.AttrName.String(name))

	n, err := s.decryptEntry(ctx, name, result)
	if err != nil {
		diagnostics.RecordError(span, telemetry.LoggedError(err, s.namesIn(name)...))
	}
	diagnostics.CacheOperations().Add(ctx, 1, metric.WithAttributes(
		diagnostics.AttrOperationName.String(diagnostics.SpanCacheDecrypt), diagnostics.AttrResult.String(decryptResult(n, err))))
	return n, err
}

func decryptResult(n int, err error) string {
	switch {
	case err != nil:
		return diagnostics.ResultError
	case n == 0:
		return diagnostics.ResultNotFound
	default:
		return diagnostics.ResultSuccess
	}
}

func (s *store) decryptEntry(ctx context.Context, name string, result []byte) (int, error) {
	entry, found, err := s.lookup(ctx, name)
	if err != nil || !found {
		return 0, err
	}
	n, err := s.decryptStored(ctx, name, entry, result)
	if err != nil {
		diagnostics.OperationFailed(ctx, s.logger, diagnostics.SpanCacheDecrypt, diagnostics.Cache.LoggedError(err, s.namesIn(name)...))
	}
	return n, err
}

// namesIn is every name a failure looking up name could quote, for diagnostics.Component.LoggedError
// to remove: name itself, and whatever names the cache derives it from (a RemoteCache's secret and
// key).
func (s *store) namesIn(name string) []string {
	if s.names != nil {
		return s.names(name)
	}
	return []string{name}
}

func (s *store) decryptStored(ctx context.Context, name string, entry *hkdfguard.KeyTrackingValue, result []byte) (int, error) {
	aad, err := hkdfguard.CacheAAD(name)
	if err != nil {
		return 0, err
	}
	key, err := s.ring.Get(ctx, entry.KeyVersion)
	if err != nil {
		return 0, err
	}
	return key.Decrypt(ctx, entry.Value, aad, result)
}

// maxDecryptedLength returns the stored ciphertext's length - an upper bound on the plaintext - and
// false when no value is stored under name.
func (s *store) maxDecryptedLength(ctx context.Context, name string) (int, bool, error) {
	entry, found, err := s.lookup(ctx, name)
	if err != nil || !found {
		return 0, false, err
	}
	return len(entry.Value), true, nil
}
