// Package cache holds HkdfGuard's protected caches - the Go port of the .NET HkdfGuard.Cache
// library and the ProtectedCacheBase from HkdfGuard.Abstractions:
//
//   - Cache: the read/write hkdfguard.ProtectedCache - values are added by the application.
//   - ReadOnlyCache: a hkdfguard.ProtectedReadOnlyCache filled on demand from a Source, such as a
//     secret store (HashiCorp Vault, Azure Key Vault, ...). A backend supplies only the Source;
//     encryption, name binding and telemetry stay here.
//   - Collection: several read-only caches behind one lookup, checked in order.
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
	"sync"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/diagnostics"
)

// ErrEmptyValue reports an attempt to cache an empty value: Decrypt reports a missing name as 0
// bytes, so an empty value would be indistinguishable from no value.
var ErrEmptyValue = errors.New("cache: an empty value cannot be cached")

// Source supplies values a cache doesn't hold yet - e.g. a client for a remote secret store. A
// cache calls Fetch on a miss, encrypts what it returns under the requested name, stores it, and
// zeroes the returned plaintext.
type Source interface {
	// Fetch returns the plaintext value for name, and found == false when the source has none.
	// The cache takes ownership of plaintext and zeroes it.
	Fetch(ctx context.Context, name string) (plaintext []byte, found bool, err error)
}

// SourceFunc adapts a function to a Source.
type SourceFunc func(ctx context.Context, name string) ([]byte, bool, error)

// Fetch calls f.
func (f SourceFunc) Fetch(ctx context.Context, name string) ([]byte, bool, error) {
	return f(ctx, name)
}

// store is the plumbing every cache here shares: a KeyRing to encrypt and decrypt through, the
// encrypted entries keyed by name, and an optional Source consulted on a miss.
type store struct {
	ring   hkdfguard.KeyRing
	source Source

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

// lookup returns the entry for name, consulting the Source on a miss. found is false when neither
// holds the name.
func (s *store) lookup(ctx context.Context, name string) (entry *hkdfguard.KeyTrackingValue, found bool, err error) {
	key := matchKey(name)
	if e, ok := s.entries.Load(key); ok {
		return e.(*hkdfguard.KeyTrackingValue), true, nil
	}
	if s.source == nil {
		return nil, false, nil
	}

	plaintext, found, err := s.source.Fetch(ctx, name)
	if err != nil || !found {
		hkdfguard.Wipe(plaintext)
		return nil, false, err
	}
	fresh, err := s.encrypt(ctx, name, plaintext)
	if err != nil {
		return nil, false, err
	}
	// Another caller may have stored this name meanwhile; theirs wins, so every reader sees one value.
	e, _ := s.entries.LoadOrStore(key, fresh)
	return e.(*hkdfguard.KeyTrackingValue), true, nil
}

// decrypt decrypts the value stored under name into result, returning 0 (and no error) if no value
// is stored under it. The ciphertext is authenticated against name's AAD, so a value stored under
// another name fails with hkdfguard.ErrAuthenticationFailed.
func (s *store) decrypt(ctx context.Context, name string, result []byte) (int, error) {
	telemetry := diagnostics.Root
	ctx, span := telemetry.Start(ctx, diagnostics.SpanCacheDecrypt)
	defer span.End()
	telemetry.LogSensitiveOperation(span, diagnostics.SpanCacheDecrypt, diagnostics.AttrName.String(name))

	n, err := s.decryptEntry(ctx, name, result)
	if err != nil {
		diagnostics.RecordError(span, err)
	}
	return n, err
}

func (s *store) decryptEntry(ctx context.Context, name string, result []byte) (int, error) {
	entry, found, err := s.lookup(ctx, name)
	if err != nil || !found {
		return 0, err
	}
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
