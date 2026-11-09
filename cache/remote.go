package cache

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/diagnostics"
	"github.com/runsecure/hkdfguard-go/internal/cachevalue"
)

// KeySeparator separates a secret's name from a key it holds: "app-config#api-key".
const KeySeparator = '#'

// MaxKeyLength is the longest key a name can hold.
const MaxKeyLength = 256

// upperCaseMarker marks an upper-case ASCII letter in an entry name (see entryName).
const upperCaseMarker = '!'

// NameMatching is how a RemoteCache matches names, which must be how its secret store does.
type NameMatching int

const (
	// IgnoreASCIICase matches names differing only in ASCII case as one secret (Azure Key Vault).
	IgnoreASCIICase NameMatching = iota

	// Exact matches names exactly; names differing in case are different secrets (AWS Secrets
	// Manager, Google Secret Manager, HashiCorp Vault). A name holding '!' is reported missing
	// without a fetch - none of those stores allow it, and it marks case in entry names.
	Exact
)

// SecretStore is the one thing a RemoteCache needs of a remote secret store: a call that reads one
// secret by name - never a listing - and the rule for which names it can hold.
type SecretStore interface {
	// IsValidName reports whether the store can hold a secret named name; a name it can't is never
	// fetched, and is reported missing.
	IsValidName(name string) bool

	// Fetch reads the one secret named name and hands its current value, and any keys it holds, to
	// sink - or returns nil without doing so when it doesn't exist. Any other failure is returned.
	// It is called only for a name IsValidName accepts, never while another fetch of the same
	// secret is running, and must honour ctx.
	Fetch(ctx context.Context, name string, sink *SecretSink) error
}

// RemoteOptions are a RemoteCache's settings; the zero value matches names ignoring ASCII case,
// reads a secret's whole value for a name without a key, and logs nothing.
type RemoteOptions struct {
	// Matching is how the secret store matches names.
	Matching NameMatching

	// DefaultKey is the key a name without one reads, for a store whose secrets are all sets of keys
	// (HashiCorp Vault's KV); "" - the default - when such a name reads the secret's whole value.
	DefaultKey string

	// Logger receives a debug record per fetched name while sensitive logging is enabled
	// (diagnostics.Cache), and an error record per failed fetch and per cached value that fails to
	// decrypt.
	Logger *slog.Logger
}

// RemoteCache is a hkdfguard.ProtectedReadOnlyCache over a remote secret store - the Go port of the
// .NET RemoteSecretCache. Nothing is fetched up front: the first Decrypt or MaxDecryptedLength for a
// name that isn't cached yet calls the store's Fetch for that one secret, encrypts every value it
// hands over under the ring's current key, and caches the ciphertext; every later lookup is served
// from the cache. A store supplies only IsValidName and Fetch.
//
// A name is a secret's name, optionally followed by KeySeparator and a key: "app-config#api-key" is
// the api-key key of the secret app-config, which Fetch hands over with SecretSink.SetKeyBytes (or,
// for a secret holding a JSON object, SecretSink.SetBytesWithJSONKeys), and "app-config" is the
// secret's whole value, or its RemoteOptions.DefaultKey where the store has one. One fetch caches
// the whole value and every key it hands over, so the first lookup of any of them fetches the
// secret once and the rest are already cached. A key is 1-MaxKeyLength printable ASCII characters
// other than space, '!' and '#' (see IsValidKey), and is matched exactly whatever the store's
// matching.
//
// A name whose secret the store's IsValidName rejects, or whose key isn't one, is reported missing
// without a fetch, so a cache can sit in a Collection beside sources with other naming rules. A
// name the fetch hands no value for, or an empty one, is reported missing - Decrypt returns 0 - and
// isn't remembered, so it is fetched again on the next request (a key a cached secret doesn't hold
// costs a fetch every time). An error from Fetch is returned to the caller unchanged, and nothing
// that fetch handed over is cached. Concurrent lookups of the same uncached secret - of any of its
// keys - share one fetch, made with the context of the lookup that started it: a lookup whose own
// context ends stops waiting, and one whose shared fetch failed only because the starter's context
// ended starts a new fetch. A cached value is kept for the life of the cache: a later fetch of the
// same secret adds keys that weren't cached yet, but never replaces one that was.
//
// Encryption, name binding and key rotation are as for every cache here, which matches names
// ignoring ASCII case, so keys - and, under Exact, secret names - are stored under a case-escaped
// spelling: every upper-case ASCII letter becomes '!' and its lower-case form, so "prod/Db" and
// "prod/db" are different entries, each bound to its own spelling.
//
// Telemetry: each fetch is a diagnostics.SpanCachePopulate span on diagnostics.Cache, counted in
// diagnostics.CacheOperations as ResultSuccess, ResultNotFound or ResultError; with sensitive
// logging on, the secret's name (never a value) is logged. Safe for concurrent use.
type RemoteCache struct {
	store      store
	secrets    SecretStore
	matching   NameMatching
	defaultKey string
	logger     *slog.Logger
	fetches    sharedFetches // one fetch per uncached secret, by secret entry name
}

var _ hkdfguard.ProtectedReadOnlyCache = (*RemoteCache)(nil)

// ErrInvalidKey reports a key no name can hold: see IsValidKey.
var ErrInvalidKey = errors.New("cache: invalid key")

// NewRemote returns a RemoteCache that encrypts through ring what secrets hands over. The ring is
// the caller's: the cache never closes keys. It fails with ErrInvalidKey when options.DefaultKey is
// set but isn't a key.
func NewRemote(ring hkdfguard.KeyRing, secrets SecretStore, options RemoteOptions) (*RemoteCache, error) {
	if ring == nil || secrets == nil {
		return nil, errors.New("cache: a key ring and a secret store are required")
	}
	if options.DefaultKey != "" && !IsValidKey(options.DefaultKey) {
		return nil, fmt.Errorf("%w: the default key '%s' isn't one: 1-%d printable ASCII characters other than space, '!' and '#'",
			ErrInvalidKey, options.DefaultKey, MaxKeyLength)
	}
	c := &RemoteCache{
		secrets:    secrets,
		matching:   options.Matching,
		defaultKey: options.DefaultKey,
		logger:     options.Logger,
	}
	c.store = store{ring: ring, logger: options.Logger, populate: c.populateShared, names: c.namesIn}
	return c, nil
}

// IsValidKey reports whether key can follow KeySeparator in a name: 1-MaxKeyLength printable ASCII
// characters other than space, '!' and '#'.
func IsValidKey(key string) bool {
	if key == "" || len(key) > MaxKeyLength {
		return false
	}
	for i := 0; i < len(key); i++ {
		if c := key[i]; c <= ' ' || c > '~' || c == upperCaseMarker || c == KeySeparator {
			return false
		}
	}
	return true
}

// Decrypt decrypts the value for name into result - fetching its secret first if it isn't cached
// yet - and returns the number of bytes written, or 0 if there is none. Size result with
// MaxDecryptedLength.
func (c *RemoteCache) Decrypt(ctx context.Context, name string, result []byte) (int, error) {
	entry, ok := c.entryName(name)
	if !ok {
		return 0, nil
	}
	return c.store.decrypt(ctx, entry, result)
}

// MaxDecryptedLength is an upper bound on how many bytes Decrypt will write for name, fetching its
// secret first if needed; ok is false if there is no such value.
func (c *RemoteCache) MaxDecryptedLength(ctx context.Context, name string) (int, bool, error) {
	entry, ok := c.entryName(name)
	if !ok {
		return 0, false, nil
	}
	return c.store.maxDecryptedLength(ctx, entry)
}

// entryName is the entry name is stored under: its secret's entry name, then '#' and the
// case-escaped key, if any; ok is false for a name that can't be fetched.
func (c *RemoteCache) entryName(name string) (string, bool) {
	secret, key, hasKey := strings.Cut(name, string(KeySeparator))
	if !hasKey && c.defaultKey != "" {
		key, hasKey = c.defaultKey, true
	}
	if (hasKey && !IsValidKey(key)) || !c.secrets.IsValidName(secret) ||
		(c.matching == Exact && strings.IndexByte(secret, upperCaseMarker) >= 0) {
		return "", false
	}
	entry := c.secretEntryName(secret)
	if hasKey {
		entry += string(KeySeparator) + escapeCase(key)
	}
	return entry, true
}

func (c *RemoteCache) secretEntryName(secret string) string {
	if c.matching == Exact {
		return escapeCase(secret)
	}
	return secret
}

func (c *RemoteCache) secretName(secretEntry string) string {
	if c.matching == Exact {
		return unescapeCase(secretEntry)
	}
	return secretEntry
}

// escapeCase is the case-escaped spelling of a name or key: each upper-case ASCII letter becomes
// '!' and its lower-case form, so the result holds no upper-case letters and matching it ignoring
// ASCII case is matching it exactly. "prod/Db" is "prod/!db"; "prod/db" stays as it is.
func escapeCase(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 8)
	for i := 0; i < len(s); i++ {
		if c := s[i]; 'A' <= c && c <= 'Z' {
			b.WriteByte(upperCaseMarker)
			b.WriteByte(c + ('a' - 'A'))
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// unescapeCase is the name escapeCase made entry from.
func unescapeCase(entry string) string {
	var b strings.Builder
	b.Grow(len(entry))
	for i := 0; i < len(entry); i++ {
		if entry[i] == upperCaseMarker && i+1 < len(entry) {
			i++
			b.WriteByte(entry[i] - ('a' - 'A'))
		} else {
			b.WriteByte(entry[i])
		}
	}
	return b.String()
}

// namesIn is every name a failure looking up entry - a secret's entry name, and possibly '#' and a
// case-escaped key - could quote: the entry name, the secret's own name, and the key, as given.
func (c *RemoteCache) namesIn(entry string) []string {
	secretEntry, key, hasKey := strings.Cut(entry, string(KeySeparator))
	names := []string{entry, secretEntry, c.secretName(secretEntry)}
	if hasKey {
		names = append(names, key, unescapeCase(key))
	}
	return names
}

// populateShared runs the fetch of the secret entryName belongs to, or waits for the one already
// running; the store then looks entryName up again.
func (c *RemoteCache) populateShared(ctx context.Context, entryName string) (bool, error) {
	secretEntry, _, _ := strings.Cut(entryName, string(KeySeparator))
	return c.fetches.do(ctx, secretEntry, func(ctx context.Context) (bool, error) {
		return c.populate(ctx, secretEntry)
	})
}

// populate fetches the secret stored under secretEntry, caching everything handed over; false if
// nothing was.
func (c *RemoteCache) populate(ctx context.Context, secretEntry string) (bool, error) {
	secret := c.secretName(secretEntry)
	telemetry := diagnostics.Cache
	ctx, span := telemetry.Start(ctx, diagnostics.SpanCachePopulate)
	defer span.End()
	telemetry.LogSensitiveOperation(span, diagnostics.SpanCachePopulate, diagnostics.AttrName.String(secret))

	sink := &SecretSink{ctx: ctx, store: &c.store, secretEntry: secretEntry, values: map[string]*hkdfguard.KeyTrackingValue{}}
	err := c.fetchInto(ctx, secret, sink)
	sink.close()
	if err != nil {
		logged := telemetry.LoggedError(err, c.namesIn(secretEntry)...)
		diagnostics.RecordError(span, logged)
		diagnostics.OperationFailed(ctx, c.logger, diagnostics.SpanCachePopulate, logged)
		cachevalue.RecordPopulate(ctx, diagnostics.ResultError)
		return false, err
	}
	if telemetry.SensitiveLoggingEnabled() {
		// Only once the fetch has returned: a record that says "completed" must not precede the outcome.
		diagnostics.SensitiveOperationLogged(ctx, c.logger, diagnostics.SpanCachePopulate, secret)
	}
	if len(sink.values) == 0 {
		cachevalue.RecordPopulate(ctx, diagnostics.ResultNotFound)
		return false, nil
	}

	// A fetch that began just after another finished may find values already stored; keep those.
	for entry, value := range sink.values {
		c.store.entries.LoadOrStore(matchKey(entry), value)
	}
	cachevalue.RecordPopulate(ctx, diagnostics.ResultSuccess)
	return true, nil
}

// fetchInto calls the store's Fetch, turning a panic into an error so the lookups sharing the fetch
// are released with it.
func (c *RemoteCache) fetchInto(ctx context.Context, secret string, sink *SecretSink) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("cache: the secret store's Fetch panicked: %v", r)
		}
	}()
	return c.secrets.Fetch(ctx, secret, sink)
}
