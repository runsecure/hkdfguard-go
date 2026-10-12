package cache

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/diagnostics"
	"go.opentelemetry.io/otel/metric"
)

// Option configures a Cache or ReadOnlyCache.
type Option func(*options)

type options struct {
	logger *slog.Logger
	source Source
}

// WithLogger sets where a cache logs each failed operation, and - while sensitive logging is
// enabled (diagnostics.Cache) - each successful one.
func WithLogger(logger *slog.Logger) Option {
	return func(o *options) { o.logger = logger }
}

// WithSource sets a Source a Cache consults when a name it is asked for isn't stored yet.
func WithSource(source Source) Option {
	return func(o *options) { o.source = source }
}

// Cache is the read/write hkdfguard.ProtectedCache. Add uses an atomic insert, so a duplicate name
// is rejected even under concurrent callers; AddOrUpdate and Decrypt are lock-free. The KeyRing
// is the caller's: the cache never closes keys. Safe for concurrent use.
type Cache struct {
	store  store
	logger *slog.Logger
}

var _ hkdfguard.ProtectedCache = (*Cache)(nil)

// New returns an empty Cache that encrypts through ring.
func New(ring hkdfguard.KeyRing, opts ...Option) *Cache {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	return &Cache{store: store{ring: ring, source: o.source}, logger: o.logger}
}

// Add encrypts plaintext and stores it under name. plaintext is zeroed, whether or not it
// succeeds. A value already stored under name (in any ASCII case) fails with an error wrapping
// hkdfguard.ErrAlreadyExists; an empty value with ErrEmptyValue.
func (c *Cache) Add(ctx context.Context, name string, plaintext []byte) error {
	return c.write(ctx, diagnostics.SpanCacheAdd, name, plaintext, func(entry *hkdfguard.KeyTrackingValue) error {
		if _, loaded := c.store.entries.LoadOrStore(matchKey(name), entry); loaded {
			return fmt.Errorf("%w: an item with the name '%s' has already been added", hkdfguard.ErrAlreadyExists, name)
		}
		return nil
	})
}

// AddOrUpdate encrypts plaintext and stores it under name, replacing any value already stored
// there. plaintext is zeroed, whether or not it succeeds.
func (c *Cache) AddOrUpdate(ctx context.Context, name string, plaintext []byte) error {
	return c.write(ctx, diagnostics.SpanCacheAddOrUpdate, name, plaintext, func(entry *hkdfguard.KeyTrackingValue) error {
		c.store.entries.Store(matchKey(name), entry)
		return nil
	})
}

func (c *Cache) write(ctx context.Context, operation, name string, plaintext []byte, put func(*hkdfguard.KeyTrackingValue) error) error {
	telemetry := diagnostics.Cache
	ctx, span := telemetry.Start(ctx, operation)
	defer span.End()
	if telemetry.SensitiveLoggingEnabled() {
		telemetry.LogSensitiveOperation(span, operation, diagnostics.AttrName.String(name), diagnostics.AttrPlaintextLength.Int(len(plaintext)))
		diagnostics.SensitiveOperationLogged(ctx, c.logger, operation, name)
	}

	entry, err := c.store.encrypt(ctx, name, plaintext)
	if err == nil {
		err = put(entry)
	}

	result := diagnostics.ResultSuccess
	if err != nil {
		result = diagnostics.ResultError
		diagnostics.RecordError(span, err)
		diagnostics.OperationFailed(ctx, c.logger, operation, err)
	}
	diagnostics.CacheOperations().Add(ctx, 1, metric.WithAttributes(
		diagnostics.AttrOperationName.String(operation), diagnostics.AttrResult.String(result)))
	return err
}

// Decrypt decrypts the value stored under name into result and returns the number of bytes
// written, or 0 (and a nil error) if nothing is stored under name. Size result with
// MaxDecryptedLength.
func (c *Cache) Decrypt(ctx context.Context, name string, result []byte) (int, error) {
	return c.store.decrypt(ctx, name, result)
}

// MaxDecryptedLength is an upper bound on how many bytes Decrypt will write for name; ok is false
// if nothing is stored under it.
func (c *Cache) MaxDecryptedLength(ctx context.Context, name string) (int, bool, error) {
	return c.store.maxDecryptedLength(ctx, name)
}

// ReadOnlyCache is a hkdfguard.ProtectedReadOnlyCache filled only from its Source: each name is
// fetched the first time it is asked for, encrypted, and served from the cache after that. It is
// the building block for caches backed by an external secret store - the backend implements
// Source, and encryption, name binding and telemetry stay here. Safe for concurrent use.
type ReadOnlyCache struct {
	store store
}

var _ hkdfguard.ProtectedReadOnlyCache = (*ReadOnlyCache)(nil)

// NewReadOnly returns a ReadOnlyCache that encrypts through ring what source supplies.
func NewReadOnly(ring hkdfguard.KeyRing, source Source) *ReadOnlyCache {
	return &ReadOnlyCache{store: store{ring: ring, source: source}}
}

// Decrypt decrypts the value for name into result - fetching it from the Source first if it isn't
// cached yet - and returns the number of bytes written, or 0 if neither has it.
func (c *ReadOnlyCache) Decrypt(ctx context.Context, name string, result []byte) (int, error) {
	return c.store.decrypt(ctx, name, result)
}

// MaxDecryptedLength is an upper bound on how many bytes Decrypt will write for name, fetching it
// from the Source first if needed; ok is false if neither has it.
func (c *ReadOnlyCache) MaxDecryptedLength(ctx context.Context, name string) (int, bool, error) {
	return c.store.maxDecryptedLength(ctx, name)
}
