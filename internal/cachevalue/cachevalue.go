// Package cachevalue is what the secret caches share about the values they hold: decrypting an
// hkdfguard.KeyTrackingValue bound to its name, authenticating one before it is kept, and counting
// cache populates.
package cachevalue

import (
	"context"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/diagnostics"
	"go.opentelemetry.io/otel/metric"
)

// Decrypt decrypts value - stored under name - into result with ring's key for the value's key
// version, and returns how many bytes it wrote. It fails as ring.Get does when the ring doesn't hold
// that version, and as the key's Decrypt does when value wasn't encrypted for name.
func Decrypt(ctx context.Context, ring hkdfguard.KeyRing, name string, value *hkdfguard.KeyTrackingValue, result []byte) (int, error) {
	aad, err := hkdfguard.ConfigurationAAD(name)
	if err != nil {
		return 0, err
	}
	key, err := ring.Get(ctx, value.KeyVersion)
	if err != nil {
		return 0, err
	}
	return key.Decrypt(ctx, value.Value, aad, result)
}

// Authenticate decrypts value once into a buffer that is zeroed at once, so a cache keeps only a
// value that authenticates under name - and under a key version the ring holds. AEAD ciphertext is
// always at least as long as its plaintext, so the ciphertext's length is room enough.
func Authenticate(ctx context.Context, ring hkdfguard.KeyRing, name string, value *hkdfguard.KeyTrackingValue) error {
	plaintext := make([]byte, len(value.Value))
	defer hkdfguard.Wipe(plaintext)
	_, err := Decrypt(ctx, ring, name, value, plaintext)
	return err
}

// RecordPopulate counts one cache populate, with its result (a diagnostics.Result* value).
func RecordPopulate(ctx context.Context, result string) {
	diagnostics.CacheOperations().Add(ctx, 1, metric.WithAttributes(
		diagnostics.AttrOperationName.String(diagnostics.SpanCachePopulate), diagnostics.AttrResult.String(result)))
}
