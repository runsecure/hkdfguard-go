package configurationresolver_test

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/cache"
	"github.com/runsecure/hkdfguard-go/dek"
	"github.com/runsecure/hkdfguard-go/integration/configurationresolver"
)

// exampleKey is a stand-in AES-256-GCM key for the examples; an application's ring comes from
// dek.Build.
type exampleKey struct{ aead cipher.AEAD }

func (k exampleKey) Encrypt(_ context.Context, plaintext, aad []byte) ([]byte, error) {
	defer hkdfguard.Wipe(plaintext)
	return k.aead.Seal(nil, nil, plaintext, aad), nil
}

func (k exampleKey) Decrypt(_ context.Context, ciphertext, aad, result []byte) (int, error) {
	out, err := k.aead.Open(result[:0], nil, ciphertext, aad)
	if err != nil {
		return 0, hkdfguard.ErrAuthenticationFailed
	}
	return len(out), nil
}

func exampleRing() *dek.KeyRing {
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	block, _ := aes.NewCipher(secret)
	aead, _ := cipher.NewGCMWithRandomNonce(block)
	ring := dek.NewKeyRing(nil)
	_ = ring.Add(context.Background(), 1, exampleKey{aead: aead})
	return ring
}

// settings is a provider of values that aren't secret, for templates' items.
type settings map[string]string

func (s settings) TryGetBytes(_ context.Context, key string, destination []byte) (int, configurationresolver.ValueStatus, error) {
	value, ok := s[key]
	switch {
	case !ok:
		return 0, configurationresolver.NotFound, nil
	case len(value) > len(destination):
		return 0, configurationresolver.DestinationTooSmall, nil
	}
	return copy(destination, value), configurationresolver.Found, nil
}

func (s settings) TryGetByteCount(_ context.Context, key string) (int, bool, error) {
	value, ok := s[key]
	return len(value), ok, nil
}

// Resolves a template's items from a protected cache.
func ExampleConfigurationResolverBuilder() {
	ctx := context.Background()
	ring := exampleRing()
	defer ring.Close()
	secrets := cache.New(ring)
	_ = secrets.Add(ctx, "app-config#user", []byte("app"))
	_ = secrets.Add(ctx, "app-config#password", []byte("s3cret"))

	template := "Host=db.internal;Username=${app-config#user};Password=${app-config#password}"

	token := configurationresolver.NewDefaultToken()
	reader, _ := configurationresolver.NewConfigurationItemReader(token)
	reader.ReadKeysString(template)

	resolver, err := configurationresolver.NewConfigurationResolverBuilder().
		WithToken(token).
		WithReader(reader).
		AddProtectedCache(secrets).
		Build()
	if err != nil {
		panic(err)
	}

	connectionString := make([]byte, 1024)
	defer hkdfguard.Wipe(connectionString)
	n, err := resolver.Resolve(ctx, []byte(template), connectionString)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(connectionString[:n])) // printed only to show the result
	// Output: Host=db.internal;Username=app;Password=s3cret
}

// Keeps a template in a cache itself: the collection resolves it on lookup.
func ExampleResolvingProtectedCacheCollection() {
	ctx := context.Background()
	ring := exampleRing()
	defer ring.Close()
	local := cache.New(ring)
	_ = local.Add(ctx, "orders.connection-string", []byte("Host=${db-host};Password=${db-password}"))
	_ = local.Add(ctx, "db-password", []byte("s3cret"))

	secrets, err := configurationresolver.NewResolvingProtectedCacheCollection(ring, configurationresolver.ResolvingOptions{})
	if err != nil {
		panic(err)
	}
	secrets.Add(local).
		AddValueProvider(configurationresolver.ValueProviderBase{ByteValueProvider: settings{"db-host": "db.internal"}})

	maxLength, _, err := secrets.MaxDecryptedLength(ctx, "orders.connection-string")
	if err != nil {
		panic(err)
	}
	connectionString := make([]byte, maxLength)
	defer hkdfguard.Wipe(connectionString)
	n, err := secrets.Decrypt(ctx, "orders.connection-string", connectionString)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(connectionString[:n])) // printed only to show the result
	// Output: Host=db.internal;Password=s3cret
}
