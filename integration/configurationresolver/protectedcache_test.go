package configurationresolver

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/runsecure/hkdfguard-go"
)

func TestProtectedCache_Resolve_ReplacesItemsWithCachedValues(t *testing.T) {
	secrets := newCache(t, "db-user", "app", "db-password", "pässword")
	template := "User=${db-user};Password=${db-password}"

	destination := make([]byte, 256)
	written, err := templateResolver(t, template, cacheProvider(t, secrets)).Resolve(bg, []byte(template), destination)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(destination[:written]); got != "User=app;Password=pässword" {
		t.Errorf("resolved %q", got)
	}
}

func TestProtectedCache_Resolve_MissingName_FailsNotFound(t *testing.T) {
	secrets := newCache(t, "present", "value")
	template := "${absent}"

	_, err := templateResolver(t, template, cacheProvider(t, secrets)).Resolve(bg, []byte(template), make([]byte, 64))

	var keyErr *ConfigurationKeyError
	if !errors.As(err, &keyErr) || keyErr.Code != KeyNotFound {
		t.Fatalf("err = %v, want KeyNotFound", err)
	}
}

// The cache's bound is the ciphertext's length, so a destination with exactly the value's room is
// below it: the value goes through a scratch buffer.
func TestProtectedCache_Resolve_DestinationBelowBoundButValueFits_Resolves(t *testing.T) {
	for _, valueLength := range []int{5, 612} {
		value := strings.Repeat("v", valueLength)

		destination := make([]byte, valueLength)
		written, err := templateResolver(t, "${item}", cacheProvider(t, newCache(t, "item", value))).Resolve(bg, []byte("${item}"), destination)
		if err != nil {
			t.Fatalf("%d bytes: %v", valueLength, err)
		}
		if got := string(destination[:written]); got != value {
			t.Errorf("%d bytes: resolved %d bytes", valueLength, len(got))
		}
	}
}

func TestProtectedCache_Resolve_ValueLargerThanDestination_FailsAndWipesDestination(t *testing.T) {
	destination := []byte("XXXX")

	_, err := templateResolver(t, "${item}", cacheProvider(t, newCache(t, "item", "too long a value"))).Resolve(bg, []byte("${item}"), destination)

	if !errors.Is(err, ErrDestinationTooSmall) {
		t.Fatalf("err = %v, want ErrDestinationTooSmall", err)
	}
	if !hkdfguard.IsZero(destination) {
		t.Errorf("destination not wiped: %q", destination)
	}
}

func TestProtectedCache_TryGetBytes_WritesAtTheStartOfDestination(t *testing.T) {
	provider := cacheProvider(t, newCache(t, "item", "value"))
	destination := make([]byte, 64)

	written, status, err := provider.TryGetBytes(bg, "item", destination)

	if err != nil || status != Found || string(destination[:written]) != "value" {
		t.Errorf("TryGetBytes = %d, %v, %v (%q)", written, status, err, destination[:written])
	}
}

func TestProtectedCache_TryGetBytes_ValueLargerThanTheRoom_IsTooSmall_AndWritesNothing(t *testing.T) {
	provider := cacheProvider(t, newCache(t, "item", "value"))
	destination := make([]byte, 4)

	written, status, err := provider.TryGetBytes(bg, "item", destination)

	if err != nil || status != DestinationTooSmall || written != 0 {
		t.Errorf("TryGetBytes = %d, %v, %v", written, status, err)
	}
	if !hkdfguard.IsZero(destination) {
		t.Errorf("destination written: %q", destination)
	}
}

func TestProtectedCache_TryGetBytes_ACacheError_IsReturned_AndResolveWipes(t *testing.T) {
	refused := errors.New("access denied")
	provider := cacheProvider(t, failingSource{err: refused})

	if _, _, err := provider.TryGetBytes(bg, "item", make([]byte, 16)); !errors.Is(err, refused) {
		t.Errorf("TryGetBytes err = %v", err)
	}

	destination := []byte("XXXXXXXXXXXXXXXX")
	_, err := templateResolver(t, "a${item}", provider).Resolve(bg, []byte("a${item}"), destination)
	if !errors.Is(err, refused) {
		t.Errorf("Resolve err = %v", err)
	}
	if !hkdfguard.IsZero(destination) {
		t.Errorf("destination not wiped: %q", destination)
	}
}

func TestProtectedCache_TryGetValue_ByDefault_Fails(t *testing.T) {
	provider := cacheProvider(t, newCache(t, "item", "value"))

	if provider.AllowStringValues() {
		t.Error("AllowStringValues is set by default")
	}
	if _, _, err := provider.TryGetValue(bg, "item"); !errors.Is(err, ErrStringValuesNotAllowed) {
		t.Errorf("err = %v, want ErrStringValuesNotAllowed", err)
	}
}

func TestProtectedCache_TryGetValue_WhenAllowed_ReturnsTheValueAsAString(t *testing.T) {
	original := cacheProvider(t, newCache(t, "item", "value"))
	provider := original.WithAllowStringValues(true)

	if !provider.AllowStringValues() || original.AllowStringValues() {
		t.Error("WithAllowStringValues didn't return a changed copy")
	}
	if value, status, err := provider.TryGetValue(bg, "item"); err != nil || status != Found || value != "value" {
		t.Errorf("TryGetValue(item) = %q, %v, %v", value, status, err)
	}
	if value, status, err := provider.TryGetValue(bg, "absent"); err != nil || status != NotFound || value != "" {
		t.Errorf("TryGetValue(absent) = %q, %v, %v", value, status, err)
	}
}

func TestProtectedCache_CompositeValueProvider_FallsThroughToTheNextProviderForMissingNames(t *testing.T) {
	secrets := newCache(t, "db-password", "s3cret")
	template := "Host=${db-host};Password=${db-password}"

	resolver := templateResolver(t, template, cacheProvider(t, secrets), newSettingsProvider("db-host", "db.internal"))
	destination := make([]byte, 256)
	written, err := resolver.Resolve(bg, []byte(template), destination)

	if err != nil || string(destination[:written]) != "Host=db.internal;Password=s3cret" {
		t.Errorf("resolved %q, %v", destination[:written], err)
	}
}

func TestProtectedCache_AddProtectedCache_AddsAProviderOverTheCache(t *testing.T) {
	secrets := newCache(t, "db-password", "s3cret")
	template := "Password=${db-password}"
	token := NewDefaultToken()
	reader, _ := NewConfigurationItemReader(token)
	reader.ReadKeysString(template)

	resolver, err := NewConfigurationResolverBuilder().
		WithToken(token).
		WithReader(reader).
		AddProtectedCache(secrets).
		Build()
	if err != nil {
		t.Fatal(err)
	}

	destination := make([]byte, 64)
	written, err := resolver.Resolve(bg, []byte(template), destination)
	if err != nil || string(destination[:written]) != "Password=s3cret" {
		t.Errorf("resolved %q, %v", destination[:written], err)
	}
}

func TestProtectedCache_Prefetch_FetchesEachSecretOnce_SoResolveDoesNotFetch(t *testing.T) {
	remote, store := newRemote(t, "app-config", `{"user":"app","password":"s3cret"}`)
	template := "User=${app-config#user};Password=${app-config#password};Again=${app-config#user}"
	token := NewDefaultToken()
	reader, _ := NewConfigurationItemReader(token)
	reader.ReadKeysString(template)
	provider := cacheProvider(t, remote)

	if err := provider.Prefetch(bg, reader); err != nil {
		t.Fatal(err)
	}
	if got := store.fetched(); !slices.Equal(got, []string{"app-config"}) {
		t.Fatalf("prefetch fetched %v", got)
	}

	resolver, _ := NewConfigurationItemResolver(token, reader, provider)
	destination := make([]byte, 256)
	written, err := resolver.Resolve(bg, []byte(template), destination)

	if err != nil || string(destination[:written]) != "User=app;Password=s3cret;Again=app" {
		t.Errorf("resolved %q, %v", destination[:written], err)
	}
	if got := store.fetched(); len(got) != 1 {
		t.Errorf("Resolve fetched again: %v", got)
	}
}

func TestProtectedCache_PrefetchKeys_SkipsKeysTheCacheDoesNotHave(t *testing.T) {
	remote, store := newRemote(t, "present", "value")
	provider := cacheProvider(t, remote)

	if err := provider.PrefetchKeys(bg, []string{"present", "absent", "absent"}); err != nil {
		t.Fatal(err)
	}

	if got := store.fetched(); !slices.Equal(got, []string{"present", "absent"}) {
		t.Errorf("fetched %v, want [present absent]", got)
	}
	if written, status, err := provider.TryGetBytes(bg, "absent", make([]byte, 16)); err != nil || status != NotFound || written != 0 {
		t.Errorf("TryGetBytes(absent) = %d, %v, %v", written, status, err)
	}
}

func TestProtectedCache_Prefetch_CancelledContext_Fails(t *testing.T) {
	remote, _ := newRemote(t)
	provider := cacheProvider(t, remote)
	ctx, cancel := context.WithCancel(bg)
	cancel()

	if err := provider.PrefetchKeys(ctx, []string{"item"}); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestProtectedCache_Members_RejectNilArguments(t *testing.T) {
	secrets := newCache(t)
	provider := cacheProvider(t, secrets)

	if provider.Cache() != secrets {
		t.Error("Cache() isn't the cache given")
	}
	if _, err := NewProtectedCacheValueProvider(nil); err == nil {
		t.Error("NewProtectedCacheValueProvider(nil) succeeded")
	}
	if err := provider.Prefetch(bg, nil); err == nil {
		t.Error("Prefetch(nil) succeeded")
	}
	reader, _ := NewConfigurationItemReader(NewDefaultToken())
	if _, err := NewConfigurationResolverBuilder().WithReader(reader).AddProtectedCache(nil).Build(); err == nil {
		t.Error("AddProtectedCache(nil) built")
	}
}
