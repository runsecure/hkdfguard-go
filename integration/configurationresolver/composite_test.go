package configurationresolver

import (
	"context"
	"errors"
	"slices"
	"testing"
)

// The port of .NET's CompositeValueProviderTests. TryGetChar's test is TryGetBytes's here.

func newCompositeTestProviders() (high, low *spyValueProvider) {
	high = newSpyValueProvider(map[string]string{"Shared": "high", "HighOnly": "h"})
	low = newSpyValueProvider(map[string]string{"Shared": "low", "LowOnly": "lö"})
	return high, low
}

func mustComposite(t testing.TB, providers ...ValueProvider) *CompositeValueProvider {
	t.Helper()
	composite, err := NewCompositeValueProvider(providers...)
	if err != nil {
		t.Fatalf("NewCompositeValueProvider: %v", err)
	}
	return composite
}

func TestCompositeTryGetValue_ReturnsTheValueFromTheFirstProviderThatHasTheKey(t *testing.T) {
	high, low := newCompositeTestProviders()
	provider := mustComposite(t, high, low)
	ctx := context.Background()

	shared, sharedStatus, sharedErr := provider.TryGetValue(ctx, "Shared")
	lowOnly, lowStatus, lowErr := provider.TryGetValue(ctx, "LowOnly")
	missing, missingStatus, missingErr := provider.TryGetValue(ctx, "Missing")

	if shared != "high" || sharedStatus != Found || sharedErr != nil {
		t.Errorf("Shared = %q, %v, %v; want high, Found", shared, sharedStatus, sharedErr)
	}
	if lowOnly != "lö" || lowStatus != Found || lowErr != nil {
		t.Errorf("LowOnly = %q, %v, %v; want lö, Found", lowOnly, lowStatus, lowErr)
	}
	if missing != "" || missingStatus != NotFound || missingErr != nil {
		t.Errorf("Missing = %q, %v, %v; want \"\", NotFound", missing, missingStatus, missingErr)
	}
	if want := []string{"Shared", "LowOnly", "Missing"}; !slices.Equal(high.tryGetValueCalls, want) {
		t.Errorf("high calls = %q, want %q", high.tryGetValueCalls, want)
	}
	if want := []string{"LowOnly", "Missing"}; !slices.Equal(low.tryGetValueCalls, want) {
		t.Errorf("low calls = %q, want %q", low.tryGetValueCalls, want)
	}
}

func TestCompositeTryGetBytes_WritesTheValueFromTheFirstProviderThatHasTheKey(t *testing.T) {
	high, low := newCompositeTestProviders()
	provider := mustComposite(t, high, low)
	ctx := context.Background()
	destination := make([]byte, 8)

	written, status, err := provider.TryGetBytes(ctx, "Shared", destination)
	if status != Found || err != nil || string(destination[:written]) != "high" {
		t.Errorf("Shared = %q, %v, %v; want high, Found", destination[:written], status, err)
	}
	written, status, err = provider.TryGetBytes(ctx, "LowOnly", destination)
	if status != Found || err != nil || string(destination[:written]) != "lö" {
		t.Errorf("LowOnly = %q, %v, %v; want lö, Found", destination[:written], status, err)
	}
	written, status, err = provider.TryGetBytes(ctx, "Missing", destination)
	if status != NotFound || err != nil || written != 0 {
		t.Errorf("Missing = %d, %v, %v; want 0, NotFound", written, status, err)
	}
	if want := []string{"LowOnly", "Missing"}; !slices.Equal(low.tryGetBytesCalls, want) {
		t.Errorf("low calls = %q, want %q", low.tryGetBytesCalls, want)
	}
}

func TestComposite_DestinationTooSmallInTheFirstProvider_DoesNotFallThrough(t *testing.T) {
	high, low := newCompositeTestProviders()
	provider := mustComposite(t, high, low)

	written, status, err := provider.TryGetBytes(context.Background(), "Shared", make([]byte, 2))

	if status != DestinationTooSmall || err != nil || written != 0 {
		t.Errorf("TryGetBytes = %d, %v, %v; want 0, DestinationTooSmall", written, status, err)
	}
	if len(low.tryGetBytesCalls) != 0 {
		t.Errorf("low calls = %q, want none", low.tryGetBytesCalls)
	}
}

func TestComposite_ProviderError_Propagates(t *testing.T) {
	_, low := newCompositeTestProviders()
	failing := newSpyValueProvider(map[string]string{})
	failing.err = &ConfigurationKeyError{Key: "Shared", Code: KeyValueUnstable}
	provider := mustComposite(t, failing, low)

	_, _, err := provider.TryGetBytes(context.Background(), "Shared", make([]byte, 8))

	var keyErr *ConfigurationKeyError
	if !errors.As(err, &keyErr) || keyErr.Code != KeyValueUnstable {
		t.Errorf("err = %v, want the provider's ValueUnstable error", err)
	}
	if len(low.tryGetBytesCalls) != 0 {
		t.Errorf("low calls = %q, want none", low.tryGetBytesCalls)
	}
}

func TestComposite_Providers_AreInPriorityOrderAndCopied(t *testing.T) {
	high, low := newCompositeTestProviders()
	list := []ValueProvider{high, low}
	provider := mustComposite(t, list...)

	list[0], list[1] = nil, nil
	got := provider.Providers()
	if len(got) != 2 || got[0] != ValueProvider(high) || got[1] != ValueProvider(low) {
		t.Fatalf("Providers() = %v, want [high low]", got)
	}

	// Nor does changing what Providers returns change the composite.
	got[0] = nil
	if again := provider.Providers(); again[0] != ValueProvider(high) {
		t.Errorf("Providers()[0] = %v after changing a returned slice, want high", again[0])
	}
}

func TestComposite_Constructor_InvalidProviders_Fails(t *testing.T) {
	high, _ := newCompositeTestProviders()

	tests := map[string][]ValueProvider{
		"nil slice":   nil,
		"empty":       {},
		"holding nil": {high, nil},
	}
	for name, providers := range tests {
		if composite, err := NewCompositeValueProvider(providers...); err == nil || composite != nil {
			t.Errorf("%s: NewCompositeValueProvider = %v, %v; want an error", name, composite, err)
		}
	}
}
