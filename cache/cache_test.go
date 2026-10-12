package cache

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/diagnostics"
	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func TestAddDecrypt_RoundTrips(t *testing.T) {
	c := newCache(t)
	mustAdd(t, c, "plain", "hello")
	mustAdd(t, c, "multibyte", "héllo wörld ✓ 🔐")

	for name, want := range map[string]string{"plain": "hello", "multibyte": "héllo wörld ✓ 🔐"} {
		if got, ok := get(t, c, name); !ok || got != want {
			t.Errorf("%s = %q, %v", name, got, ok)
		}
	}
}

func TestAdd_ZeroesThePlaintext_OnSuccessAndFailure(t *testing.T) {
	c := newCache(t)
	ok := []byte("secret")
	_ = c.Add(bg, "item", ok)
	duplicate := []byte("secret")
	_ = c.Add(bg, "item", duplicate)
	badName := []byte("secret")
	_ = c.Add(bg, "bad\xffname", badName)

	for name, b := range map[string][]byte{"success": ok, "duplicate": duplicate, "invalid name": badName} {
		if !hkdfguard.IsZero(b) {
			t.Errorf("%s: plaintext left as %q", name, b)
		}
	}
}

func TestAdd_ADuplicateName_InAnyASCIICase_IsRefused_AndKeepsTheFirstValue(t *testing.T) {
	c := newCache(t)
	mustAdd(t, c, "Item", "first")

	for _, name := range []string{"Item", "ITEM", "item"} {
		if err := c.Add(bg, name, []byte("second")); !errors.Is(err, hkdfguard.ErrAlreadyExists) {
			t.Errorf("Add(%q): %v", name, err)
		}
	}
	if got, _ := get(t, c, "item"); got != "first" {
		t.Errorf("value = %q", got)
	}
}

func TestAddOrUpdate_ReplacesAnyValue(t *testing.T) {
	c := newCache(t)
	mustAdd(t, c, "item", "first")

	if err := c.AddOrUpdate(bg, "ITEM", []byte("second")); err != nil {
		t.Fatal(err)
	}
	if err := c.AddOrUpdate(bg, "new", []byte("fresh")); err != nil {
		t.Fatal(err)
	}
	if got, _ := get(t, c, "Item"); got != "second" {
		t.Errorf("item = %q", got)
	}
	if got, _ := get(t, c, "new"); got != "fresh" {
		t.Errorf("new = %q", got)
	}
}

func TestNames_IgnoreOnlyASCIICase(t *testing.T) {
	c := newCache(t)
	mustAdd(t, c, "Api-Key_1", "ascii")
	mustAdd(t, c, "café", "lower")
	mustAdd(t, c, "CAFÉ", "upper")

	if got, ok := get(t, c, "api-key_1"); !ok || got != "ascii" {
		t.Errorf("ASCII variant = %q, %v", got, ok)
	}
	if lower, _ := get(t, c, "café"); lower != "lower" {
		t.Errorf("café = %q", lower)
	}
	if upper, _ := get(t, c, "CAFÉ"); upper != "upper" {
		t.Errorf("CAFÉ = %q", upper)
	}
}

func TestAMissingName_DecryptsToZero_AndHasNoLength(t *testing.T) {
	c := newCache(t)

	if n, err := c.Decrypt(bg, "missing", make([]byte, 8)); n != 0 || err != nil {
		t.Errorf("Decrypt = %d, %v", n, err)
	}
	if _, ok, err := c.MaxDecryptedLength(bg, "missing"); ok || err != nil {
		t.Errorf("MaxDecryptedLength ok = %v, %v", ok, err)
	}
}

func TestMaxDecryptedLength_IsASafeUpperBound(t *testing.T) {
	c := newCache(t)
	mustAdd(t, c, "item", "hello")

	n, ok, _ := c.MaxDecryptedLength(bg, "item")
	if !ok || n < len("hello") {
		t.Errorf("MaxDecryptedLength = %d, %v", n, ok)
	}
}

func TestDecrypt_IntoATooSmallBuffer_Fails(t *testing.T) {
	c := newCache(t)
	mustAdd(t, c, "item", "hello")

	if _, err := c.Decrypt(bg, "item", make([]byte, 2)); err == nil {
		t.Error("Decrypt into 2 bytes succeeded")
	}
}

func TestAnEmptyValueOrInvalidName_IsRefused_AndStoresNothing(t *testing.T) {
	c := newCache(t)

	if err := c.Add(bg, "empty", nil); !errors.Is(err, ErrEmptyValue) {
		t.Errorf("Add empty: %v", err)
	}
	if err := c.AddOrUpdate(bg, "empty", []byte{}); !errors.Is(err, ErrEmptyValue) {
		t.Errorf("AddOrUpdate empty: %v", err)
	}
	if err := c.Add(bg, "bad\xed\xa0\x80name", []byte("value")); !errors.Is(err, hkdfguard.ErrInvalidCacheName) {
		t.Errorf("Add invalid name: %v", err)
	}
	for _, name := range []string{"empty", "bad\xed\xa0\x80name"} {
		if _, ok := get(t, c, name); ok {
			t.Errorf("%q was stored", name)
		}
	}
}

func TestALargeValue_RoundTrips(t *testing.T) {
	c := newCache(t)
	large := strings.Repeat("x", 2<<20)

	if err := c.AddOrUpdate(bg, "large", []byte(large)); err != nil {
		t.Fatal(err)
	}
	if got, _ := get(t, c, "large"); got != large {
		t.Errorf("got %d bytes", len(got))
	}
}

func TestConcurrentAddsAndDecrypts_AcrossManyNames_AllRoundTrip(t *testing.T) {
	c := newCache(t)
	var wg sync.WaitGroup
	for i := range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			name, value := fmt.Sprintf("item-%d", i), fmt.Sprintf("value-%d", i)
			if err := c.Add(bg, name, []byte(value)); err != nil {
				t.Error(err)
				return
			}
			if got, _ := get(t, c, name); got != value {
				t.Errorf("%s = %q", name, got)
			}
		}()
	}
	wg.Wait()
}

func TestConcurrentAddsOfOneName_ExactlyOneSucceeds(t *testing.T) {
	c := newCache(t)
	var succeeded atomic.Int32
	var wg sync.WaitGroup
	for i := range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.Add(bg, "contended", []byte(fmt.Sprint(i))); err == nil {
				succeeded.Add(1)
			} else if !errors.Is(err, hkdfguard.ErrAlreadyExists) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()

	if succeeded.Load() != 1 {
		t.Errorf("%d Adds succeeded", succeeded.Load())
	}
}

// --- Name binding ---------------------------------------------------------------------------

func TestEveryValue_IsEncryptedAndDecryptedWithItsNamesAAD(t *testing.T) {
	ring, keys := newRing(t, 1)
	c := New(ring)
	mustAdd(t, c, "Item", "value")
	get(t, c, "ITEM")
	get(t, c, "item")

	want, _ := hkdfguard.CacheAAD("Item")
	key := keys[1]
	if len(key.encryptAADs) != 1 || !bytes.Equal(key.encryptAADs[0], want) {
		t.Errorf("encrypt AADs = %q", key.encryptAADs)
	}
	for _, aad := range key.decryptAADs {
		if !bytes.Equal(aad, want) {
			t.Errorf("decrypt AAD = %q, want %q", aad, want)
		}
	}
}

func TestACiphertextMovedUnderAnotherName_FailsAuthentication_AndTheOriginalStillDecrypts(t *testing.T) {
	c := newCache(t)
	mustAdd(t, c, "admin", "admin-secret")
	mustAdd(t, c, "reporting", "reporting-secret")

	// What a bug in a store, or an attacker who can swap entries, would do.
	adminEntry, _ := c.store.entries.Load(matchKey("admin"))
	c.store.entries.Store(matchKey("reporting"), adminEntry)

	if _, err := c.Decrypt(bg, "reporting", make([]byte, 64)); !errors.Is(err, hkdfguard.ErrAuthenticationFailed) {
		t.Errorf("moved value: %v", err)
	}
	if got, _ := get(t, c, "admin"); got != "admin-secret" {
		t.Errorf("admin = %q", got)
	}
}

// --- Key rotation ---------------------------------------------------------------------------

func TestValuesStoredBeforeAndAfterARotation_UseTheirOwnKeys_AndAllDecrypt(t *testing.T) {
	ring, keys := newRing(t, 1)
	c := New(ring)
	mustAdd(t, c, "before", "old")

	keys[2] = newRecordingKey(t)
	_ = ring.Add(bg, 2, keys[2])
	mustAdd(t, c, "after", "new")

	if len(keys[1].encryptAADs) != 1 || len(keys[2].encryptAADs) != 1 {
		t.Errorf("v1 encrypted %d values, v2 %d", len(keys[1].encryptAADs), len(keys[2].encryptAADs))
	}
	if before, _ := get(t, c, "before"); before != "old" {
		t.Errorf("before = %q", before)
	}
	if after, _ := get(t, c, "after"); after != "new" {
		t.Errorf("after = %q", after)
	}
}

func TestAddOrUpdate_AfterARotation_ReEncryptsUnderTheNewKey(t *testing.T) {
	ring, _ := newRing(t, 1)
	c := New(ring)
	mustAdd(t, c, "item", "old")
	_ = ring.Add(bg, 2, newRecordingKey(t))

	_ = c.AddOrUpdate(bg, "item", []byte("new"))

	entry, _ := c.store.entries.Load(matchKey("item"))
	if version := entry.(*hkdfguard.KeyTrackingValue).KeyVersion; version != 2 {
		t.Errorf("entry version = %d", version)
	}
}

func TestAnEntryWhoseVersionWasSwappedOrRemoved_Fails(t *testing.T) {
	ring, _ := newRing(t, 1, 2)
	c := New(ring)
	mustAdd(t, c, "item", "value")
	entry, _ := c.store.entries.Load(matchKey("item"))

	swapped := *entry.(*hkdfguard.KeyTrackingValue)
	swapped.KeyVersion = 1
	c.store.entries.Store(matchKey("item"), &swapped)
	if _, err := c.Decrypt(bg, "item", make([]byte, 64)); !errors.Is(err, hkdfguard.ErrAuthenticationFailed) {
		t.Errorf("swapped version: %v", err)
	}

	swapped.KeyVersion = 9
	if _, err := c.Decrypt(bg, "item", make([]byte, 64)); !errors.Is(err, hkdfguard.ErrKeyNotFound) {
		t.Errorf("missing version: %v", err)
	}
}

// --- Telemetry ------------------------------------------------------------------------------

func withSensitiveLogging(t *testing.T) {
	t.Helper()
	original := diagnostics.Cache.SensitiveLoggingEnabled()
	diagnostics.Cache.SetSensitiveLogging(true)
	t.Cleanup(func() { diagnostics.Cache.SetSensitiveLogging(original) })
}

func TestTheLogger_RecordsSensitiveOperations_AndEveryFailure(t *testing.T) {
	withSensitiveLogging(t)
	logger, logs := newLogger()
	c := newCache(t, WithLogger(logger))

	mustAdd(t, c, "item", "value")
	_ = c.Add(bg, "item", []byte("duplicate"))
	_ = c.AddOrUpdate(bg, "empty", nil)

	if len(logs.withEventID(1)) != 3 {
		t.Errorf("%d sensitive operations logged", len(logs.withEventID(1)))
	}
	if failures := logs.withEventID(2); len(failures) != 2 || !strings.Contains(failures[0].Message, "hkdfguard.cache.add failed.") {
		t.Errorf("%d failures logged", len(failures))
	}
	if got, _ := get(t, c, "item"); got != "value" {
		t.Errorf("round trip with sensitive logging = %q", got)
	}
}

func TestOperations_AreCountedBySuccessAndFailure(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	otel.SetMeterProvider(provider)
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })

	c := newCache(t)
	mustAdd(t, c, "item", "value")
	_ = c.Add(bg, "item", []byte("duplicate"))
	_ = c.AddOrUpdate(bg, "item", []byte("update"))

	var collected metricdata.ResourceMetrics
	_ = reader.Collect(context.Background(), &collected)
	counts := map[string]int64{}
	for _, scope := range collected.ScopeMetrics {
		for _, m := range scope.Metrics {
			for _, point := range m.Data.(metricdata.Sum[int64]).DataPoints {
				op, _ := point.Attributes.Value(diagnostics.AttrOperationName)
				result, _ := point.Attributes.Value(diagnostics.AttrResult)
				counts[op.AsString()+"/"+result.AsString()] += point.Value
			}
		}
	}

	want := map[string]int64{"hkdfguard.cache.add/success": 1, "hkdfguard.cache.add/error": 1, "hkdfguard.cache.add_or_update/success": 1}
	for k, v := range want {
		if counts[k] != v {
			t.Errorf("%s = %d, want %d (all: %v)", k, counts[k], v, counts)
		}
	}
}
