package configurationresolver

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/diagnostics"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func newCollection(t *testing.T, options ResolvingOptions) *ResolvingProtectedCacheCollection {
	t.Helper()
	collection, err := NewResolvingProtectedCacheCollection(newRing(t), options)
	if err != nil {
		t.Fatal(err)
	}
	return collection
}

// newConnCollection returns a collection over one source holding the template "conn" and the two
// values it names.
func newConnCollection(t *testing.T) (*ResolvingProtectedCacheCollection, *plainSource) {
	t.Helper()
	source := newPlainSource(
		"conn", "Host=${host};Password=${password}",
		"host", "db.internal",
		"password", "s3cret")
	return newCollection(t, ResolvingOptions{}).Add(source), source
}

func wantConfigurationKeyError(t *testing.T, err error, code ConfigurationKeyErrorCode) {
	t.Helper()
	var keyErr *ConfigurationKeyError
	if !errors.As(err, &keyErr) || keyErr.Code != code {
		t.Fatalf("err = %v, want a ConfigurationKeyError with %v", err, code)
	}
}

func TestCollection_Template_IsResolvedFromTheSources_AndCached(t *testing.T) {
	collection, source := newConnCollection(t)

	for range 2 {
		if got := decryptString(t, collection, "conn"); got != "Host=db.internal;Password=s3cret" {
			t.Errorf("conn = %q", got)
		}
	}

	// Read and resolved once; every later lookup decrypts the kept result.
	if source.decryptCount("conn") != 1 || source.decryptCount("password") != 1 {
		t.Errorf("conn read %d times, password %d times", source.decryptCount("conn"), source.decryptCount("password"))
	}
}

func TestCollection_Template_IsResolvedByAFirstDecrypt_WithoutSizingFirst(t *testing.T) {
	collection, _ := newConnCollection(t)

	result := make([]byte, 64)
	n, err := collection.Decrypt(bg, "conn", result)
	if err != nil || string(result[:n]) != "Host=db.internal;Password=s3cret" {
		t.Errorf("Decrypt = %q, %v", result[:n], err)
	}
}

func TestCollection_ResolvedValue_IsKeptEncrypted_NotAsTheSourcesValues(t *testing.T) {
	collection, _ := newConnCollection(t)

	maxLength, ok, err := collection.MaxDecryptedLength(bg, "conn")

	// An AEAD bound: longer than the 32-byte resolved value it encloses.
	if err != nil || !ok || maxLength <= len("Host=db.internal;Password=s3cret") {
		t.Errorf("MaxDecryptedLength = %d, %v, %v", maxLength, ok, err)
	}
}

func TestCollection_ValueWithoutItems_IsAnsweredByItsSource_WhichIsRemembered(t *testing.T) {
	collection, source := newConnCollection(t)

	for range 2 {
		if got := decryptString(t, collection, "password"); got != "s3cret" {
			t.Errorf("password = %q", got)
		}
	}

	// One search through the sources, then only the lookups the remembered source answers.
	if source.lengthLookupCount("password") != 3 || source.decryptCount("password") != 3 {
		t.Errorf("%d length lookups, %d decrypts; want 3 and 3", source.lengthLookupCount("password"), source.decryptCount("password"))
	}
}

func TestCollection_MissingName_IsReportedMissing(t *testing.T) {
	collection, _ := newConnCollection(t)

	if n, err := collection.Decrypt(bg, "absent", make([]byte, 16)); n != 0 || err != nil {
		t.Errorf("Decrypt = %d, %v", n, err)
	}
	if maxLength, ok, err := collection.MaxDecryptedLength(bg, "absent"); maxLength != 0 || ok || err != nil {
		t.Errorf("MaxDecryptedLength = %d, %v, %v", maxLength, ok, err)
	}
}

func TestCollection_Sources_AreCheckedInOrder_ForNamesAndItems(t *testing.T) {
	first := newPlainSource("conn", "${password}", "password", "first")
	second := newPlainSource("conn", "ignored", "password", "second", "only-second", "${password}")
	collection := newCollection(t, ResolvingOptions{}).Add(first).Add(second)

	if got := decryptString(t, collection, "conn"); got != "first" {
		t.Errorf("conn = %q", got)
	}
	if got := decryptString(t, collection, "only-second"); got != "first" {
		t.Errorf("only-second = %q", got)
	}
	if second.decryptCount("conn") != 0 {
		t.Error("the second source was read for a name the first holds")
	}
}

func TestCollection_ValueProviders_SupplyItemsAfterTheSources_GrowingTheBufferWhenNeeded(t *testing.T) {
	large := strings.Repeat("x", 5000)
	source := newPlainSource("conn", "Host=${host};Blob=${blob}", "host", "from-source")
	collection := newCollection(t, ResolvingOptions{}).
		Add(source).
		AddValueProvider(newSettingsProvider("host", "ignored", "blob", large))

	if got := decryptString(t, collection, "conn"); got != "Host=from-source;Blob="+large {
		t.Errorf("conn = %.40q... (%d bytes)", got, len(got))
	}
}

func TestCollection_ValueProviders_AreNotAnsweredByNameOnTheirOwn(t *testing.T) {
	collection := newCollection(t, ResolvingOptions{}).AddValueProvider(newSettingsProvider("host", "db"))

	if _, ok, err := collection.MaxDecryptedLength(bg, "host"); ok || err != nil {
		t.Errorf("MaxDecryptedLength(host) = %v, %v", ok, err)
	}
}

func TestCollection_ResolvedValueLongerThanMaxResolvedLength_Fails(t *testing.T) {
	collection := newCollection(t, ResolvingOptions{MaxResolvedLength: 16}).
		Add(newPlainSource("conn", "${blob}")).
		AddValueProvider(newSettingsProvider("blob", strings.Repeat("x", 17)))

	_, err := collection.Decrypt(bg, "conn", make([]byte, 64))

	if !errors.Is(err, ErrResolvedValueTooLong) {
		t.Errorf("err = %v, want ErrResolvedValueTooLong", err)
	}
	if errors.Is(err, ErrDestinationTooSmall) {
		t.Error("the caller's result is reported too small")
	}
}

func TestCollection_Options_DefaultAndRejectInvalidValues(t *testing.T) {
	ring := newRing(t)
	collection, err := NewResolvingProtectedCacheCollection(ring, ResolvingOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if collection.MaxResolvedLength() != DefaultMaxResolvedLength {
		t.Errorf("MaxResolvedLength = %d", collection.MaxResolvedLength())
	}
	if token := collection.Token(); token.StartSequence() != "${" || token.EndSequence() != "}" || token.EscapeSequence() != "$" {
		t.Errorf("Token = %+v, want the default token", token)
	}
	if _, err := NewResolvingProtectedCacheCollection(ring, ResolvingOptions{MaxResolvedLength: -1}); err == nil {
		t.Error("a negative MaxResolvedLength was accepted")
	}
	if _, err := NewResolvingProtectedCacheCollection(nil, ResolvingOptions{}); err == nil {
		t.Error("a nil ring was accepted")
	}
}

func TestCollection_CustomToken_MarksItems(t *testing.T) {
	token, err := NewConfigurationItemToken("{{", "}}", "")
	if err != nil {
		t.Fatal(err)
	}
	source := newPlainSource("conn", "Host={{host}};Literal=${host}", "host", "db")
	collection := newCollection(t, ResolvingOptions{Token: token}).Add(source)

	if got := decryptString(t, collection, "conn"); got != "Host=db;Literal=${host}" {
		t.Errorf("conn = %q", got)
	}
}

func TestCollection_TemplateNamingAMissingValue_Fails(t *testing.T) {
	collection := newCollection(t, ResolvingOptions{}).Add(newPlainSource("conn", "${absent}"))

	_, err := collection.Decrypt(bg, "conn", make([]byte, 64))
	wantConfigurationKeyError(t, err, KeyNotFound)

	_, _, err = collection.MaxDecryptedLength(bg, "conn")
	wantConfigurationKeyError(t, err, KeyNotFound)
}

func TestCollection_TemplateResolvingToNothing_IsReportedMissing(t *testing.T) {
	collection := newCollection(t, ResolvingOptions{}).
		Add(newPlainSource("conn", "${empty}")).
		AddValueProvider(newSettingsProvider("empty", ""))

	if _, ok, err := collection.MaxDecryptedLength(bg, "conn"); ok || err != nil {
		t.Errorf("MaxDecryptedLength = %v, %v", ok, err)
	}
	if n, err := collection.Decrypt(bg, "conn", make([]byte, 16)); n != 0 || err != nil {
		t.Errorf("Decrypt = %d, %v", n, err)
	}
}

func TestCollection_ASourceError_FailsTheLookup(t *testing.T) {
	refused := errors.New("access denied")
	collection := newCollection(t, ResolvingOptions{}).
		Add(newPlainSource("conn", "${remote}")).
		Add(failingSource{err: refused})

	if _, err := collection.Decrypt(bg, "conn", make([]byte, 64)); !errors.Is(err, refused) {
		t.Errorf("Decrypt err = %v", err)
	}
	if _, _, err := collection.MaxDecryptedLength(bg, "absent"); !errors.Is(err, refused) {
		t.Errorf("MaxDecryptedLength err = %v", err)
	}
}

func TestCollection_ResolvedValue_IsKeptUntilInvalidated(t *testing.T) {
	collection, source := newConnCollection(t)
	if got := decryptString(t, collection, "conn"); got != "Host=db.internal;Password=s3cret" {
		t.Fatalf("conn = %q", got)
	}

	source.set("password", "rotated")
	if got := decryptString(t, collection, "conn"); got != "Host=db.internal;Password=s3cret" {
		t.Errorf("before Invalidate, conn = %q", got)
	}

	if !collection.Invalidate("conn") {
		t.Error("Invalidate(conn) = false")
	}
	if got := decryptString(t, collection, "conn"); got != "Host=db.internal;Password=rotated" {
		t.Errorf("after Invalidate, conn = %q", got)
	}
	if collection.Invalidate("never-looked-up") {
		t.Error("Invalidate(never-looked-up) = true")
	}
}

func TestCollection_LookupAfterTheTemplateWasInvalidated_ResolvesAgain(t *testing.T) {
	collection, source := newConnCollection(t)
	if _, ok, err := collection.MaxDecryptedLength(bg, "conn"); !ok || err != nil {
		t.Fatalf("MaxDecryptedLength = %v, %v", ok, err)
	}

	source.set("password", "rotated")
	collection.Invalidate("conn")

	result := make([]byte, 64)
	n, err := collection.Decrypt(bg, "conn", result)
	if err != nil || string(result[:n]) != "Host=db.internal;Password=rotated" {
		t.Errorf("Decrypt = %q, %v", result[:n], err)
	}
}

func TestCollection_Invalidate_ForgetsWhichSourceHoldsAPlainValue(t *testing.T) {
	first := newPlainSource()
	second := newPlainSource("password", "second")
	collection := newCollection(t, ResolvingOptions{}).Add(first).Add(second)
	if got := decryptString(t, collection, "password"); got != "second" {
		t.Fatalf("password = %q", got)
	}

	first.set("password", "first")
	if got := decryptString(t, collection, "password"); got != "second" {
		t.Errorf("before Invalidate, password = %q", got)
	}

	if !collection.Invalidate("password") {
		t.Error("Invalidate(password) = false")
	}
	if got := decryptString(t, collection, "password"); got != "first" {
		t.Errorf("after Invalidate, password = %q", got)
	}
}

func TestCollection_Clear_ForgetsEverything(t *testing.T) {
	collection, source := newConnCollection(t)
	decryptString(t, collection, "conn")
	decryptString(t, collection, "host")

	source.set("host", "db2")
	source.set("password", "rotated")
	collection.Clear()

	if got := decryptString(t, collection, "conn"); got != "Host=db2;Password=rotated" {
		t.Errorf("conn = %q", got)
	}
	if got := decryptString(t, collection, "host"); got != "db2" {
		t.Errorf("host = %q", got)
	}
}

func TestCollection_InvalidateDuringAResolve_KeepsItsResultOutOfTheCache(t *testing.T) {
	collection, source := newConnCollection(t)
	source.onFirstDecrypt("password", func() {
		source.set("password", "rotated")
		collection.Invalidate("conn")
	})

	// The first resolution read the old value's length, so it is dropped and the lookup resolves
	// again.
	result := make([]byte, 64)
	for range 2 {
		n, err := collection.Decrypt(bg, "conn", result)
		if err != nil || string(result[:n]) != "Host=db.internal;Password=rotated" {
			t.Errorf("Decrypt = %q, %v", result[:n], err)
		}
		if source.decryptCount("conn") != 2 {
			t.Errorf("conn read %d times, want 2", source.decryptCount("conn"))
		}
	}
}

func TestCollection_ClearDuringAPlainLookup_DoesNotRememberTheSource(t *testing.T) {
	collection, source := newConnCollection(t)
	source.onFirstDecrypt("host", collection.Clear)

	if got := decryptString(t, collection, "host"); got != "db.internal" {
		t.Fatalf("host = %q", got)
	}
	lookups := source.lengthLookupCount("host")

	if got := decryptString(t, collection, "host"); got != "db.internal" {
		t.Fatalf("host = %q", got)
	}
	// The lookup the Clear interrupted didn't remember the source; the Decrypt after it searched
	// again and did, so now the source is asked directly.
	if got := source.lengthLookupCount("host"); got != lookups+1 {
		t.Errorf("%d length lookups, want %d", got, lookups+1)
	}
}

func TestCollection_Names_MatchExactly_EvenWhereTheResolvedStoreIgnoresCase(t *testing.T) {
	source := newPlainSource(
		"Db", "upper ${value}",
		"db", "lower ${value}",
		"a!b", "bang ${value}",
		"aB", "camel ${value}",
		"a!!b", "double ${value}",
		"app/Db-1", "path ${value}",
		"value", "v")
	collection := newCollection(t, ResolvingOptions{}).Add(source)

	for _, want := range []struct{ name, value string }{
		{"Db", "upper v"}, {"db", "lower v"}, {"a!b", "bang v"}, {"aB", "camel v"},
		{"a!!b", "double v"}, {"app/Db-1", "path v"}, {"Db", "upper v"},
	} {
		if got := decryptString(t, collection, want.name); got != want.value {
			t.Errorf("%s = %q, want %q", want.name, got, want.value)
		}
	}
}

func TestStoreKey_HasNoUpperCaseASCII_AndIsInjective(t *testing.T) {
	names := []string{"", "db", "Db", "DB", "dB", "!", "!!", "!d", "!D", "a!b", "aB", "a!!b", "a!Bb", "app/Db-1", "café", "CAFÉ"}
	seen := map[string]string{}
	for _, name := range names {
		key := storeKey(name)
		if strings.ContainsAny(key, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
			t.Errorf("storeKey(%q) = %q holds upper-case ASCII", name, key)
		}
		aad, err := hkdfguard.CacheAAD(key)
		if err != nil {
			t.Fatal(err)
		}
		if other, ok := seen[string(aad)]; ok {
			t.Errorf("%q and %q share the AAD %q", name, other, aad)
		}
		seen[string(aad)] = name
	}
}

func TestCollection_RemoteSource_ResolvesWithOneFetchPerSecret(t *testing.T) {
	remote, store := newRemote(t,
		"conn", "Host=${app-config#host};Password=${app-config#password}",
		"app-config", `{"host":"db.internal","password":"s3cret"}`,
		"plain", "value")
	collection := newCollection(t, ResolvingOptions{}).Add(remote)

	maxLength, ok, err := collection.MaxDecryptedLength(bg, "conn")
	if err != nil || !ok {
		t.Fatalf("MaxDecryptedLength = %v, %v", ok, err)
	}
	result := make([]byte, maxLength)
	n, err := collection.Decrypt(bg, "conn", result)
	if err != nil || string(result[:n]) != "Host=db.internal;Password=s3cret" {
		t.Errorf("Decrypt = %q, %v", result[:n], err)
	}
	if again, _, _ := collection.MaxDecryptedLength(bg, "conn"); again != maxLength {
		t.Errorf("MaxDecryptedLength changed from %d to %d", maxLength, again)
	}

	// A plain value, found and then remembered.
	if got := decryptString(t, collection, "plain"); got != "value" {
		t.Errorf("plain = %q", got)
	}

	if got := store.fetched(); len(got) != 3 {
		t.Errorf("fetched %v, want conn, app-config and plain once each", got)
	}
}

func TestCollection_ConcurrentLookups_AllSeeTheResolvedValue(t *testing.T) {
	collection, _ := newConnCollection(t)

	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for i := range 32 {
		wg.Go(func() {
			if i%8 == 0 {
				collection.Invalidate("conn")
			}
			result := make([]byte, 64)
			n, err := collection.Decrypt(bg, "conn", result)
			if err == nil && string(result[:n]) != "Host=db.internal;Password=s3cret" {
				err = fmt.Errorf("conn = %q", result[:n])
			}
			if err != nil {
				errs <- err
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestCollection_SensitiveLogging_RecordsTheName(t *testing.T) {
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	previousProvider := otel.GetTracerProvider()
	otel.SetTracerProvider(provider)
	previousLogging := diagnostics.Cache.SensitiveLoggingEnabled()
	diagnostics.Cache.SetSensitiveLogging(true)
	t.Cleanup(func() {
		diagnostics.Cache.SetSensitiveLogging(previousLogging)
		otel.SetTracerProvider(previousProvider)
		_ = provider.Shutdown(bg)
	})

	collection, _ := newConnCollection(t)
	if got := decryptString(t, collection, "password"); got != "s3cret" {
		t.Fatalf("password = %q", got)
	}

	for _, span := range recorder.Ended() {
		if span.Name() != diagnostics.SpanCacheDecrypt {
			continue
		}
		for _, event := range span.Events() {
			for _, attr := range event.Attributes {
				if attr.Key == diagnostics.AttrName && attr.Value.AsString() == "password" {
					return
				}
			}
		}
	}
	t.Error("no decrypt span recorded the name")
}

func TestCollection_Members_RejectNilArguments(t *testing.T) {
	collection := newCollection(t, ResolvingOptions{})

	wantPanic := func(what string, f func()) {
		t.Helper()
		defer func() {
			if recover() == nil {
				t.Errorf("%s didn't panic", what)
			}
		}()
		f()
	}
	wantPanic("Add(nil)", func() { collection.Add(nil) })
	wantPanic("AddValueProvider(nil)", func() { collection.AddValueProvider(nil) })
}
