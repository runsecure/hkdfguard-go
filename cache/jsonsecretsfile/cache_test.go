package jsonsecretsfile

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/cryptoprovider/aesgcm256"
	"github.com/runsecure/hkdfguard-go/dek"
	"github.com/runsecure/hkdfguard-go/diagnostics"
	"github.com/runsecure/hkdfguard-go/internal/cachevalue"
	"github.com/runsecure/hkdfguard-go/pipeline"
	"github.com/runsecure/hkdfguard-go/securefile"
)

// The Cache over a real file securefile accepts (see trustedFolder), with values written by a
// ring's protectors or a pipeline - the port of the .NET JsonSecretsFileReadOnlyCacheTests.

// testKey is a real AES-256-GCM hkdfguard.DataEncryptionKey, laid out as aesgcm256's:
// [nonce | ciphertext | tag].
type testKey struct{ aead cipher.AEAD }

func newTestKey(t *testing.T) *testKey {
	t.Helper()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return newTestKeyFrom(t, key)
}

func newTestKeyFrom(t *testing.T, key []byte) *testKey {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		t.Fatal(err)
	}
	return &testKey{aead: aead}
}

func (k *testKey) Encrypt(_ context.Context, plaintext, aad []byte) ([]byte, error) {
	defer hkdfguard.Wipe(plaintext)
	return k.aead.Seal(nil, nil, plaintext, aad), nil
}

func (k *testKey) Decrypt(_ context.Context, ciphertext, aad, result []byte) (int, error) {
	if len(ciphertext) < k.aead.Overhead() || len(result) < len(ciphertext)-k.aead.Overhead() {
		return 0, hkdfguard.ErrAuthenticationFailed
	}
	out, err := k.aead.Open(result[:0], nil, ciphertext, aad)
	if err != nil {
		return 0, hkdfguard.ErrAuthenticationFailed
	}
	return len(out), nil
}

// fixture is a trusted folder holding secrets.json (once written), the trust it needs, and a ring
// holding one fresh key as version 1.
type fixture struct {
	t      *testing.T
	folder string
	file   string
	trust  securefile.KeyFileTrust
	format *dek.DefaultFormatProvider
	ring   *dek.KeyRing
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	return newFixtureWithFormat(t, dek.NewDefaultFormatProvider())
}

func newFixtureWithFormat(t *testing.T, format *dek.DefaultFormatProvider) *fixture {
	t.Helper()
	return newFixtureWithKey(t, format, newTestKey(t))
}

func newFixtureWithKey(t *testing.T, format *dek.DefaultFormatProvider, key hkdfguard.DataEncryptionKey) *fixture {
	t.Helper()
	folder, trust := trustedFolder(t)
	ring := dek.NewKeyRing(format)
	if err := ring.Add(t.Context(), 1, key); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ring.Close() })
	return &fixture{t: t, folder: folder, file: filepath.Join(folder, "secrets.json"), trust: trust, format: format, ring: ring}
}

func (f *fixture) newCache() *Cache {
	f.t.Helper()
	return f.newCacheWith(f.trust, Options{})
}

func (f *fixture) newCacheWith(trust securefile.KeyFileTrust, options Options) *Cache {
	f.t.Helper()
	c, err := New(f.file, trust, f.ring, f.format, options)
	if err != nil {
		f.t.Fatal(err)
	}
	return c
}

// encrypt is value encrypted for name, as a pipeline or deployer would: bound to that name.
func (f *fixture) encrypt(name, value string) string {
	f.t.Helper()
	purpose, err := hkdfguard.ConfigurationPurpose(name)
	if err != nil {
		f.t.Fatal(err)
	}
	protector, err := f.ring.CreateProtector(purpose)
	if err != nil {
		f.t.Fatal(err)
	}
	encrypted, err := protector.Encrypt(f.t.Context(), []byte(value))
	if err != nil {
		f.t.Fatal(err)
	}
	return encrypted
}

// write writes every secret encrypted for its name, as one JSON object; name, value pairs.
func (f *fixture) write(pairs ...string) {
	f.t.Helper()
	members := map[string]string{}
	for i := 0; i < len(pairs); i += 2 {
		members[pairs[i]] = f.encrypt(pairs[i], pairs[i+1])
	}
	f.writeMembers(members)
}

func (f *fixture) writeMembers(members map[string]string) {
	f.t.Helper()
	contents, err := json.Marshal(members)
	if err != nil {
		f.t.Fatal(err)
	}
	f.writeRaw(string(contents))
}

func (f *fixture) writeRaw(contents string) {
	f.t.Helper()
	if err := os.WriteFile(f.file, []byte(contents), 0o600); err != nil {
		f.t.Fatal(err)
	}
}

// get decrypts name's value, sized by MaxDecryptedLength; "" and false when there is none.
func get(t *testing.T, c hkdfguard.ProtectedReadOnlyCache, name string) (string, bool) {
	t.Helper()
	n, ok, err := c.MaxDecryptedLength(t.Context(), name)
	if err != nil {
		t.Fatalf("MaxDecryptedLength(%q): %v", name, err)
	}
	if !ok {
		return "", false
	}
	result := make([]byte, n)
	written, err := c.Decrypt(t.Context(), name, result)
	if err != nil {
		t.Fatalf("Decrypt(%q): %v", name, err)
	}
	return string(result[:written]), true
}

// mustGet is get, failing the test unless the value is want.
func mustGet(t *testing.T, c hkdfguard.ProtectedReadOnlyCache, name, want string) {
	t.Helper()
	if got, ok := get(t, c, name); !ok || got != want {
		t.Fatalf("%q: got %q, %v; want %q", name, got, ok, want)
	}
}

// requireMissing fails the test unless both lookups report name missing.
func requireMissing(t *testing.T, c *Cache, name string) {
	t.Helper()
	if n, err := c.Decrypt(t.Context(), name, make([]byte, 16)); n != 0 || err != nil {
		t.Errorf("Decrypt(%q) = %d, %v; want 0, nil", name, n, err)
	}
	if n, ok, err := c.MaxDecryptedLength(t.Context(), name); n != 0 || ok || err != nil {
		t.Errorf("MaxDecryptedLength(%q) = %d, %v, %v; want 0, false, nil", name, n, ok, err)
	}
}

// requireFailure fails the test unless both lookups fail with an error matching target, and
// returns Decrypt's.
func requireFailure(t *testing.T, c *Cache, name string, target error) error {
	t.Helper()
	_, err := c.Decrypt(t.Context(), name, make([]byte, 64))
	if !errors.Is(err, target) {
		t.Errorf("Decrypt(%q): %v; want %v", name, err, target)
	}
	if _, _, err := c.MaxDecryptedLength(t.Context(), name); !errors.Is(err, target) {
		t.Errorf("MaxDecryptedLength(%q): %v; want %v", name, err, target)
	}
	return err
}

// memoryStore is a pipeline.SecretStore over values held in memory, so a test can read exactly what
// WriteJSONSecrets writes.
type memoryStore map[string]string

func (memoryStore) IsValidName(string) bool { return true }

func (m memoryStore) ReadSecret(ctx context.Context, name string, secret *pipeline.Secret) error {
	return secret.ProtectSecret(ctx, []byte(m[name]))
}

func TestWhatAPipelineWrites_DecryptsUnderTheKeyItWraps(t *testing.T) {
	protector, err := aesgcm256.NewPipelineDataProtector(dek.NewDefaultFormatProvider(), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer protector.Close()
	writer, err := pipeline.New(protector, []string{"db-password", "api-key"},
		memoryStore{"db-password": "pässwörd", "api-key": "key"}, pipeline.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.PullSecrets(t.Context()); err != nil {
		t.Fatal(err)
	}

	// What the application holds once the pipeline's key has been wrapped and unwrapped.
	key := make([]byte, 32)
	if _, err := base64.StdEncoding.Decode(key, protector.KeyBase64()); err != nil {
		t.Fatal(err)
	}
	f := newFixtureWithKey(t, dek.NewDefaultFormatProvider(), newTestKeyFrom(t, key))
	if err := writer.WriteJSONSecrets(f.file); err != nil {
		t.Fatal(err)
	}
	c := f.newCache()

	mustGet(t, c, "db-password", "pässwörd")
	mustGet(t, c, "api-key", "key")
}

func TestAValue_DecryptsThroughEveryLookup_UnderItsNameIgnoringASCIICase(t *testing.T) {
	f := newFixture(t)
	f.write("Db-Password", "value")
	c := f.newCache()

	mustGet(t, c, "Db-Password", "value")
	mustGet(t, c, "DB-PASSWORD", "value")
	result := make([]byte, 16)
	if n, err := c.Decrypt(t.Context(), "db-password", result); err != nil || string(result[:n]) != "value" {
		t.Fatalf("Decrypt = %q, %v; want the value", result[:n], err)
	}
	if maxLength, ok, err := c.MaxDecryptedLength(t.Context(), "Db-Password"); err != nil || !ok || maxLength < len("value") {
		t.Errorf("MaxDecryptedLength = %d, %v, %v; want at least 5", maxLength, ok, err)
	}
}

func TestTheFile_IsReadOnce_EvenByConcurrentLookups_ThenServedFromMemory(t *testing.T) {
	reader := collectMetrics(t)
	f := newFixture(t)
	var pairs []string
	for i := range 200 {
		pairs = append(pairs, fmt.Sprintf("secret-%03d", i), fmt.Sprintf("value-%d", i))
	}
	f.write(pairs...)
	c := f.newCache()

	results := make([]string, 200)
	var wg sync.WaitGroup
	for i := range 200 {
		wg.Go(func() {
			result := make([]byte, 64)
			n, err := c.Decrypt(t.Context(), pairs[2*i], result)
			if err != nil {
				t.Errorf("%s: %v", pairs[2*i], err)
			}
			results[i] = string(result[:n])
		})
	}
	wg.Wait()
	if err := os.Remove(f.file); err != nil {
		t.Fatal(err)
	}

	for i, got := range results {
		if want := pairs[2*i+1]; got != want {
			t.Errorf("%s = %q; want %q", pairs[2*i], got, want)
		}
	}
	mustGet(t, c, "secret-007", "value-7")
	if counts := populateCounts(t, reader); !sameCounts(counts, map[string]int64{"success": 1}) {
		t.Errorf("loaded %v; want one load", counts)
	}
}

func TestANameTheFileDoesntHold_OrThatCantBeOne_IsMissing(t *testing.T) {
	f := newFixture(t)
	f.write("item", "value")
	c := f.newCache()

	for _, name := range []string{"absent", "", ".hidden", "../item", "ıtem", "it em", "item\x00"} {
		requireMissing(t, c, name)
	}
}

func TestANameThatCantBeOne_NeverLoadsTheFile(t *testing.T) {
	f := newFixture(t)
	f.writeRaw("not json")
	c := f.newCache()

	requireMissing(t, c, "../item")
	if c.values.Load() != nil {
		t.Error("the file was loaded")
	}
}

func TestAMissingFile_ReportsEverySecretMissing_AndIsntRemembered(t *testing.T) {
	f := newFixture(t)
	f.write("item", "value")
	c := f.newCache()
	if err := os.Remove(f.file); err != nil {
		t.Fatal(err)
	}

	requireMissing(t, c, "item")

	f.write("item", "later")
	mustGet(t, c, "item", "later")
}

func TestAFolderRemovedAfterNew_ReportsEverySecretMissing(t *testing.T) {
	f := newFixture(t)
	folder := filepath.Join(f.folder, "sub")
	if err := os.Mkdir(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	f.file = filepath.Join(folder, "secrets.json")
	f.write("item", "value")
	c := f.newCache()
	if err := os.RemoveAll(folder); err != nil {
		t.Fatal(err)
	}

	requireMissing(t, c, "item")
}

func TestAFileThatIsntTheSecretsObject_IsRefused_AndNotKept(t *testing.T) {
	for _, tc := range []struct{ json, problem string }{
		{``, "isn't valid JSON"},
		{`not json`, "isn't valid JSON"},
		{`["item"]`, "holds an array, not an object of secrets"},
		{`"item"`, "holds a string, not an object of secrets"},
		{`1`, "holds a number, not an object of secrets"},
		{`true`, "holds a boolean, not an object of secrets"},
		{`null`, "holds null, not an object of secrets"},
		{`{"item":1}`, "no value for 'item'"},
		{`{"item":{"a":"b"}}`, "no value for 'item'"},
		{`{"item":["a"]}`, "no value for 'item'"},
		{`{"item":null}`, "no value for 'item'"},
		{`{"item":true}`, "no value for 'item'"},
		{`{"item":"  "}`, "no value for 'item'"},
		{`{"../item":"x"}`, "isn't a secret's name"},
		{`{"item":"{0}","ITEM":"{0}"}`, "'ITEM' more than once"},
		{`{"item":"{0}"} {}`, "isn't valid JSON"},
		{`{"item":"{0}"} x`, "isn't valid JSON"},
		{`{"item":"{0}" `, "isn't valid JSON"},
		{`{"item" `, "isn't valid JSON"},
		{`{"item":"{0}",}`, "isn't valid JSON"},
	} {
		t.Run(tc.json, func(t *testing.T) {
			f := newFixture(t)
			f.writeRaw(strings.ReplaceAll(tc.json, "{0}", f.encrypt("item", "value")))
			c := f.newCache()

			err := requireFailure(t, c, "item", ErrInvalidData)
			if err == nil || !strings.Contains(err.Error(), tc.problem) || !strings.Contains(err.Error(), c.FilePath()) {
				t.Errorf("got %v; want it to say %q of the file", err, tc.problem)
			}

			f.write("item", "fixed")
			mustGet(t, c, "item", "fixed")
		})
	}
}

func TestAValueNotInTheFormat_FailsTheWholeFile(t *testing.T) {
	f := newFixture(t)
	f.writeMembers(map[string]string{"item": f.encrypt("item", "fine"), "other": "not encrypted"})

	requireFailure(t, f.newCache(), "item", dek.ErrInvalidFormat)
}

func TestAValueMovedUnderAnotherName_FailsTheWholeFile(t *testing.T) {
	f := newFixture(t)
	f.writeMembers(map[string]string{"reader": f.encrypt("reader", "fine"), "writer": f.encrypt("reader", "moved")})
	c := f.newCache()

	requireFailure(t, c, "reader", hkdfguard.ErrAuthenticationFailed)
}

func TestAValueUnderAKeyVersionTheRingDoesntHold_FailsTheWholeFile(t *testing.T) {
	f := newFixture(t)
	ciphertext := make([]byte, 40)
	_, _ = rand.Read(ciphertext)
	old, err := f.format.Format(t.Context(), hkdfguard.KeyTrackingValue{KeyVersion: 7, Value: ciphertext})
	if err != nil {
		t.Fatal(err)
	}
	f.writeMembers(map[string]string{"item": f.encrypt("item", "fine"), "old": old})

	requireFailure(t, f.newCache(), "item", hkdfguard.ErrKeyNotFound)
}

func TestValuesUnderOlderKeyVersions_StillDecryptAfterRotation(t *testing.T) {
	f := newFixture(t)
	old := f.encrypt("item", "old")
	if err := f.ring.Add(t.Context(), 2, newTestKey(t)); err != nil {
		t.Fatal(err)
	}
	other := f.encrypt("other", "new")
	if !strings.HasPrefix(other, "enc::v2::") {
		t.Fatalf("other was written as %q; want version 2", other[:9])
	}
	f.writeMembers(map[string]string{"item": old, "other": other})
	c := f.newCache()

	mustGet(t, c, "item", "old")
	mustGet(t, c, "other", "new")
}

func TestAFileInAnUntrustedLocation_IsRefused_AndNotKept(t *testing.T) {
	if runningAsRoot() {
		t.Skip("Running as root, whose files are trusted.")
	}
	f := newFixture(t)
	f.write("item", "value")
	untrusted := f.newCacheWith(securefile.AdministratorsOnly(), Options{})

	err := requireFailure(t, untrusted, "item", securefile.ErrUntrusted)
	var keyFileErr *securefile.KeyFileError
	if !errors.As(err, &keyFileErr) || !errors.Is(err, fs.ErrPermission) {
		t.Errorf("got %v; want a *securefile.KeyFileError matching fs.ErrPermission", err)
	}
	if untrusted.values.Load() != nil {
		t.Error("the untrusted file's values were kept")
	}
	mustGet(t, f.newCache(), "item", "value")
}

func TestAFileOverTheMaximumLength_IsRefused(t *testing.T) {
	f := newFixture(t)
	f.write("item", "value")

	requireFailure(t, f.newCacheWith(f.trust, Options{MaxFileLength: 16}), "item", securefile.ErrTooLarge)
}

func TestTheDefaultMaximumLength_IsAMebibyte(t *testing.T) {
	f := newFixture(t)
	f.writeRaw(`{"item":"` + strings.Repeat("x", DefaultMaxFileLength) + `"}`)

	requireFailure(t, f.newCache(), "item", securefile.ErrTooLarge)
}

func TestALargeValue_Decrypts_UnderALargerFormatLimit(t *testing.T) {
	// Over the default format's limit, so ring and cache both allow longer values.
	format, err := dek.NewDefaultFormatProviderWithLimit(16 * 1024)
	if err != nil {
		t.Fatal(err)
	}
	f := newFixtureWithFormat(t, format)
	value := strings.Repeat("x", dek.DefaultMaxEncryptedLength+10)
	f.write("large", value)

	mustGet(t, f.newCache(), "large", value)
}

func TestACancelledContext_Fails(t *testing.T) {
	f := newFixture(t)
	f.write("item", "value")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if _, err := f.newCache().Decrypt(ctx, "item", make([]byte, 16)); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v; want context.Canceled", err)
	}
}

func TestALookupWaitingOnAnotherLoad_StopsWhenItsContextEnds(t *testing.T) {
	f := newFixture(t)
	f.write("item", "value")
	c := f.newCache()
	c.loading <- struct{}{} // another load is under way

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if _, err := c.Decrypt(ctx, "item", make([]byte, 16)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v; want context.DeadlineExceeded", err)
	}

	<-c.loading
	mustGet(t, c, "item", "value")
}

func TestALookupWaitingOnAnotherLoad_TakesWhatItLoaded(t *testing.T) {
	f := newFixture(t)
	f.write("item", "value")
	c := f.newCache()
	c.loading <- struct{}{} // another load is under way
	done := make(chan string)
	go func() {
		result := make([]byte, 16)
		n, _ := c.load(t.Context())
		if n == nil {
			done <- ""
			return
		}
		written, _ := cachevalue.Decrypt(t.Context(), c.ring, "item", (*n)["ITEM"], result)
		done <- string(result[:written])
	}()

	// The other load finishes, then the file goes: the waiting lookup must not read it again.
	loaded, err := c.readValues(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	c.values.Store(loaded)
	if err := os.Remove(f.file); err != nil {
		t.Fatal(err)
	}
	<-c.loading

	if got := <-done; got != "value" {
		t.Fatalf("the waiting lookup got %q; want the loaded value", got)
	}
}

// capturingHandler records slog records.
type capturingHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *capturingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *capturingHandler) WithAttrs([]slog.Attr) slog.Handler       { return h }
func (h *capturingHandler) WithGroup(string) slog.Handler            { return h }
func (h *capturingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r)
	return nil
}

func (h *capturingHandler) messages() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var messages []string
	for _, r := range h.records {
		messages = append(messages, r.Message)
	}
	return messages
}

func TestSensitiveLogging_LogsThePathAndTheNameOnly_AndDoesntChangeTheResult(t *testing.T) {
	original := diagnostics.Cache.SensitiveLoggingEnabled()
	diagnostics.Cache.SetSensitiveLogging(true)
	t.Cleanup(func() { diagnostics.Cache.SetSensitiveLogging(original) })
	f := newFixture(t)
	f.write("item", "value")
	handler := &capturingHandler{}
	c := f.newCacheWith(f.trust, Options{Logger: slog.New(handler)})

	result := make([]byte, 16)
	if n, err := c.Decrypt(t.Context(), "item", result); err != nil || string(result[:n]) != "value" {
		t.Fatalf("Decrypt = %q, %v", result[:n], err)
	}
	want := []string{"hkdfguard.cache.decrypt completed for item.", "hkdfguard.cache.populate completed for " + c.FilePath() + "."}
	if got := handler.messages(); !slices.Equal(got, want) {
		t.Errorf("logged %q; want %q", got, want)
	}
}

func TestAFailedLoad_IsLogged(t *testing.T) {
	f := newFixture(t)
	f.writeRaw("not json")
	handler := &capturingHandler{}
	c := f.newCacheWith(f.trust, Options{Logger: slog.New(handler)})

	if _, err := c.Decrypt(t.Context(), "item", make([]byte, 16)); !errors.Is(err, ErrInvalidData) {
		t.Fatalf("got %v; want ErrInvalidData", err)
	}
	if got := handler.messages(); len(got) != 1 {
		t.Errorf("logged %q; want the one failure", got)
	}
}

// collectMetrics routes every meter to a reader the test collects from.
func collectMetrics(t *testing.T) *sdkmetric.ManualReader {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	original := otel.GetMeterProvider()
	otel.SetMeterProvider(provider)
	t.Cleanup(func() {
		otel.SetMeterProvider(original)
		_ = provider.Shutdown(context.Background())
	})
	return reader
}

// populateCounts is how many loads the reader has seen, by result.
func populateCounts(t *testing.T, reader *sdkmetric.ManualReader) map[string]int64 {
	t.Helper()
	var collected metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &collected); err != nil {
		t.Fatal(err)
	}
	counts := map[string]int64{}
	for _, scope := range collected.ScopeMetrics {
		for _, m := range scope.Metrics {
			for _, point := range m.Data.(metricdata.Sum[int64]).DataPoints {
				op, _ := point.Attributes.Value(diagnostics.AttrOperationName)
				result, _ := point.Attributes.Value(diagnostics.AttrResult)
				if op.AsString() == diagnostics.SpanCachePopulate {
					counts[result.AsString()] += point.Value
				}
			}
		}
	}
	return counts
}

func sameCounts(got, want map[string]int64) bool {
	if len(got) != len(want) {
		return false
	}
	for k, v := range want {
		if got[k] != v {
			return false
		}
	}
	return true
}

func TestLoads_AreCountedBySuccessNotFoundAndError(t *testing.T) {
	reader := collectMetrics(t)
	f := newFixture(t)
	f.writeRaw("not json")
	c := f.newCache()
	_, _ = c.Decrypt(t.Context(), "item", make([]byte, 16)) // error
	if err := os.Remove(f.file); err != nil {
		t.Fatal(err)
	}
	_, _ = get(t, c, "item") // not found
	f.write("item", "value")
	mustGet(t, c, "item", "value") // success; the second lookup is served from memory
	_, _ = get(t, c, "absent")
	_, _ = c.Decrypt(t.Context(), "../item", make([]byte, 16)) // never loaded

	want := map[string]int64{diagnostics.ResultSuccess: 1, diagnostics.ResultNotFound: 1, diagnostics.ResultError: 1}
	if counts := populateCounts(t, reader); !sameCounts(counts, want) {
		t.Errorf("counted %v; want %v", counts, want)
	}
}

func TestNew_ValidatesItsArguments(t *testing.T) {
	f := newFixture(t)
	f.write("item", "value")

	for name, err := range map[string]error{
		"no file":                func() error { _, err := New("", f.trust, f.ring, f.format, Options{}); return err }(),
		"no ring":                func() error { _, err := New(f.file, f.trust, nil, f.format, Options{}); return err }(),
		"no format provider":     func() error { _, err := New(f.file, f.trust, f.ring, nil, Options{}); return err }(),
		"a negative file length": func() error { _, err := New(f.file, f.trust, f.ring, f.format, Options{MaxFileLength: -1}); return err }(),
		"a missing file": func() error {
			_, err := New(filepath.Join(f.folder, "absent.json"), f.trust, f.ring, f.format, Options{})
			return err
		}(),
		"a folder, not a file": func() error { _, err := New(f.folder, f.trust, f.ring, f.format, Options{}); return err }(),
		"a file in a missing one": func() error {
			_, err := New(filepath.Join(f.folder, "absent", "s.json"), f.trust, f.ring, f.format, Options{})
			return err
		}(),
	} {
		want := ErrInvalidArgument
		if strings.HasPrefix(name, "a ") && name != "a negative file length" {
			want = fs.ErrNotExist
		}
		if !errors.Is(err, want) {
			t.Errorf("%s: %v; want %v", name, err, want)
		}
	}

	t.Chdir(f.folder)
	c, err := New("secrets.json", f.trust, f.ring, f.format, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if want, _ := filepath.Abs(f.file); c.FilePath() != want {
		t.Errorf("FilePath = %q; want %q", c.FilePath(), want)
	}
	if c.maxFileLength != DefaultMaxFileLength {
		t.Errorf("the maximum file length is %d; want %d", c.maxFileLength, DefaultMaxFileLength)
	}
}

func TestAFailedLoad_IsLoggedWithoutTheMembersName_WithSensitiveLoggingOff(t *testing.T) {
	original := diagnostics.Cache.SensitiveLoggingEnabled()
	diagnostics.Cache.SetSensitiveLogging(false)
	t.Cleanup(func() { diagnostics.Cache.SetSensitiveLogging(original) })
	f := newFixture(t)
	value := f.encrypt("tenant-42-password", "value")
	f.writeRaw(`{"tenant-42-password":"` + value + `","TENANT-42-PASSWORD":"` + value + `"}`)
	handler := &capturingHandler{}
	c := f.newCacheWith(f.trust, Options{Logger: slog.New(handler)})

	_, err := c.Decrypt(t.Context(), "tenant-42-password", make([]byte, 16))
	if !errors.Is(err, ErrInvalidData) || !strings.Contains(err.Error(), "TENANT-42-PASSWORD") {
		t.Fatalf("got %v; the caller's error should still name the member", err)
	}
	if len(handler.records) != 1 {
		t.Fatalf("logged %q; want the one failure", handler.messages())
	}
	handler.records[0].Attrs(func(a slog.Attr) bool {
		if text := a.Value.String(); strings.Contains(strings.ToLower(text), "tenant-42") {
			t.Errorf("%s=%q names the member", a.Key, text)
		}
		return true
	})
}
