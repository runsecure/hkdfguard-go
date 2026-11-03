package filepersecret

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/dek"
	"github.com/runsecure/hkdfguard-go/diagnostics"
	"github.com/runsecure/hkdfguard-go/securefile"
)

// The Cache over a real folder securefile accepts (see trustedFolder), with values written by a
// ring's protectors - the port of the .NET FilePerSecretCacheTests.

// testKey is a real AES-256-GCM hkdfguard.DataEncryptionKey.
type testKey struct{ aead cipher.AEAD }

func newTestKey(t *testing.T) *testKey {
	t.Helper()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
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

// fixture is a trusted folder, the trust it needs, and a ring holding one fresh key as version 1.
type fixture struct {
	t      *testing.T
	folder string
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
	folder, trust := trustedFolder(t)
	ring := dek.NewKeyRing(format)
	if err := ring.Add(t.Context(), 1, newTestKey(t)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ring.Close() })
	return &fixture{t: t, folder: folder, trust: trust, format: format, ring: ring}
}

func (f *fixture) newCache() *Cache {
	f.t.Helper()
	return f.newCacheOver(f.folder, f.trust)
}

func (f *fixture) newCacheOver(folder string, trust securefile.KeyFileTrust) *Cache {
	f.t.Helper()
	c, err := New(folder, trust, f.ring, f.format, Options{})
	if err != nil {
		f.t.Fatal(err)
	}
	return c
}

func (f *fixture) path(name string) string { return filepath.Join(f.folder, name) }

// write writes value to name's file, encrypted as a pipeline or deployer would: bound to that name.
func (f *fixture) write(name, value string) { f.writeWithSuffix(name, value, "") }

func (f *fixture) writeWithSuffix(name, value, suffix string) {
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
	f.writeRaw(name, []byte(encrypted+suffix))
}

func (f *fixture) writeRaw(name string, contents []byte) {
	f.t.Helper()
	if err := os.WriteFile(f.path(name), contents, 0o600); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) remove(name string) {
	f.t.Helper()
	if err := os.Remove(f.path(name)); err != nil {
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

// requireFailure fails the test unless both lookups fail with an error matching target.
func requireFailure(t *testing.T, c *Cache, name string, target error) {
	t.Helper()
	if _, err := c.Decrypt(t.Context(), name, make([]byte, 64)); !errors.Is(err, target) {
		t.Errorf("Decrypt(%q): %v; want %v", name, err, target)
	}
	if _, _, err := c.MaxDecryptedLength(t.Context(), name); !errors.Is(err, target) {
		t.Errorf("MaxDecryptedLength(%q): %v; want %v", name, err, target)
	}
}

func TestAFile_DecryptsThroughEveryLookup(t *testing.T) {
	f := newFixture(t)
	f.write("Db-Password", "value")
	c := f.newCache()

	result := make([]byte, 16)
	n, err := c.Decrypt(t.Context(), "Db-Password", result)
	if err != nil || string(result[:n]) != "value" {
		t.Fatalf("Decrypt = %q, %v; want the value", result[:n], err)
	}
	maxLength, ok, err := c.MaxDecryptedLength(t.Context(), "Db-Password")
	if err != nil || !ok || maxLength < len("value") {
		t.Errorf("MaxDecryptedLength = %d, %v, %v; want at least 5", maxLength, ok, err)
	}
	mustGet(t, c, "Db-Password", "value")
}

const secretCount = 20

// Non-ASCII fragments, so each secret also exercises multi-byte UTF-8 - "🔑" four bytes of it.
var nonASCII = []string{"café", "naïve", "日本語", "Ωμέγα", "🔑", "Größe"}

func randomInt(t *testing.T, below int) int {
	t.Helper()
	n, err := rand.Int(rand.Reader, big.NewInt(int64(below)))
	if err != nil {
		t.Fatal(err)
	}
	return int(n.Int64())
}

// randomSecrets is secretCount secrets, each a random base64 run of random length plus random
// non-ASCII text, under names that differ only by number.
func randomSecrets(t *testing.T) map[string]string {
	t.Helper()
	secrets := map[string]string{}
	for i := range secretCount {
		raw := make([]byte, 16+randomInt(t, 113))
		_, _ = rand.Read(raw)
		secrets[fmt.Sprintf("Secret-%02d", i)] = base64.StdEncoding.EncodeToString(raw) +
			" " + nonASCII[randomInt(t, len(nonASCII))] + " " + nonASCII[randomInt(t, len(nonASCII))]
	}
	return secrets
}

var formatted = regexp.MustCompile(`^enc::v1::[A-Za-z0-9+/]+=*$`)

// writeAndVerifyEncrypted writes every secret encrypted, and checks each file holds only the
// formatted ciphertext: ASCII base64, with neither the secret's random text nor its non-ASCII text
// anywhere in it.
func writeAndVerifyEncrypted(f *fixture, secrets map[string]string) {
	f.t.Helper()
	for name, value := range secrets {
		f.write(name, value)

		onDisk, err := os.ReadFile(f.path(name))
		if err != nil {
			f.t.Fatal(err)
		}
		for _, b := range onDisk {
			if b >= 0x80 {
				f.t.Fatalf("%s holds a non-ASCII byte", name)
			}
		}
		if !formatted.Match(onDisk) {
			f.t.Errorf("%s holds %q; want only the formatted ciphertext", name, onDisk)
		}
		if bytes.Contains(onDisk, []byte(strings.Split(value, " ")[0])) || bytes.Contains(onDisk, []byte(value)) {
			f.t.Errorf("%s holds its secret", name)
		}
	}
}

// requireEachDecrypts checks every secret through both lookups.
func requireEachDecrypts(t *testing.T, c *Cache, secrets map[string]string) {
	t.Helper()
	for name, value := range secrets {
		maxLength, ok, err := c.MaxDecryptedLength(t.Context(), name)
		if err != nil || !ok || maxLength < len(value) {
			t.Fatalf("%s: MaxDecryptedLength = %d, %v, %v; want at least %d", name, maxLength, ok, err, len(value))
		}
		result := make([]byte, maxLength)
		n, err := c.Decrypt(t.Context(), name, result)
		if err != nil || string(result[:n]) != value || !utf8.Valid(result[:n]) {
			t.Fatalf("%s: Decrypt = %q, %v; want %q", name, result[:n], err, value)
		}
	}
}

func TestTwentyRandomSecrets_AreOnlyCiphertextOnDisk_AndEachDecrypts(t *testing.T) {
	f := newFixture(t)
	secrets := randomSecrets(t)
	writeAndVerifyEncrypted(f, secrets)

	requireEachDecrypts(t, f.newCache(), secrets)
}

func TestTwentyRandomSecrets_LoadedConcurrently_AreServedFromMemoryOnceTheirFilesAreGone(t *testing.T) {
	f := newFixture(t)
	secrets := randomSecrets(t)
	writeAndVerifyEncrypted(f, secrets)
	c := f.newCache()

	// Every secret's first lookup at once, half of them twice, so loads also race each other.
	var names []string
	for name := range secrets {
		names = append(names, name)
	}
	names = append(names, names[:secretCount/2]...)
	var wg sync.WaitGroup
	failures := make(chan string, len(names))
	for _, name := range names {
		wg.Go(func() {
			if n, ok, err := c.MaxDecryptedLength(t.Context(), name); err != nil || !ok || n == 0 {
				failures <- name
			}
		})
	}
	wg.Wait()
	close(failures)
	for name := range failures {
		t.Errorf("%s didn't load", name)
	}

	for name := range secrets {
		f.remove(name)
	}
	if entries, err := os.ReadDir(f.folder); err != nil || len(entries) != 0 {
		t.Fatalf("the folder still holds %d entries (%v)", len(entries), err)
	}
	requireEachDecrypts(t, c, secrets)
}

func TestSurroundingWhitespace_IsIgnored(t *testing.T) {
	f := newFixture(t)
	f.writeWithSuffix("item", "value", "\r\n")

	mustGet(t, f.newCache(), "item", "value")
}

func TestAFile_IsReadOnce_ThenServedFromMemory(t *testing.T) {
	f := newFixture(t)
	c := f.newCache()
	f.write("item", "first")
	mustGet(t, c, "item", "first")

	f.write("item", "second")
	mustGet(t, c, "item", "first")
	f.remove("item")
	mustGet(t, c, "item", "first")
}

func TestAChangedFile_IsPickedUpByANewCache(t *testing.T) {
	f := newFixture(t)
	f.write("item", "first")
	mustGet(t, f.newCache(), "item", "first")

	f.write("item", "second")
	mustGet(t, f.newCache(), "item", "second")
}

func TestAMissingSecret_IsntRemembered_SoAFileAddedLaterIsFound(t *testing.T) {
	f := newFixture(t)
	c := f.newCache()
	requireMissing(t, c, "item")

	f.write("item", "value")
	mustGet(t, c, "item", "value")
}

func TestAMissingOrEmptyFile_IsMissing(t *testing.T) {
	f := newFixture(t)
	f.writeRaw("empty", []byte(" \n"))
	f.writeRaw("zero", nil)
	c := f.newCache()

	for _, name := range []string{"absent", "empty", "zero"} {
		requireMissing(t, c, name)
	}
}

func TestAFolderRemovedAfterNew_ReportsEverySecretMissing(t *testing.T) {
	f := newFixture(t)
	f.write("item", "value")
	c := f.newCache()
	if err := os.RemoveAll(f.folder); err != nil {
		t.Fatal(err)
	}

	requireMissing(t, c, "item")
}

func TestANameThatCantBeAFileName_IsMissing_WithoutReadingOutsideTheFolder(t *testing.T) {
	f := newFixture(t)
	sub := f.path("sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	f.write("item", "value")
	c := f.newCacheOver(sub, f.trust)

	for _, name := range []string{"", ".hidden", "..", "../item", "sub/item", `sub\item`, `..\item`, "db:password", "café", "item\x00"} {
		if IsValidName(name) {
			t.Errorf("IsValidName(%q) = true", name)
		}
		requireMissing(t, c, name)
	}
}

func TestIsValidName_AcceptsUpToMaxNameLength_OfLettersDigitsAndPunctuation(t *testing.T) {
	for name, want := range map[string]bool{
		"Db-Password_v2.txt":                 true,
		strings.Repeat("a", MaxNameLength):   true,
		strings.Repeat("a", MaxNameLength+1): false,
		"":                                   false,
		"item ":                              false,
		"K":                                  false, // KELVIN SIGN, which some filesystems fold to k
	} {
		if got := IsValidName(name); got != want {
			t.Errorf("IsValidName(%q) = %v; want %v", name, got, want)
		}
	}
}

func TestAFileCopiedUnderAnotherName_FailsAuthentication(t *testing.T) {
	f := newFixture(t)
	f.write("admin", "secret")
	copied, err := os.ReadFile(f.path("admin"))
	if err != nil {
		t.Fatal(err)
	}
	f.writeRaw("reader", copied)

	requireFailure(t, f.newCache(), "reader", hkdfguard.ErrAuthenticationFailed)
}

func TestAFileThatFailsAuthentication_IsntCached_SoAFixedFileIsReadNextTime(t *testing.T) {
	f := newFixture(t)
	f.write("admin", "secret")
	copied, err := os.ReadFile(f.path("admin"))
	if err != nil {
		t.Fatal(err)
	}
	f.writeRaw("reader", copied)
	c := f.newCache()
	requireFailure(t, c, "reader", hkdfguard.ErrAuthenticationFailed)

	f.write("reader", "fixed")
	mustGet(t, c, "reader", "fixed")
}

func TestAFileInAnUntrustedLocation_IsRefused_AndNotCached(t *testing.T) {
	if runningAsRoot() {
		t.Skip("Running as root, whose files are trusted.")
	}
	f := newFixture(t)
	f.write("item", "value")
	untrusted := f.newCacheOver(f.folder, securefile.AdministratorsOnly())

	requireFailure(t, untrusted, "item", securefile.ErrUntrusted)
	var keyFileErr *securefile.KeyFileError
	if _, err := untrusted.Decrypt(t.Context(), "item", make([]byte, 16)); !errors.As(err, &keyFileErr) || !errors.Is(err, fs.ErrPermission) {
		t.Errorf("got %v; want a *securefile.KeyFileError matching fs.ErrPermission", err)
	}
	mustGet(t, f.newCache(), "item", "value")
}

func TestAValueUnderAnOlderKeyVersion_StillDecryptsAfterRotation(t *testing.T) {
	f := newFixture(t)
	f.write("item", "old")
	if err := f.ring.Add(t.Context(), 2, newTestKey(t)); err != nil {
		t.Fatal(err)
	}
	f.write("other", "new")
	c := f.newCache()

	mustGet(t, c, "item", "old")
	mustGet(t, c, "other", "new")
	if onDisk, _ := os.ReadFile(f.path("other")); !bytes.HasPrefix(onDisk, []byte("enc::v2::")) {
		t.Errorf("other was written under %q; want version 2", onDisk[:min(len(onDisk), 9)])
	}
}

func TestAValueUnderAKeyVersionTheRingDoesntHold_Fails(t *testing.T) {
	f := newFixture(t)
	ciphertext := make([]byte, 40)
	_, _ = rand.Read(ciphertext)
	encrypted, err := f.format.Format(t.Context(), hkdfguard.KeyTrackingValue{KeyVersion: 7, Value: ciphertext})
	if err != nil {
		t.Fatal(err)
	}
	f.writeRaw("item", []byte(encrypted))

	requireFailure(t, f.newCache(), "item", hkdfguard.ErrKeyNotFound)
}

func TestAFileNotInTheFormat_Fails(t *testing.T) {
	f := newFixture(t)
	f.writeRaw("item", []byte("not encrypted"))

	requireFailure(t, f.newCache(), "item", dek.ErrInvalidFormat)
}

func TestAFileOverMaxFileLength_IsRefused(t *testing.T) {
	f := newFixture(t)
	f.writeRaw("huge", make([]byte, MaxFileLength+1))

	requireFailure(t, f.newCache(), "huge", securefile.ErrTooLarge)
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

func TestSensitiveLogging_LogsTheNameOnly_AndDoesntChangeTheResult(t *testing.T) {
	original := diagnostics.Cache.SensitiveLoggingEnabled()
	diagnostics.Cache.SetSensitiveLogging(true)
	t.Cleanup(func() { diagnostics.Cache.SetSensitiveLogging(original) })
	f := newFixture(t)
	f.write("item", "value")
	handler := &capturingHandler{}
	c, err := New(f.folder, f.trust, f.ring, f.format, Options{Logger: slog.New(handler)})
	if err != nil {
		t.Fatal(err)
	}

	mustGet(t, c, "item", "value")
	messages := handler.messages()
	if len(messages) != 1 || messages[0] != "hkdfguard.cache.populate completed for item." {
		t.Errorf("logged %q; want the one load, by name", messages)
	}
}

func TestLoads_AreCountedBySuccessNotFoundAndError(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	otel.SetMeterProvider(provider)
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	f := newFixture(t)
	f.write("item", "value")
	f.writeRaw("broken", []byte("not encrypted"))
	c := f.newCache()

	mustGet(t, c, "item", "value") // one load; the second lookup is served from memory
	_, _ = get(t, c, "absent")
	_, _ = c.Decrypt(t.Context(), "broken", make([]byte, 16))
	_, _ = c.Decrypt(t.Context(), "../item", make([]byte, 16)) // never loaded

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
	want := map[string]int64{"hkdfguard.cache.populate/success": 1, "hkdfguard.cache.populate/not_found": 1, "hkdfguard.cache.populate/error": 1}
	if len(counts) != len(want) {
		t.Errorf("counted %v; want %v", counts, want)
	}
	for k, v := range want {
		if counts[k] != v {
			t.Errorf("%s = %d, want %d (all: %v)", k, counts[k], v, counts)
		}
	}
}

func TestNew_ValidatesItsArguments(t *testing.T) {
	f := newFixture(t)

	for name, err := range map[string]error{
		"no folder":          func() error { _, err := New("", f.trust, f.ring, f.format, Options{}); return err }(),
		"no ring":            func() error { _, err := New(f.folder, f.trust, nil, f.format, Options{}); return err }(),
		"no format provider": func() error { _, err := New(f.folder, f.trust, f.ring, nil, Options{}); return err }(),
		"a missing folder":   func() error { _, err := New(f.path("absent"), f.trust, f.ring, f.format, Options{}); return err }(),
		"a file, not a folder": func() error {
			f.writeRaw("file", []byte("x"))
			_, err := New(f.path("file"), f.trust, f.ring, f.format, Options{})
			return err
		}(),
	} {
		want := ErrInvalidArgument
		if strings.HasPrefix(name, "a ") {
			want = fs.ErrNotExist
		}
		if !errors.Is(err, want) {
			t.Errorf("%s: %v; want %v", name, err, want)
		}
	}

	t.Chdir(f.folder)
	c, err := New(".", f.trust, f.ring, f.format, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if want, _ := filepath.Abs(f.folder); c.FolderPath() != want {
		t.Errorf("FolderPath = %q; want %q", c.FolderPath(), want)
	}
}
