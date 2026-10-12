package encryptedconfig_test

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/cache"
	"github.com/runsecure/hkdfguard-go/dek"
	"github.com/runsecure/hkdfguard-go/diagnostics"
	"github.com/runsecure/hkdfguard-go/encryptedconfig"
)

var bg = context.Background()

// gcmProvider is a minimal real AES-256-GCM hkdfguard.CryptoProvider.
type gcmProvider struct{ aead cipher.AEAD }

func (p gcmProvider) Encrypt(_ context.Context, plaintext, aad, result []byte) (int, error) {
	defer hkdfguard.Wipe(plaintext)
	return len(p.aead.Seal(result[:0], nil, plaintext, aad)), nil
}

func (p gcmProvider) Decrypt(_ context.Context, ciphertext, aad, result []byte) (int, error) {
	out, err := p.aead.Open(result[:0], nil, ciphertext, aad)
	if err != nil {
		return 0, hkdfguard.ErrAuthenticationFailed
	}
	return len(out), nil
}

func (p gcmProvider) EncryptedAllocationLength(n int) int { return n + p.aead.Overhead() }
func (p gcmProvider) DecryptedAllocationLength(n int) int { return max(0, n-p.aead.Overhead()) }
func (p gcmProvider) Close() error                        { return nil }

func newRing(t *testing.T) *dek.KeyRing {
	t.Helper()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCMWithRandomNonce(block)
	ring := dek.NewKeyRing(nil)
	if err := ring.Add(bg, 1, dek.NewKey(gcmProvider{aead})); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ring.Close() })
	return ring
}

// protectFor encrypts plaintext the way the pipeline does for a configuration key: bound to that
// key's purpose.
func protectFor(t *testing.T, ring *dek.KeyRing, key, plaintext string) string {
	t.Helper()
	purpose, err := hkdfguard.ConfigurationPurpose(key)
	if err != nil {
		t.Fatal(err)
	}
	protector, _ := ring.CreateProtector(purpose)
	formatted, err := protector.Encrypt(bg, []byte(plaintext))
	if err != nil {
		t.Fatal(err)
	}
	return formatted
}

func mapLookup(t *testing.T, values map[string]string) encryptedconfig.Lookup {
	t.Helper()
	lookup, err := encryptedconfig.NewMapLookup(values)
	if err != nil {
		t.Fatal(err)
	}
	return lookup
}

func read(t *testing.T, r hkdfguard.ProtectedReadOnlyCache, name string) (string, bool, error) {
	t.Helper()
	n, ok, err := r.MaxDecryptedLength(bg, name)
	if err != nil || !ok {
		return "", ok, err
	}
	result := make([]byte, n)
	n, err = r.Decrypt(bg, name, result)
	return string(result[:n]), true, err
}

func TestReader_DecryptsAValueProtectedForItsKey(t *testing.T) {
	ring := newRing(t)
	reader := encryptedconfig.New(ring, mapLookup(t, map[string]string{
		"ConnectionStrings:Admin": protectFor(t, ring, "ConnectionStrings:Admin", "Server=db;Password=hunter2"),
		"Unicode":                 protectFor(t, ring, "Unicode", "héllo wörld ✓ 🔐"),
	}))

	for key, want := range map[string]string{"ConnectionStrings:Admin": "Server=db;Password=hunter2", "Unicode": "héllo wörld ✓ 🔐"} {
		if got, ok, err := read(t, reader, key); err != nil || !ok || got != want {
			t.Errorf("%s = %q, %v, %v", key, got, ok, err)
		}
	}
}

func TestReader_AMissingKey_DecryptsToNothing(t *testing.T) {
	reader := encryptedconfig.New(newRing(t), mapLookup(t, nil))

	if n, err := reader.Decrypt(bg, "Missing", make([]byte, 8)); n != 0 || err != nil {
		t.Errorf("Decrypt = %d, %v", n, err)
	}
	if _, ok, err := reader.MaxDecryptedLength(bg, "Missing"); ok || err != nil {
		t.Errorf("MaxDecryptedLength ok = %v, %v", ok, err)
	}
}

func TestReader_LookupsIgnoreASCIICase(t *testing.T) {
	ring := newRing(t)
	reader := encryptedconfig.New(ring, mapLookup(t, map[string]string{
		"ConnectionStrings:Admin": protectFor(t, ring, "ConnectionStrings:Admin", "secret"),
	}))

	for _, key := range []string{"connectionstrings:admin", "CONNECTIONSTRINGS:ADMIN", "ConnectionStrings:Admin"} {
		if got, _, err := read(t, reader, key); err != nil || got != "secret" {
			t.Errorf("%s = %q, %v", key, got, err)
		}
	}
}

func TestReader_AValueMovedToAnotherKey_FailsAuthentication(t *testing.T) {
	ring := newRing(t)
	admin := protectFor(t, ring, "ConnectionStrings:Admin", "admin-secret")
	cafe := protectFor(t, ring, "café", "lower")
	reader := encryptedconfig.New(ring, mapLookup(t, map[string]string{
		"ConnectionStrings:Reporting": admin,
		"CAFÉ":                        cafe, // non-ASCII case: a different key
	}))

	for _, key := range []string{"ConnectionStrings:Reporting", "CAFÉ"} {
		if _, err := reader.Decrypt(bg, key, make([]byte, 64)); !errors.Is(err, hkdfguard.ErrAuthenticationFailed) {
			t.Errorf("%s: %v", key, err)
		}
	}
}

func TestReader_AValueProtectedUnderAPlainPurpose_DoesNotDecrypt(t *testing.T) {
	// Only the configuration purpose binds a value to its key; a protector named just "Secret"
	// produces values the reader must refuse.
	ring := newRing(t)
	plain, _ := ring.CreateProtector("Secret")
	formatted, _ := plain.Encrypt(bg, []byte("value"))
	reader := encryptedconfig.New(ring, mapLookup(t, map[string]string{"Secret": formatted}))

	if _, err := reader.Decrypt(bg, "Secret", make([]byte, 64)); !errors.Is(err, hkdfguard.ErrAuthenticationFailed) {
		t.Errorf("error = %v", err)
	}
}

func TestReader_AValueThatIsNotProtected_FailsToParse(t *testing.T) {
	reader := encryptedconfig.New(newRing(t), mapLookup(t, map[string]string{"Plain": "not-a-protected-value"}))

	if _, err := reader.Decrypt(bg, "Plain", make([]byte, 64)); !errors.Is(err, dek.ErrInvalidFormat) {
		t.Errorf("Decrypt: %v", err)
	}
	if _, _, err := reader.MaxDecryptedLength(bg, "Plain"); !errors.Is(err, dek.ErrInvalidFormat) {
		t.Errorf("MaxDecryptedLength: %v", err)
	}
}

func TestReader_AnEmptyKey_IsRefused(t *testing.T) {
	reader := encryptedconfig.New(newRing(t), func(string) (string, bool) { return "enc::v1::AAAA", true })

	if _, err := reader.Decrypt(bg, "", make([]byte, 8)); !errors.Is(err, hkdfguard.ErrInvalidConfigurationKey) {
		t.Errorf("error = %v", err)
	}
}

func TestReader_ReadsFreshOnEveryCall(t *testing.T) {
	ring := newRing(t)
	current := protectFor(t, ring, "Rotating", "first")
	reader := encryptedconfig.New(ring, func(key string) (string, bool) { return current, key == "Rotating" })

	if got, _, _ := read(t, reader, "Rotating"); got != "first" {
		t.Fatalf("got %q", got)
	}
	current = protectFor(t, ring, "Rotating", "second") // a configuration reload
	if got, _, _ := read(t, reader, "Rotating"); got != "second" {
		t.Errorf("after reload got %q", got)
	}
}

func TestReader_SitsInACacheCollection(t *testing.T) {
	ring := newRing(t)
	local := cache.New(ring)
	_ = local.Add(bg, "Local", []byte("from the cache"))
	reader := encryptedconfig.New(ring, mapLookup(t, map[string]string{"FromConfig": protectFor(t, ring, "FromConfig", "from config")}))
	secrets := cache.NewCollection(local, reader)

	for key, want := range map[string]string{"Local": "from the cache", "FromConfig": "from config"} {
		if got, _, err := read(t, secrets, key); err != nil || got != want {
			t.Errorf("%s = %q, %v", key, got, err)
		}
	}
}

func TestReader_WithSensitiveLoggingEnabled_StillRoundTrips(t *testing.T) {
	telemetry := diagnostics.EncryptedConfiguration
	original := telemetry.SensitiveLoggingEnabled()
	telemetry.SetSensitiveLogging(true)
	t.Cleanup(func() { telemetry.SetSensitiveLogging(original) })

	ring := newRing(t)
	reader := encryptedconfig.New(ring, mapLookup(t, map[string]string{"Key": protectFor(t, ring, "Key", "value")}))
	if got, _, err := read(t, reader, "Key"); err != nil || got != "value" {
		t.Errorf("%q, %v", got, err)
	}
}

// --- Lookups --------------------------------------------------------------------------------

func TestNewMapLookup_RefusesKeysThatDifferOnlyInASCIICase(t *testing.T) {
	if _, err := encryptedconfig.NewMapLookup(map[string]string{"Key": "a", "KEY": "b"}); !errors.Is(err, encryptedconfig.ErrDuplicateKey) {
		t.Errorf("error = %v", err)
	}
	if _, err := encryptedconfig.NewMapLookup(map[string]string{"café": "a", "CAFÉ": "b"}); err != nil {
		t.Errorf("non-ASCII case variants refused: %v", err)
	}
}

func TestEnvLookup_FollowsTheDotNetDoubleUnderscoreConvention(t *testing.T) {
	t.Setenv("APP_ConnectionStrings__Admin", "from env")
	lookup := encryptedconfig.EnvLookup("APP_")

	if value, ok := lookup("ConnectionStrings:Admin"); !ok || value != "from env" {
		t.Errorf("got %q, %v", value, ok)
	}
	if _, ok := lookup("ConnectionStrings:Missing"); ok {
		t.Error("a missing variable was found")
	}
	_ = os.Unsetenv("APP_ConnectionStrings__Admin")
}

func TestFlattenJSON_FlattensLikeDotNetConfiguration(t *testing.T) {
	values, err := encryptedconfig.FlattenJSON([]byte(`{
		"ConnectionStrings": { "Admin": "enc::v1::AAAA", "Reporting": "plain" },
		"Hosts": ["a", "b"],
		"Port": 8080, "Ratio": 1.5, "Enabled": true, "Nothing": null,
		"Nested": { "Deeper": { "Leaf": "x" } }
	}`))
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"ConnectionStrings:Admin": "enc::v1::AAAA", "ConnectionStrings:Reporting": "plain",
		"Hosts:0": "a", "Hosts:1": "b",
		"Port": "8080", "Ratio": "1.5", "Enabled": "true", "Nothing": "",
		"Nested:Deeper:Leaf": "x",
	}
	if len(values) != len(want) {
		t.Errorf("got %d keys: %v", len(values), values)
	}
	for key, value := range want {
		if values[key] != value {
			t.Errorf("%s = %q, want %q", key, values[key], value)
		}
	}
}

func TestFlattenJSON_RefusesInvalidDocuments(t *testing.T) {
	cases := map[string]string{
		"not JSON":          `{"a":`,
		"not an object":     `["a"]`,
		"trailing data":     `{"a":"b"} {"c":"d"}`,
		"case-only collide": `{"Key":"a","KEY":"b"}`,
	}
	for name, document := range cases {
		if _, err := encryptedconfig.FlattenJSON([]byte(document)); err == nil {
			t.Errorf("%s: accepted", name)
		} else if name == "case-only collide" && !errors.Is(err, encryptedconfig.ErrDuplicateKey) {
			t.Errorf("%s: %v", name, err)
		} else if !strings.Contains(err.Error(), "encryptedconfig") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
