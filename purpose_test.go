package hkdfguard_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/runsecure/hkdfguard-go"
)

func mustPurpose(t *testing.T, key string) string {
	t.Helper()
	purpose, err := hkdfguard.ConfigurationPurpose(key)
	if err != nil {
		t.Fatalf("ConfigurationPurpose(%q): %v", key, err)
	}
	return purpose
}

func mustAAD(t *testing.T, key string) []byte {
	t.Helper()
	aad, err := hkdfguard.ConfigurationAAD(key)
	if err != nil {
		t.Fatalf("ConfigurationAAD(%q): %v", key, err)
	}
	return aad
}

func TestConfigurationPurpose_PrefixesAndUpperCasesTheFullKeyPath(t *testing.T) {
	if got := mustPurpose(t, "ConnectionStrings:Admin"); got != "HkdfGuard.EncryptedConfiguration:CONNECTIONSTRINGS:ADMIN" {
		t.Errorf("got %q", got)
	}
}

func TestConfigurationPurpose_DifferentKeys_GiveDifferentPurposes(t *testing.T) {
	if mustPurpose(t, "ConnectionStrings:Admin") == mustPurpose(t, "ConnectionStrings:Reporting") {
		t.Error("different keys share a purpose")
	}
}

func TestConfigurationAAD_IsTheUTF8BytesOfThePurpose(t *testing.T) {
	for _, key := range []string{"Database:Password", "héllo:ünïcode", strings.Repeat("Section:", 60) + "Leaf"} {
		if !bytes.Equal(mustAAD(t, key), []byte(mustPurpose(t, key))) {
			t.Errorf("AAD for %q is not the purpose's bytes", key)
		}
	}
}

func TestConfigurationPurpose_KeysDifferingOnlyInASCIICase_ShareAPurpose(t *testing.T) {
	pairs := [][2]string{
		{"secret", "SECRET"},
		{"Secret", "secret"},
		{"Connection_Strings:Admin-1", "connection_strings:ADMIN-1"},
	}
	for _, p := range pairs {
		if mustPurpose(t, p[0]) != mustPurpose(t, p[1]) || !bytes.Equal(mustAAD(t, p[0]), mustAAD(t, p[1])) {
			t.Errorf("%q and %q should share a purpose", p[0], p[1])
		}
	}
}

func TestConfigurationPurpose_NonASCIICaseVariants_NeverShareAPurpose(t *testing.T) {
	pairs := [][2]string{
		{"café", "CAFÉ"},      // non-ASCII case
		{"ſecret", "Secret"},  // 'ſ' upper-cases to 'S' under Unicode rules, never here
		{"ıd", "ID"},          // dotless i
		{"straße", "STRASSE"}, // ß
	}
	for _, p := range pairs {
		if mustPurpose(t, p[0]) == mustPurpose(t, p[1]) {
			t.Errorf("%q and %q should not share a purpose", p[0], p[1])
		}
	}
}

func TestConfigurationPurpose_UpperCasesOnlyASCIILetters_AndCopiesEverythingElseAsIs(t *testing.T) {
	want := hkdfguard.ConfigurationPurposePrefix + ":CAFé:üBER-1_中"
	if got := mustPurpose(t, "café:über-1_中"); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestConfigurationPurpose_ChangesOnlyASCIILowercaseLetters_ForAnyCodePoint(t *testing.T) {
	// The safety half of the rule, checked exhaustively: the only characters the purpose changes
	// are a-z, so two keys share a purpose only when they differ in ASCII case alone.
	prefix := hkdfguard.ConfigurationPurposePrefix + ":"
	for cp := rune(0); cp <= utf8.MaxRune; cp++ {
		if !utf8.ValidRune(cp) {
			continue
		}
		key := string(cp)
		want := key
		if 'a' <= cp && cp <= 'z' {
			want = string(cp - ('a' - 'A'))
		}
		if got := mustPurpose(t, key); got != prefix+want {
			t.Fatalf("U+%04X: got %q, want %q", cp, got, prefix+want)
		}
	}
}

func TestConfigurationPurposeAndAAD_RejectEmptyAndInvalidUTF8Keys(t *testing.T) {
	keys := []string{
		"",
		"Key\xffTail",         // not UTF-8 at all
		"Key\xed\xa0\x80Tail", // an encoded lone surrogate (U+D800)
		"Key\xe2\x82",         // truncated sequence at the end
	}
	for _, key := range keys {
		if _, err := hkdfguard.ConfigurationPurpose(key); !errors.Is(err, hkdfguard.ErrInvalidConfigurationKey) {
			t.Errorf("ConfigurationPurpose(%q) error = %v, want ErrInvalidConfigurationKey", key, err)
		}
		if _, err := hkdfguard.ConfigurationAAD(key); !errors.Is(err, hkdfguard.ErrInvalidConfigurationKey) {
			t.Errorf("ConfigurationAAD(%q) error = %v, want ErrInvalidConfigurationKey", key, err)
		}
	}
}

func TestConfigurationPurpose_AcceptsAnAstralCharacter(t *testing.T) {
	if got := mustPurpose(t, "Key😀Tail"); got != hkdfguard.ConfigurationPurposePrefix+":KEY😀TAIL" {
		t.Errorf("got %q", got)
	}
}

func TestConfigurationAAD_KnownVector_ForCrossLanguagePorts(t *testing.T) {
	// Every port must produce exactly these bytes for this key.
	want := []byte("HkdfGuard.EncryptedConfiguration:CONNECTIONSTRINGS:CAFé")
	if got := mustAAD(t, "ConnectionStrings:café"); !bytes.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}
