package hkdfguard_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/runsecure/hkdfguard-go"
)

func TestCacheAAD_KnownVector_ForCrossLanguagePorts(t *testing.T) {
	// Every port must produce exactly these bytes for this name.
	got, err := hkdfguard.CacheAAD("api-Key_1:café")
	if err != nil || !bytes.Equal(got, []byte("HkdfGuard.Cache:API-KEY_1:CAFé")) {
		t.Errorf("CacheAAD = %q, %v", got, err)
	}
}

func TestCacheAAD_IgnoresOnlyASCIICase(t *testing.T) {
	cases := []struct {
		x, y  string
		equal bool
	}{
		{"item", "ITEM", true},
		{"Item-1_x", "iTEM-1_X", true},
		{"café", "CAFÉ", false},
		{"ſecret", "Secret", false},
		{"item", "items", false},
		{"", "", true},
	}
	for _, c := range cases {
		x, _ := hkdfguard.CacheAAD(c.x)
		y, _ := hkdfguard.CacheAAD(c.y)
		if bytes.Equal(x, y) != c.equal {
			t.Errorf("%q vs %q: equal = %v, want %v", c.x, c.y, !c.equal, c.equal)
		}
	}
}

func TestCacheAAD_RefusesInvalidUTF8(t *testing.T) {
	if _, err := hkdfguard.CacheAAD("bad\xed\xa0\x80name"); !errors.Is(err, hkdfguard.ErrInvalidCacheName) {
		t.Errorf("error = %v", err)
	}
}
