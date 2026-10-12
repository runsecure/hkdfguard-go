package dek

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/runsecure/hkdfguard-go"
)

var bg = context.Background()

func TestFormat_KnownVector_ForCrossLanguagePorts(t *testing.T) {
	formatted, err := NewDefaultFormatProvider().Format(bg, hkdfguard.KeyTrackingValue{KeyVersion: 1, Value: []byte{1, 2, 3}})

	if err != nil || formatted != "enc::v1::AQID" {
		t.Errorf("Format = %q, %v", formatted, err)
	}
}

func TestFormat_ThenParse_RoundTrips(t *testing.T) {
	f := NewDefaultFormatProvider()
	for _, value := range []hkdfguard.KeyTrackingValue{
		{KeyVersion: 7, Value: []byte("ciphertext bytes")},
		{KeyVersion: 1, Value: []byte{}},
		{KeyVersion: -5, Value: []byte{9}},
	} {
		formatted, err := f.Format(bg, value)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := f.Parse(bg, formatted)
		if err != nil || parsed.KeyVersion != value.KeyVersion || !bytes.Equal(parsed.Value, value.Value) {
			t.Errorf("%q parsed as %+v, %v", formatted, parsed, err)
		}
		if n, err := f.MaxDecryptedLength(bg, formatted); err != nil || n != len(value.Value) {
			t.Errorf("%q: MaxDecryptedLength = %d, %v", formatted, n, err)
		}
	}
}

func TestParse_RefusesAnythingButTheCanonicalForm(t *testing.T) {
	f := NewDefaultFormatProvider()
	for _, input := range []string{
		"", "no-delimiters-at-all", "enc::onlyonepart", "wrong::v1::AAAA", "enc::1::AAAA", "enc::vNotANumber::AAAA",
		"enc::v1::not-valid-base64!!!",
		"enc::v+1::AQID", "enc::v 1::AQID", "enc::v1 ::AQID", "enc::v~1::AQID", "enc::v::AQID", "enc::v-::AQID",
		"enc::v2147483648::AQID", // outside the 32-bit range every port shares
		"enc::v1::AQID    ", "enc::v1::AQ ID", "enc::v1::AQID\t", "enc::v1::AQID\r\n", "enc::v1:: AQID",
		"enc::v1::AQI", // not a multiple of four
	} {
		if _, err := f.Parse(bg, input); !errors.Is(err, ErrInvalidFormat) {
			t.Errorf("Parse(%q) error = %v", input, err)
		}
		if _, err := f.MaxDecryptedLength(bg, input); !errors.Is(err, ErrInvalidFormat) {
			t.Errorf("MaxDecryptedLength(%q) error = %v", input, err)
		}
	}
}

func TestTheLimit_DefaultsTo4096_AndAppliesToFormatAndParse(t *testing.T) {
	f := NewDefaultFormatProvider()
	if f.MaxEncryptedLength() != 4096 || DefaultMaxEncryptedLength != 4096 {
		t.Fatalf("limit = %d", f.MaxEncryptedLength())
	}

	// "enc::v1::" is 9 characters; 3063 bytes encode to 4084, 4093 in all - within the limit.
	formatted, err := f.Format(bg, hkdfguard.KeyTrackingValue{KeyVersion: 1, Value: make([]byte, 3063)})
	if err != nil || len(formatted) > 4096 {
		t.Fatalf("a value within the limit: %d characters, %v", len(formatted), err)
	}
	if _, err := f.Parse(bg, formatted); err != nil {
		t.Errorf("Parse within the limit: %v", err)
	}

	if _, err := f.Format(bg, hkdfguard.KeyTrackingValue{KeyVersion: 1, Value: make([]byte, 3072)}); !errors.Is(err, ErrInvalidFormat) {
		t.Errorf("Format over the limit: %v", err)
	}
	if _, err := f.Parse(bg, "enc::v1::"+strings.Repeat("A", 4096)); !errors.Is(err, ErrInvalidFormat) {
		t.Errorf("Parse over the limit: %v", err)
	}
}

func TestACustomLimit_AppliesToFormatAndParse_AndMustBePositive(t *testing.T) {
	// "enc::v1::" plus 8 base64 characters (6 bytes) is exactly 17.
	f, err := NewDefaultFormatProviderWithLimit(17)
	if err != nil {
		t.Fatal(err)
	}
	formatted, err := f.Format(bg, hkdfguard.KeyTrackingValue{KeyVersion: 1, Value: make([]byte, 6)})
	if err != nil || len(formatted) != 17 {
		t.Fatalf("a value of exactly the limit: %q, %v", formatted, err)
	}
	if _, err := f.Parse(bg, formatted); err != nil {
		t.Errorf("Parse at exactly the limit: %v", err)
	}
	if _, err := f.Format(bg, hkdfguard.KeyTrackingValue{KeyVersion: 1, Value: make([]byte, 9)}); !errors.Is(err, ErrInvalidFormat) {
		t.Errorf("over a custom limit: %v", err)
	}

	for _, limit := range []int{0, -1} {
		if _, err := NewDefaultFormatProviderWithLimit(limit); err == nil {
			t.Errorf("limit %d accepted", limit)
		}
	}
}
