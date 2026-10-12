package hkdfguard_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/runsecure/hkdfguard-go"
)

func TestServiceName_ValidNamesPass(t *testing.T) {
	for _, name := range []string{"a", "7", "my.service", "com.example.Orders2", "trailing."} {
		if err := hkdfguard.ValidateServiceName(name); err != nil || !hkdfguard.IsValidServiceName(name) {
			t.Errorf("%q: unexpected error %v", name, err)
		}
	}
}

func TestServiceName_ExactlyMaxLengthPasses_AndOneMoreFails(t *testing.T) {
	if hkdfguard.MaxServiceNameLength != 128 {
		t.Fatalf("MaxServiceNameLength = %d, want 128", hkdfguard.MaxServiceNameLength)
	}
	if !hkdfguard.IsValidServiceName(strings.Repeat("a", hkdfguard.MaxServiceNameLength)) {
		t.Error("a name of exactly MaxServiceNameLength was rejected")
	}

	err := hkdfguard.ValidateServiceName(strings.Repeat("a", hkdfguard.MaxServiceNameLength+1))
	if err == nil || !strings.Contains(err.Error(), "at most 128 characters; this one is 129") {
		t.Errorf("error = %v", err)
	}
}

func TestServiceName_InvalidNamesFailWithTheReason(t *testing.T) {
	cases := []struct{ name, reason string }{
		{"", "required"},
		{".service", "can't start with '.'"},
		{".", "can't start with '.'"},
		{"my..service", "can't contain '..'"},
		{"my...service", "can't contain '..'"},
		{"service..", "can't contain '..'"},
		{"my-service", "U+002D at position 2"},
		{"my service", "U+0020 at position 2"},
		{"my_service", "U+005F at position 2"},
		{"café", "U+00E9 at position 3"},
		{"a/b", "U+002F at position 1"},
		{"a\x00b", "U+0000 at position 1"},
	}
	for _, c := range cases {
		err := hkdfguard.ValidateServiceName(c.name)
		if !errors.Is(err, hkdfguard.ErrInvalidServiceName) || !strings.Contains(err.Error(), c.reason) {
			t.Errorf("%q: error = %v, want ErrInvalidServiceName containing %q", c.name, err, c.reason)
		}
		if hkdfguard.IsValidServiceName(c.name) {
			t.Errorf("%q: IsValidServiceName = true", c.name)
		}
	}
}
