package hkdfguard_test

import (
	"bytes"
	"testing"

	"github.com/runsecure/hkdfguard-go"
)

func TestIsZero(t *testing.T) {
	lastSet := make([]byte, 64)
	lastSet[63] = 1
	midSet := make([]byte, 16)
	midSet[10] = 1

	cases := []struct {
		name string
		in   []byte
		want bool
	}{
		{"nil", nil, true},
		{"empty", []byte{}, true},
		{"all zero", make([]byte, 16), true},
		{"non-zero in the middle", midSet, false},
		{"only non-zero at the end", lastSet, false},
	}
	for _, c := range cases {
		if got := hkdfguard.IsZero(c.in); got != c.want {
			t.Errorf("%s: IsZero = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestWipe_ClearsEveryByte(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5}

	hkdfguard.Wipe(b)

	if !bytes.Equal(b, make([]byte, 5)) {
		t.Errorf("Wipe left %v", b)
	}
}

func TestWipe_WithNilOrEmpty_DoesNotPanic(t *testing.T) {
	hkdfguard.Wipe(nil)
	hkdfguard.Wipe([]byte{})
}
