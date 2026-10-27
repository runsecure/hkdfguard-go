package securefile

import (
	"crypto/rand"
	"errors"
	"strings"
	"testing"
)

// wrapped is about the size of a KMS ciphertext blob for a 32-byte DEK, random.
func wrapped() []byte { return random(184) }

func random(length int) []byte {
	b := make([]byte, length)
	_, _ = rand.Read(b)
	return b
}

// requireKeyFileError fails the test unless err is a *KeyFileError matching target with
// errors.Is, whose message holds every one of contains.
func requireKeyFileError(t *testing.T, err error, target error, contains ...string) *KeyFileError {
	t.Helper()
	var keyFileErr *KeyFileError
	if !errors.As(err, &keyFileErr) {
		t.Fatalf("got %v (%T); want a *KeyFileError", err, err)
	}
	if !errors.Is(err, target) {
		t.Fatalf("%q does not match %v (it wraps %v)", err, target, keyFileErr.Err)
	}
	for _, s := range contains {
		if !strings.Contains(err.Error(), s) {
			t.Errorf("%q lacks %q", err, s)
		}
	}
	return keyFileErr
}

// requireErrorContaining fails the test unless err matches target with errors.Is and its message
// holds every one of contains.
func requireErrorContaining(t *testing.T, err error, target error, contains ...string) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("got %v; want an error matching %v", err, target)
	}
	for _, s := range contains {
		if !strings.Contains(err.Error(), s) {
			t.Errorf("%q lacks %q", err, s)
		}
	}
}
