package dek

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/diagnostics"
)

func TestKey_RoundTrips_WithAndWithoutAAD(t *testing.T) {
	key, _ := newTestKey(t)
	for _, aad := range [][]byte{nil, []byte("purpose")} {
		ciphertext, err := key.Encrypt(context.Background(), []byte("hello"), aad)
		if err != nil {
			t.Fatal(err)
		}
		result := make([]byte, 5)
		if n, err := key.Decrypt(context.Background(), ciphertext, aad, result); err != nil || string(result[:n]) != "hello" {
			t.Errorf("aad %q: %q, %v", aad, result[:n], err)
		}
	}
}

func TestKey_AMismatchedAAD_FailsAuthentication(t *testing.T) {
	key, _ := newTestKey(t)
	ciphertext, _ := key.Encrypt(context.Background(), []byte("hello"), []byte("right"))

	if _, err := key.Decrypt(context.Background(), ciphertext, []byte("wrong"), make([]byte, 5)); !errors.Is(err, hkdfguard.ErrAuthenticationFailed) {
		t.Errorf("error = %v", err)
	}
}

func TestKey_ZeroesThePlaintext(t *testing.T) {
	key, _ := newTestKey(t)
	plaintext := []byte("top secret")

	_, _ = key.Encrypt(context.Background(), plaintext, nil)

	if !hkdfguard.IsZero(plaintext) {
		t.Errorf("plaintext left as %q", plaintext)
	}
}

func TestKey_TrimsToWhatTheProviderWrote(t *testing.T) {
	provider := newTestProvider(t)
	provider.overhead = 10 // over-allocates
	ciphertext, err := NewKey(provider).Encrypt(context.Background(), []byte("hello"), nil)

	if err != nil || len(ciphertext) != 5+28 || cap(ciphertext) != len(ciphertext) {
		t.Errorf("ciphertext len %d cap %d, %v", len(ciphertext), cap(ciphertext), err)
	}
}

func TestKey_Close_ClosesTheProviderOnce(t *testing.T) {
	key, provider := newTestKey(t)

	_ = key.Close()
	_ = key.Close()

	if provider.closes() != 1 {
		t.Errorf("provider closed %d times", provider.closes())
	}
}

func TestKey_WithSensitiveLoggingEnabled_StillRoundTrips(t *testing.T) {
	telemetry := diagnostics.DataProtection
	original := telemetry.SensitiveLoggingEnabled()
	telemetry.SetSensitiveLogging(true)
	t.Cleanup(func() { telemetry.SetSensitiveLogging(original) })

	key, _ := newTestKey(t)
	ciphertext, _ := key.Encrypt(context.Background(), []byte("hello"), nil)
	result := make([]byte, 5)
	if n, err := key.Decrypt(context.Background(), ciphertext, nil, result); err != nil || !bytes.Equal(result[:n], []byte("hello")) {
		t.Errorf("%q, %v", result[:n], err)
	}
}
