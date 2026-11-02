package dek

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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

func TestKey_StopsEncryptingAtItsDeadline_ZeroingThePlaintext_ButKeepsDecrypting(t *testing.T) {
	var calls []string
	now := time.Now()
	key := NewKeyWithDeadline(newTestProvider(t), EncryptionDeadline{
		WarnAt: now.Add(time.Second), RefuseAt: now.Add(2 * time.Second), Reason: "rotate me",
		OnWarning: func() { calls = append(calls, "warn") }, OnExpired: func() { calls = append(calls, "expired") },
	})
	key.now = func() time.Time { return now }
	ciphertext, err := key.Encrypt(bg, []byte("before"), nil)
	if err != nil || key.CheckDeadline(now) || len(calls) != 0 {
		t.Fatalf("before the deadline: %v, %v", err, calls)
	}

	now = now.Add(1500 * time.Millisecond)
	for _, plaintext := range []string{"warned", "warned again"} {
		if _, err := key.Encrypt(bg, []byte(plaintext), nil); err != nil {
			t.Fatal(err)
		}
	}
	if !slices.Equal(calls, []string{"warn"}) {
		t.Errorf("calls after the warning = %v", calls)
	}

	now = now.Add(500 * time.Millisecond)
	plaintext := []byte("refused")
	if _, err := key.Encrypt(bg, plaintext, nil); !errors.Is(err, hkdfguard.ErrEncryptionLimitReached) || !strings.HasSuffix(err.Error(), ": rotate me") {
		t.Errorf("Encrypt at the deadline: %v", err)
	}
	if !hkdfguard.IsZero(plaintext) {
		t.Errorf("plaintext left as %q", plaintext)
	}
	if _, err := key.Encrypt(bg, []byte("refused again"), nil); !errors.Is(err, hkdfguard.ErrEncryptionLimitReached) {
		t.Errorf("Encrypt again: %v", err)
	}
	if !slices.Equal(calls, []string{"warn", "expired"}) {
		t.Errorf("calls = %v", calls)
	}

	result := make([]byte, 6)
	if n, err := key.Decrypt(bg, ciphertext, nil, result); err != nil || string(result[:n]) != "before" {
		t.Errorf("Decrypt: %q, %v", result[:n], err)
	}
}

func TestKey_AnnouncesExpiryOnce_EvenWhenTheWarningWasSkipped_AndIgnoresAPanickingCallback(t *testing.T) {
	expired := 0
	key := NewKeyWithDeadline(newTestProvider(t), EncryptionDeadline{
		WarnAt: time.Unix(0, 0), RefuseAt: time.Unix(1, 0), Reason: "old",
		OnWarning: func() { panic("never called") },
		OnExpired: func() { expired++; panic("bad logger") },
	})
	for range 2 {
		if _, err := key.Encrypt(bg, []byte("x"), nil); !errors.Is(err, hkdfguard.ErrEncryptionLimitReached) {
			t.Errorf("Encrypt: %v", err)
		}
	}
	if expired != 1 {
		t.Errorf("OnExpired called %d times", expired)
	}
}

func TestKey_WithoutADeadline_EncryptsWithoutLimit(t *testing.T) {
	key, _ := newTestKey(t)
	if _, ok := key.Deadline(); ok || key.CheckDeadline(time.Unix(1<<62, 0)) {
		t.Error("a key without a deadline is limited")
	}
	if ciphertext, err := key.Encrypt(bg, []byte("hello"), nil); err != nil || len(ciphertext) != 5+28 {
		t.Errorf("len %d, %v", len(ciphertext), err)
	}
}

func TestKey_ConcurrentEncrypts_AnnounceEachDeadlineOnce(t *testing.T) {
	var warnings, expiries atomic.Int32
	now := time.Now()
	for _, c := range []struct {
		name             string
		warnAt, refuseAt time.Time
	}{{"warning", now.Add(-time.Hour), now.Add(time.Hour)}, {"expiry", now.Add(-2 * time.Hour), now.Add(-time.Hour)}} {
		warnings.Store(0)
		expiries.Store(0)
		key := NewKeyWithDeadline(newTestProvider(t), EncryptionDeadline{
			WarnAt: c.warnAt, RefuseAt: c.refuseAt, Reason: "r",
			OnWarning: func() { warnings.Add(1) }, OnExpired: func() { expiries.Add(1) },
		})
		var wg sync.WaitGroup
		for range 32 {
			wg.Go(func() { _, _ = key.Encrypt(bg, []byte("x"), nil) })
		}
		wg.Wait()
		if warnings.Load()+expiries.Load() != 1 {
			t.Errorf("%s: %d warnings, %d expiries", c.name, warnings.Load(), expiries.Load())
		}
	}
}
