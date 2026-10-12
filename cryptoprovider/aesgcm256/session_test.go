package aesgcm256

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"sync"
	"testing"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/diagnostics"
)

func newTestSession(t *testing.T, key []byte) *session {
	t.Helper()
	s, err := newSession(key, defaultBudget(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.close)
	return s
}

func encryptWith(t *testing.T, s *session, plaintext, aad []byte) []byte {
	t.Helper()
	result := make([]byte, len(plaintext)+Overhead)
	n, ok, err := s.tryEncrypt(context.Background(), bytes.Clone(plaintext), aad, result)
	if !ok || err != nil || n != len(result) {
		t.Fatalf("tryEncrypt = %d, %v, %v", n, ok, err)
	}
	return result
}

func decryptWith(s *session, ciphertext, aad, result []byte) (int, error) {
	n, ok, err := s.tryDecrypt(context.Background(), ciphertext, aad, result)
	if !ok {
		return 0, hkdfguard.ErrClosed
	}
	return n, err
}

func TestSession_RoundTrips_WithAndWithoutAAD(t *testing.T) {
	s := newTestSession(t, randomKey(t))
	for _, aad := range [][]byte{nil, []byte("purpose")} {
		plaintext := []byte("hello, world")
		ciphertext := encryptWith(t, s, plaintext, aad)

		result := make([]byte, len(plaintext))
		if n, err := decryptWith(s, ciphertext, aad, result); err != nil || !bytes.Equal(result[:n], plaintext) {
			t.Errorf("aad %q: decrypted %q, %v", aad, result[:n], err)
		}
	}
}

func TestSession_TheWireFormatIsNonceThenStandardGCM(t *testing.T) {
	// [12-byte nonce | ciphertext | 16-byte tag], decryptable by any standard AES-GCM - the
	// layout the .NET port reads and writes.
	key := randomKey(t)
	ciphertext := encryptWith(t, newTestSession(t, bytes.Clone(key)), []byte("interop"), []byte("aad"))

	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	plaintext, err := gcm.Open(nil, ciphertext[:NonceSize], ciphertext[NonceSize:], []byte("aad"))
	if err != nil || string(plaintext) != "interop" {
		t.Errorf("standard GCM open = %q, %v", plaintext, err)
	}
}

func TestSession_AuthenticationFailures_ReportTheSentinelAndZeroTheResult(t *testing.T) {
	s := newTestSession(t, randomKey(t))
	ciphertext := encryptWith(t, s, []byte("hello"), []byte("right"))
	tampered := bytes.Clone(ciphertext)
	tampered[NonceSize] ^= 0xFF

	cases := map[string]struct{ ciphertext, aad []byte }{
		"wrong aad": {ciphertext, []byte("wrong")},
		"tampered":  {tampered, []byte("right")},
	}
	for name, c := range cases {
		result := bytes.Repeat([]byte{0xAB}, 5)
		if _, err := decryptWith(s, c.ciphertext, c.aad, result); !errors.Is(err, hkdfguard.ErrAuthenticationFailed) {
			t.Errorf("%s: error = %v", name, err)
		}
		if !hkdfguard.IsZero(result) {
			t.Errorf("%s: result = %v, want zeroed", name, result)
		}
	}
}

func TestSession_BadLengths_AreRefused(t *testing.T) {
	s := newTestSession(t, randomKey(t))
	ciphertext := encryptWith(t, s, []byte("hello"), nil)

	if _, ok, err := s.tryEncrypt(context.Background(), []byte("hello"), nil, make([]byte, 5+Overhead-1)); !ok || !errors.Is(err, ErrInvalidLength) {
		t.Errorf("small encrypt result: %v", err)
	}
	for _, short := range [][]byte{nil, make([]byte, Overhead-1)} {
		if _, err := decryptWith(s, short, nil, make([]byte, 4)); !errors.Is(err, ErrInvalidLength) {
			t.Errorf("short ciphertext (%d): %v", len(short), err)
		}
	}
	if _, err := decryptWith(s, ciphertext, nil, make([]byte, 4)); !errors.Is(err, ErrInvalidLength) {
		t.Errorf("small decrypt result: %v", err)
	}
}

func TestSession_RefusesABadKey(t *testing.T) {
	for _, key := range [][]byte{make([]byte, 16), make([]byte, 33), make([]byte, KeySize) /* all zero */} {
		if _, err := newSession(key, defaultBudget(), nil); err == nil {
			t.Errorf("a %d-byte key (zero: %v) was accepted", len(key), hkdfguard.IsZero(key))
		}
	}
}

func TestSession_AnEmptyPlaintext_IsAnAuthenticatedEmptyMessage(t *testing.T) {
	s := newTestSession(t, randomKey(t))
	ciphertext := encryptWith(t, s, nil, []byte("aad"))

	if len(ciphertext) != Overhead {
		t.Errorf("ciphertext is %d bytes, want %d", len(ciphertext), Overhead)
	}
	if n, err := decryptWith(s, ciphertext, []byte("aad"), nil); n != 0 || err != nil {
		t.Errorf("decrypt = %d, %v", n, err)
	}
	if _, err := decryptWith(s, ciphertext, []byte("other"), nil); !errors.Is(err, hkdfguard.ErrAuthenticationFailed) {
		t.Errorf("wrong aad: %v", err)
	}
}

func TestSession_EncryptZeroesThePlaintext_EvenOnFailure(t *testing.T) {
	s := newTestSession(t, randomKey(t))

	ok := []byte("secret")
	s.tryEncrypt(context.Background(), ok, nil, make([]byte, 64))
	failed := []byte("secret")
	s.tryEncrypt(context.Background(), failed, nil, make([]byte, 1))

	if !hkdfguard.IsZero(ok) || !hkdfguard.IsZero(failed) {
		t.Errorf("plaintext left as %q and %q", ok, failed)
	}
}

func TestSession_Close_ZeroesTheKey_AndLaterOperationsTouchNothing(t *testing.T) {
	key := randomKey(t)
	budget := defaultBudget()
	s, _ := newSession(key, budget, nil)
	ciphertext := encryptWith(t, s, []byte("x"), nil)
	countBefore := budget.count.Load()

	s.close()
	s.close() // twice is safe

	if !hkdfguard.IsZero(key) {
		t.Error("the key was not zeroed")
	}
	plaintext := []byte("still here")
	if _, ok, _ := s.tryEncrypt(context.Background(), plaintext, nil, make([]byte, 64)); ok {
		t.Error("tryEncrypt ran on a closed session")
	}
	if string(plaintext) != "still here" || budget.count.Load() != countBefore {
		t.Error("a refused tryEncrypt touched the plaintext or the count")
	}
	if _, ok, _ := s.tryDecrypt(context.Background(), ciphertext, nil, make([]byte, 4)); ok {
		t.Error("tryDecrypt ran on a closed session")
	}
}

func TestSession_ConcurrentOperations_EachUseAFreshNonce_AndRoundTrip(t *testing.T) {
	s := newTestSession(t, randomKey(t))
	const workers, perWorker = 8, 500
	var nonces sync.Map
	var wg sync.WaitGroup

	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range perWorker {
				value := make([]byte, 4)
				binary.LittleEndian.PutUint32(value, uint32(w*perWorker+i))
				ciphertext := make([]byte, 4+Overhead)
				if _, _, err := s.tryEncrypt(context.Background(), bytes.Clone(value), nil, ciphertext); err != nil {
					t.Error(err)
					return
				}
				if _, loaded := nonces.LoadOrStore(string(ciphertext[:NonceSize]), true); loaded {
					t.Error("nonce repeated")
				}
				decrypted := make([]byte, 4)
				if _, err := decryptWith(s, ciphertext, nil, decrypted); err != nil || !bytes.Equal(decrypted, value) {
					t.Errorf("round trip: %v", err)
				}
			}
		}()
	}
	wg.Wait()
}

func TestSession_WithSensitiveLoggingEnabled_StillRoundTrips(t *testing.T) {
	telemetry := diagnostics.CryptoProviderAESGCM256
	original := telemetry.SensitiveLoggingEnabled()
	telemetry.SetSensitiveLogging(true)
	t.Cleanup(func() { telemetry.SetSensitiveLogging(original) })
	useSpanRecorder(t)

	s := newTestSession(t, randomKey(t))
	result := make([]byte, 5)
	if n, err := decryptWith(s, encryptWith(t, s, []byte("hello"), nil), nil, result); err != nil || string(result[:n]) != "hello" {
		t.Errorf("round trip = %q, %v", result[:n], err)
	}
}

// --- Encryption budget ----------------------------------------------------------------------

func TestBudget_Defaults_AreHalfAndOneEighthOfTheNISTLimit(t *testing.T) {
	b := defaultBudget()
	if b.limit != 1<<31 || b.warningThreshold != 1<<28 || b.count.Load() != 0 {
		t.Errorf("budget = %d/%d/%d", b.limit, b.warningThreshold, b.count.Load())
	}
	if MaxEncryptionsPerKey != 1<<31 || EncryptionWarningThreshold != 1<<28 {
		t.Error("the public limits don't match the defaults")
	}
}

func TestBudget_WarnsExactlyOnce_AtTheThreshold(t *testing.T) {
	b, _ := newEncryptionBudget(3, 10)
	var warnings []bool
	for range 6 {
		warn, _ := b.consume()
		warnings = append(warnings, warn)
	}

	if want := []bool{false, false, true, false, false, false}; !equalBools(warnings, want) || b.count.Load() != 6 {
		t.Errorf("warnings = %v, count = %d", warnings, b.count.Load())
	}
}

func equalBools(a, b []bool) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestBudget_PastTheLimit_FailsAndLeavesTheCountAtTheLimit(t *testing.T) {
	b, _ := newEncryptionBudget(1, 2)
	b.consume()
	b.consume()

	for range 2 {
		if _, err := b.consume(); !errors.Is(err, hkdfguard.ErrEncryptionLimitReached) {
			t.Errorf("error = %v", err)
		}
	}
	if b.count.Load() != 2 {
		t.Errorf("count = %d", b.count.Load())
	}
}

func TestBudget_UnderConcurrency_NeverExceedsTheLimit(t *testing.T) {
	b, _ := newEncryptionBudget(1, 1000)
	var successes sync.WaitGroup
	var mu sync.Mutex
	succeeded := 0

	for range 8 {
		successes.Add(1)
		go func() {
			defer successes.Done()
			for range 500 {
				if _, err := b.consume(); err == nil {
					mu.Lock()
					succeeded++
					mu.Unlock()
				}
			}
		}()
	}
	successes.Wait()

	if succeeded != 1000 || b.count.Load() != 1000 {
		t.Errorf("succeeded %d, count %d", succeeded, b.count.Load())
	}
}

func TestBudget_InvalidThresholdOrLimit_IsRefused(t *testing.T) {
	for _, c := range [][2]int64{{0, 10}, {11, 10}, {1, 0}} {
		if _, err := newEncryptionBudget(c[0], c[1]); err == nil {
			t.Errorf("threshold %d, limit %d accepted", c[0], c[1])
		}
	}
}

func TestBudgetFor_IsSharedPerKey(t *testing.T) {
	key := randomKey(t)
	if budgetFor(key) != budgetFor(bytes.Clone(key)) {
		t.Error("the same key got two budgets")
	}
	if budgetFor(key) == budgetFor(randomKey(t)) {
		t.Error("two keys share a budget")
	}
}
