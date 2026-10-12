package dek

import (
	"bytes"
	"context"
	"errors"
	"math"
	"testing"

	"github.com/runsecure/hkdfguard-go"
)

func mustAdd(t *testing.T, ring *KeyRing, version int) *testProvider {
	t.Helper()
	key, provider := newTestKey(t)
	if err := ring.Add(bg, version, key); err != nil {
		t.Fatalf("Add(%d): %v", version, err)
	}
	return provider
}

func newRing(t *testing.T) *KeyRing {
	t.Helper()
	ring := NewKeyRing(nil)
	t.Cleanup(func() { _ = ring.Close() })
	return ring
}

func requireCurrent(t *testing.T, ring *KeyRing, want int) {
	t.Helper()
	if got, err := ring.CurrentVersion(); err != nil || got != want {
		t.Errorf("CurrentVersion = %d, %v; want %d", got, err, want)
	}
}

func TestKeyRing_SatisfiesTheInterface_AndStartsEmpty(t *testing.T) {
	var ring hkdfguard.KeyRing = newRing(t)

	if _, err := ring.CurrentVersion(); !errors.Is(err, hkdfguard.ErrNoCurrentKey) {
		t.Errorf("CurrentVersion: %v", err)
	}
	if _, _, err := ring.Current(bg); !errors.Is(err, hkdfguard.ErrNoCurrentKey) {
		t.Errorf("Current: %v", err)
	}
}

func TestAdd_TheHighestVersionIsCurrent_WhateverTheOrder(t *testing.T) {
	ring := newRing(t)
	mustAdd(t, ring, 1)
	requireCurrent(t, ring, 1)
	mustAdd(t, ring, 3)
	requireCurrent(t, ring, 3)
	mustAdd(t, ring, 2)
	requireCurrent(t, ring, 3)
}

func TestAdd_EveryInt32Version_Works_AndNoOtherDoes(t *testing.T) {
	for _, version := range []int{math.MinInt32, -1, 0, math.MaxInt32} {
		ring := newRing(t)
		mustAdd(t, ring, version)
		requireCurrent(t, ring, version)

		protector, _ := ring.CreateProtector("range")
		if got, err := unprotect(protector, protect(t, protector, "value")); err != nil || got != "value" {
			t.Errorf("version %d: %q, %v", version, got, err)
		}
	}

	ring := newRing(t)
	mustAdd(t, ring, math.MinInt32)
	mustAdd(t, ring, 5)
	requireCurrent(t, ring, 5)

	for _, version := range []int{math.MaxInt32 + 1, math.MinInt32 - 1} {
		key, _ := newTestKey(t)
		if err := ring.Add(bg, version, key); !errors.Is(err, ErrVersionOutOfRange) {
			t.Errorf("Add(%d): %v", version, err)
		}
	}
}

func TestAdd_ADuplicateVersion_IsRefused_AndOwnershipStaysWithTheCaller(t *testing.T) {
	ring := newRing(t)
	mustAdd(t, ring, 1)
	key, provider := newTestKey(t)

	if err := ring.Add(bg, 1, key); !errors.Is(err, ErrDuplicateVersion) {
		t.Fatalf("error = %v", err)
	}
	_ = ring.Close()
	if provider.closes() != 0 {
		t.Error("the ring closed a key it refused")
	}
}

func TestGetTryGetAndCurrent(t *testing.T) {
	ring := newRing(t)
	key, _ := newTestKey(t)
	_ = ring.Add(bg, 4, key)

	if got, err := ring.Get(bg, 4); err != nil || got != key {
		t.Errorf("Get(4) = %v, %v", got, err)
	}
	if got, ok := ring.TryGet(bg, 4); !ok || got != key {
		t.Errorf("TryGet(4) = %v, %v", got, ok)
	}
	if version, got, err := ring.Current(bg); err != nil || version != 4 || got != key {
		t.Errorf("Current = %d, %v, %v", version, got, err)
	}
	if _, err := ring.Get(bg, 9); !errors.Is(err, hkdfguard.ErrKeyNotFound) {
		t.Errorf("Get(9): %v", err)
	}
	if _, ok := ring.TryGet(bg, 9); ok {
		t.Error("TryGet(9) found a key")
	}
}

func TestClose_ClosesEveryKeyOnce_AndRefusesLaterAdds(t *testing.T) {
	ring := NewKeyRing(nil)
	first, second := mustAdd(t, ring, 1), mustAdd(t, ring, 2)

	_ = ring.Close()
	_ = ring.Close()

	if first.closes() != 1 || second.closes() != 1 {
		t.Errorf("keys closed %d and %d times", first.closes(), second.closes())
	}
	key, _ := newTestKey(t)
	if err := ring.Add(bg, 3, key); !errors.Is(err, hkdfguard.ErrClosed) {
		t.Errorf("Add after Close: %v", err)
	}
	protector, _ := ring.CreateProtector("after")
	if _, err := protector.Encrypt(bg, []byte("x")); !errors.Is(err, hkdfguard.ErrClosed) {
		t.Errorf("Encrypt after Close: %v", err)
	}
}

func TestClose_LeavesKeysThatAreNotClosersAlone(t *testing.T) {
	ring := NewKeyRing(nil)
	_ = ring.Add(bg, 1, notACloser{})

	if err := ring.Close(); err != nil {
		t.Error(err)
	}
}

type notACloser struct{}

func (notACloser) Encrypt(context.Context, []byte, []byte) ([]byte, error)      { return nil, nil }
func (notACloser) Decrypt(context.Context, []byte, []byte, []byte) (int, error) { return 0, nil }

// --- Protectors -----------------------------------------------------------------------------

func TestProtector_RoundTrips_AndLeavesTheCallersPlaintextAlone(t *testing.T) {
	ring := newRing(t)
	mustAdd(t, ring, 1)
	protector, _ := ring.CreateProtector("purpose")
	plaintext := []byte("héllo wörld ✓")

	formatted, err := protector.Encrypt(bg, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != "héllo wörld ✓" {
		t.Error("Encrypt changed the caller's plaintext")
	}
	if got, err := unprotect(protector, formatted); err != nil || got != "héllo wörld ✓" {
		t.Errorf("%q, %v", got, err)
	}
}

func TestProtector_EncryptsUnderTheCurrentVersion_AndDecryptsUnderTheOneNamed(t *testing.T) {
	ring := newRing(t)
	mustAdd(t, ring, 1)
	protector, _ := ring.CreateProtector("purpose")
	underV1 := protect(t, protector, "old")

	mustAdd(t, ring, 2)
	underV2 := protect(t, protector, "new")

	if underV1[:8] != "enc::v1:" || underV2[:8] != "enc::v2:" {
		t.Errorf("versions: %q, %q", underV1[:8], underV2[:8])
	}
	if got, _ := unprotect(protector, underV1); got != "old" {
		t.Errorf("v1 value = %q", got)
	}
}

func TestProtector_AnotherNameOrAMissingVersionOrMalformedInput_Fails(t *testing.T) {
	ring := newRing(t)
	mustAdd(t, ring, 1)
	protector, _ := ring.CreateProtector("one")
	other, _ := ring.CreateProtector("two")
	formatted := protect(t, protector, "hello")

	if _, err := unprotect(other, formatted); !errors.Is(err, hkdfguard.ErrAuthenticationFailed) {
		t.Errorf("another name: %v", err)
	}
	if _, err := unprotect(protector, "enc::v9"+formatted[6:]); !errors.Is(err, hkdfguard.ErrKeyNotFound) {
		t.Errorf("missing version: %v", err)
	}
	if _, err := protector.Decrypt(bg, "not-a-valid-format", make([]byte, 16)); !errors.Is(err, ErrInvalidFormat) {
		t.Errorf("malformed: %v", err)
	}
}

func TestProtector_OnAnEmptyRing_Fails(t *testing.T) {
	protector, _ := newRing(t).CreateProtector("empty")

	if _, err := protector.Encrypt(bg, []byte("x")); !errors.Is(err, hkdfguard.ErrNoCurrentKey) {
		t.Errorf("error = %v", err)
	}
}

func TestCreateProtector_RefusesEmptyInvalidAndReservedNames(t *testing.T) {
	ring := newRing(t)
	for _, name := range []string{"", "Key\xff", hkdfguard.CacheAADPrefix, hkdfguard.CacheAADPrefix + "item"} {
		if _, err := ring.CreateProtector(name); !errors.Is(err, ErrInvalidProtectorName) {
			t.Errorf("%q: %v", name, err)
		}
	}
	for _, name := range []string{"HkdfGuard.Cache", "hkdfguard.cache:item", "x" + hkdfguard.CacheAADPrefix} {
		if _, err := ring.CreateProtector(name); err != nil {
			t.Errorf("%q refused: %v", name, err)
		}
	}
}

func TestAProtectorForAConfigurationPurpose_UsesTheSameAADAsThePipeline(t *testing.T) {
	// This shared AAD is what lets a value a PipelineDataProtector wrote for a configuration key
	// decrypt through the ring's protector for that key's purpose.
	purpose, _ := hkdfguard.ConfigurationPurpose("ConnectionStrings:Admin")
	aad, _ := hkdfguard.ConfigurationAAD("ConnectionStrings:Admin")
	p, _ := newRing(t).CreateProtector(purpose)

	if !bytes.Equal(p.(*protector).aad, aad) {
		t.Error("the protector's AAD is not ConfigurationAAD")
	}
}
