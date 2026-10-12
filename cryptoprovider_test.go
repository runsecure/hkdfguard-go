package hkdfguard_test

import (
	"errors"
	"testing"

	"github.com/runsecure/hkdfguard-go"
)

func TestRefreshFailurePolicy_ZeroValue_FailsClosedAfterTheDefault(t *testing.T) {
	var policy hkdfguard.RefreshFailurePolicy

	if limit, failsClosed := policy.MaxFailures(); !failsClosed || limit != hkdfguard.DefaultMaxRefreshFailures {
		t.Errorf("MaxFailures() = %d, %v; want %d, true", limit, failsClosed, hkdfguard.DefaultMaxRefreshFailures)
	}
	if hkdfguard.DefaultMaxRefreshFailures != 3 {
		t.Errorf("DefaultMaxRefreshFailures = %d, want 3", hkdfguard.DefaultMaxRefreshFailures)
	}
	if err := policy.Validate(); err != nil {
		t.Errorf("Validate() = %v", err)
	}
	if got := policy.String(); got != "fail closed after 3 consecutive failures" {
		t.Errorf("String() = %q", got)
	}
}

func TestRefreshFailurePolicy_FailClosedAfter(t *testing.T) {
	policy := hkdfguard.FailClosedAfter(5)

	if limit, failsClosed := policy.MaxFailures(); !failsClosed || limit != 5 {
		t.Errorf("MaxFailures() = %d, %v; want 5, true", limit, failsClosed)
	}
	if got := policy.String(); got != "fail closed after 5 consecutive failures" {
		t.Errorf("String() = %q", got)
	}
}

func TestRefreshFailurePolicy_FailClosedAfterBelowOne_IsInvalid(t *testing.T) {
	for _, n := range []int{0, -1} {
		if err := hkdfguard.FailClosedAfter(n).Validate(); !errors.Is(err, hkdfguard.ErrInvalidRefreshFailurePolicy) {
			t.Errorf("FailClosedAfter(%d).Validate() = %v, want ErrInvalidRefreshFailurePolicy", n, err)
		}
	}
}

func TestRefreshFailurePolicy_FailOpen(t *testing.T) {
	policy := hkdfguard.FailOpen()

	if _, failsClosed := policy.MaxFailures(); failsClosed {
		t.Error("FailOpen() fails closed")
	}
	if err := policy.Validate(); err != nil {
		t.Errorf("Validate() = %v", err)
	}
	if got := policy.String(); got != "fail open (the last good key stays in use)" {
		t.Errorf("String() = %q", got)
	}
}

func TestMaxWrappedKeyBytes(t *testing.T) {
	if hkdfguard.MaxWrappedKeyBytes != 512 {
		t.Errorf("MaxWrappedKeyBytes = %d, want 512", hkdfguard.MaxWrappedKeyBytes)
	}
}
