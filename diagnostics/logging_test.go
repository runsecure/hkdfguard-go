package diagnostics

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

// capturingHandler records every slog record it is handed.
type capturingHandler struct {
	enabled bool
	records []slog.Record
}

func (h *capturingHandler) Enabled(context.Context, slog.Level) bool { return h.enabled }

func (h *capturingHandler) Handle(_ context.Context, r slog.Record) error {
	h.records = append(h.records, r)
	return nil
}

func (h *capturingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *capturingHandler) WithGroup(string) slog.Handler      { return h }

func newCapturingLogger(enabled bool) (*slog.Logger, *capturingHandler) {
	h := &capturingHandler{enabled: enabled}
	return slog.New(h), h
}

func recordAttrs(r slog.Record) map[string]slog.Value {
	attrs := map[string]slog.Value{}
	r.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value
		return true
	})
	return attrs
}

// single asserts exactly one record was written at level with eventID, returning it and its attributes.
func single(t *testing.T, h *capturingHandler, level slog.Level, eventID int64) (slog.Record, map[string]slog.Value) {
	t.Helper()
	if len(h.records) != 1 {
		t.Fatalf("wrote %d records, want 1", len(h.records))
	}
	r := h.records[0]
	attrs := recordAttrs(r)
	if r.Level != level {
		t.Errorf("level = %v, want %v", r.Level, level)
	}
	if got := attrs[LogKeyEventID].Int64(); got != eventID {
		t.Errorf("%s = %d, want %d", LogKeyEventID, got, eventID)
	}
	return r, attrs
}

func assertError(t *testing.T, attrs map[string]slog.Value, want error) {
	t.Helper()
	if got, _ := attrs[LogKeyError].Any().(error); got != want {
		t.Errorf("%s = %v, want %v", LogKeyError, got, want)
	}
}

func TestSensitiveOperationLogged_WritesADebugRecordNamingTheOperationAndName(t *testing.T) {
	logger, h := newCapturingLogger(true)

	SensitiveOperationLogged(context.Background(), logger, SpanCacheAdd, "item")

	r, attrs := single(t, h, slog.LevelDebug, 1)
	if r.Message != "hkdfguard.cache.add completed for item." {
		t.Errorf("message = %q", r.Message)
	}
	if attrs[string(AttrName)].String() != "item" {
		t.Errorf("%s = %q, want item", AttrName, attrs[string(AttrName)].String())
	}
}

func TestOperationFailed_WritesAnErrorRecordCarryingTheError(t *testing.T) {
	logger, h := newCapturingLogger(true)
	failure := errors.New("boom")

	OperationFailed(context.Background(), logger, SpanCacheAdd, failure)

	r, attrs := single(t, h, slog.LevelError, 2)
	if r.Message != "hkdfguard.cache.add failed." {
		t.Errorf("message = %q", r.Message)
	}
	assertError(t, attrs, failure)
}

func TestKeyRefreshFailed_WritesAnErrorRecordWithTheCountPolicyAndError(t *testing.T) {
	logger, h := newCapturingLogger(true)
	failure := errors.New("KEK unavailable")

	KeyRefreshFailed(context.Background(), logger, 2, "fail closed after 3 consecutive failures", failure)

	r, attrs := single(t, h, slog.LevelError, 3)
	if r.Message != "Background key refresh failed (2 consecutive). Policy: fail closed after 3 consecutive failures." {
		t.Errorf("message = %q", r.Message)
	}
	assertError(t, attrs, failure)
}

func TestKeyAccessSuspended_WritesACriticalRecord(t *testing.T) {
	logger, h := newCapturingLogger(true)

	KeyAccessSuspended(context.Background(), logger, 3)

	r, _ := single(t, h, LevelCritical, 4)
	if !strings.HasPrefix(r.Message, "Key access suspended after 3 consecutive failed refreshes") {
		t.Errorf("message = %q", r.Message)
	}
}

func TestKeyAccessResumed_WritesAnInfoRecord(t *testing.T) {
	logger, h := newCapturingLogger(true)

	KeyAccessResumed(context.Background(), logger, 4)

	r, _ := single(t, h, slog.LevelInfo, 5)
	if r.Message != "Key access resumed: a background refresh succeeded after 4 consecutive failures." {
		t.Errorf("message = %q", r.Message)
	}
}

func TestEphemeralKeyRotated_WritesAnInfoRecordNamingTheNewVersion(t *testing.T) {
	logger, h := newCapturingLogger(true)

	EphemeralKeyRotated(context.Background(), logger, 8)

	r, attrs := single(t, h, slog.LevelInfo, 6)
	if r.Message != "Ephemeral key rotated: version 8 is now current." {
		t.Errorf("message = %q", r.Message)
	}
	if attrs[string(AttrKeyVersion)].Int64() != 8 {
		t.Errorf("%s = %v, want 8", AttrKeyVersion, attrs[string(AttrKeyVersion)])
	}
}

func TestEphemeralKeyRotationFailed_WritesAnErrorRecordNamingTheVersionStillCurrent(t *testing.T) {
	logger, h := newCapturingLogger(true)
	failure := errors.New("KEK unavailable")

	EphemeralKeyRotationFailed(context.Background(), logger, 7, failure)

	r, attrs := single(t, h, slog.LevelError, 7)
	if r.Message != "Ephemeral key rotation failed; version 7 stays current until the next attempt." {
		t.Errorf("message = %q", r.Message)
	}
	assertError(t, attrs, failure)
}

func TestEphemeralKeyRetired_WritesAnInfoRecord(t *testing.T) {
	logger, h := newCapturingLogger(true)

	EphemeralKeyRetired(context.Background(), logger, 5)

	r, _ := single(t, h, slog.LevelInfo, 8)
	if r.Message != "Ephemeral key retired: version 5 has been removed and its key zeroed; values encrypted under it no longer decrypt." {
		t.Errorf("message = %q", r.Message)
	}
}

func TestEphemeralKeyRetirementFailed_WritesAnErrorRecordCarryingTheError(t *testing.T) {
	logger, h := newCapturingLogger(true)
	failure := errors.New("dispose failed")

	EphemeralKeyRetirementFailed(context.Background(), logger, 5, failure)

	r, attrs := single(t, h, slog.LevelError, 9)
	if r.Message != "Ephemeral key version 5 was removed from the ring, but disposing it failed." {
		t.Errorf("message = %q", r.Message)
	}
	assertError(t, attrs, failure)
}

func TestEncryptionBudgetWarning_WritesAWarnRecordWithCountAndLimit(t *testing.T) {
	logger, h := newCapturingLogger(true)

	EncryptionBudgetWarning(context.Background(), logger, 100, 200)

	r, attrs := single(t, h, slog.LevelWarn, 10)
	if r.Message != "This key has performed 100 encryptions of its 200 AES-GCM limit; rotate it before the limit, when it stops encrypting." {
		t.Errorf("message = %q", r.Message)
	}
	if attrs[string(AttrEncryptionCount)].Int64() != 100 || attrs[string(AttrEncryptionLimit)].Int64() != 200 {
		t.Errorf("count/limit attributes = %v/%v, want 100/200", attrs[string(AttrEncryptionCount)], attrs[string(AttrEncryptionLimit)])
	}
}

func TestLogHelpers_WhenTheLevelIsDisabledOrTheLoggerIsNil_WriteNothing(t *testing.T) {
	ctx := context.Background()
	disabled, h := newCapturingLogger(false)

	for _, logger := range []*slog.Logger{disabled, nil} {
		SensitiveOperationLogged(ctx, logger, SpanCacheAdd, "item")
		OperationFailed(ctx, logger, SpanCacheAdd, errors.New("x"))
		KeyRefreshFailed(ctx, logger, 1, "fail open", errors.New("x"))
		KeyAccessSuspended(ctx, logger, 1)
		KeyAccessResumed(ctx, logger, 1)
		EphemeralKeyRotated(ctx, logger, 1)
		EphemeralKeyRotationFailed(ctx, logger, 1, errors.New("x"))
		EphemeralKeyRetired(ctx, logger, 1)
		EphemeralKeyRetirementFailed(ctx, logger, 1, errors.New("x"))
		EncryptionBudgetWarning(ctx, logger, 1, 2)
	}

	if len(h.records) != 0 {
		t.Errorf("wrote %d records, want 0", len(h.records))
	}
}
