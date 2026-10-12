package cache

import (
	"errors"
	"log/slog"
	"testing"

	"github.com/runsecure/hkdfguard-go"
)

func newLogger() (*slog.Logger, *capturingHandler) {
	h := &capturingHandler{}
	return slog.New(h), h
}

func newReadOnly(t *testing.T, source Source) *ReadOnlyCache {
	t.Helper()
	ring, _ := newRing(t, 1)
	return NewReadOnly(ring, source)
}

func TestReadOnlyCache_FetchesAMissOnce_ThenServesItFromTheCache(t *testing.T) {
	source := &fakeSource{values: map[string]string{"api-key": "from the store"}}
	c := newReadOnly(t, source)

	// The source is asked with the spelling requested; once cached, every ASCII-case spelling hits.
	for _, name := range []string{"api-key", "API-KEY", "Api-Key"} {
		if got, ok := get(t, c, name); !ok || got != "from the store" {
			t.Fatalf("%s: got %q, %v", name, got, ok)
		}
	}
	if source.fetchCount() != 1 {
		t.Errorf("fetched %d times", source.fetchCount())
	}
	if !hkdfguard.IsZero(source.served[0]) {
		t.Error("the fetched plaintext was not zeroed")
	}
}

func TestReadOnlyCache_ANameTheSourceLacks_IsMissing(t *testing.T) {
	c := newReadOnly(t, &fakeSource{values: map[string]string{}})

	if n, err := c.Decrypt(bg, "missing", make([]byte, 8)); n != 0 || err != nil {
		t.Errorf("Decrypt = %d, %v", n, err)
	}
	if _, ok := get(t, c, "missing"); ok {
		t.Error("a missing name has a value")
	}
}

func TestReadOnlyCache_ASourceError_IsReturned(t *testing.T) {
	unreachable := errors.New("store unreachable")
	c := newReadOnly(t, &fakeSource{err: unreachable})

	if _, err := c.Decrypt(bg, "item", make([]byte, 8)); !errors.Is(err, unreachable) {
		t.Errorf("Decrypt: %v", err)
	}
	if _, _, err := c.MaxDecryptedLength(bg, "item"); !errors.Is(err, unreachable) {
		t.Errorf("MaxDecryptedLength: %v", err)
	}
}

func TestReadOnlyCache_AnEmptyValueFromTheSource_IsRefused(t *testing.T) {
	c := newReadOnly(t, &fakeSource{values: map[string]string{"empty": ""}})

	if _, err := c.Decrypt(bg, "empty", make([]byte, 8)); !errors.Is(err, ErrEmptyValue) {
		t.Errorf("error = %v", err)
	}
}

func TestCache_WithASource_PullsMissesThrough_ButNotHits(t *testing.T) {
	source := &fakeSource{values: map[string]string{"pulled": "from the store", "added": "never used"}}
	ring, _ := newRing(t, 1)
	c := New(ring, WithSource(source))
	mustAdd(t, c, "added", "added locally")

	if got, _ := get(t, c, "added"); got != "added locally" {
		t.Errorf("added = %q", got)
	}
	if got, _ := get(t, c, "pulled"); got != "from the store" {
		t.Errorf("pulled = %q", got)
	}
	if source.fetchCount() != 1 {
		t.Errorf("fetched %d times", source.fetchCount())
	}
}

func TestSourceFunc_AdaptsAFunction(t *testing.T) {
	c := newReadOnly(t, SourceFunc(func(_ ctx, name string) ([]byte, bool, error) {
		return []byte("value of " + name), true, nil
	}))

	if got, _ := get(t, c, "x"); got != "value of x" {
		t.Errorf("got %q", got)
	}
}
