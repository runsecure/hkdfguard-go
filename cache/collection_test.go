package cache

import (
	"context"
	"errors"
	"testing"

	"github.com/runsecure/hkdfguard-go"
)

type ctx = context.Context

func cacheWith(t *testing.T, values map[string]string) *Cache {
	t.Helper()
	c := newCache(t)
	for name, value := range values {
		mustAdd(t, c, name, value)
	}
	return c
}

func TestCollection_Add_ChainsAndAppends(t *testing.T) {
	collection := NewCollection()
	first, second := newCache(t), newCache(t)

	if collection.Add(first).Add(second) != collection {
		t.Error("Add did not return the collection")
	}
	if len(collection.sources) != 2 || collection.sources[0] != first || collection.sources[1] != second {
		t.Error("sources not appended in order")
	}
}

func TestCollection_WithNoSources_HasNothing(t *testing.T) {
	collection := NewCollection()

	if n, err := collection.Decrypt(bg, "item", make([]byte, 8)); n != 0 || err != nil {
		t.Errorf("Decrypt = %d, %v", n, err)
	}
	if _, ok, err := collection.MaxDecryptedLength(bg, "item"); ok || err != nil {
		t.Errorf("MaxDecryptedLength ok = %v, %v", ok, err)
	}
}

func TestCollection_TheFirstSourceWithTheName_Wins_AndLaterOnesAreFallbacks(t *testing.T) {
	first := cacheWith(t, map[string]string{"shared": "from first", "only-first": "first only"})
	second := cacheWith(t, map[string]string{"shared": "from second", "only-second": "second only"})
	collection := NewCollection(first, second)

	cases := map[string]string{"shared": "from first", "only-first": "first only", "only-second": "second only"}
	for name, want := range cases {
		if got, ok := get(t, collection, name); !ok || got != want {
			t.Errorf("%s = %q, %v", name, got, ok)
		}
	}
	if _, ok := get(t, collection, "nowhere"); ok {
		t.Error("a name no source has was found")
	}
}

func TestCollection_MixesWritableAndPullThroughSources(t *testing.T) {
	local := cacheWith(t, map[string]string{"local": "added here"})
	remote := newReadOnly(t, &fakeSource{values: map[string]string{"remote": "from the store"}})
	collection := NewCollection(local, remote)

	if got, _ := get(t, collection, "local"); got != "added here" {
		t.Errorf("local = %q", got)
	}
	if got, _ := get(t, collection, "remote"); got != "from the store" {
		t.Errorf("remote = %q", got)
	}
}

func TestCollection_ASourceError_StopsTheSearch_AndIsReturned(t *testing.T) {
	unreachable := errors.New("store unreachable")
	collection := NewCollection(newReadOnly(t, &fakeSource{err: unreachable}), cacheWith(t, map[string]string{"item": "value"}))

	if _, err := collection.Decrypt(bg, "item", make([]byte, 64)); !errors.Is(err, unreachable) {
		t.Errorf("Decrypt: %v", err)
	}
	if _, _, err := collection.MaxDecryptedLength(bg, "item"); !errors.Is(err, unreachable) {
		t.Errorf("MaxDecryptedLength: %v", err)
	}
}

func TestCollection_WithSensitiveLoggingEnabled_StillWorks(t *testing.T) {
	withSensitiveLogging(t)
	collection := NewCollection(cacheWith(t, map[string]string{"item": "value"}))

	if got, _ := get(t, collection, "item"); got != "value" {
		t.Errorf("got %q", got)
	}
}

func TestEveryCache_SatisfiesItsInterface(t *testing.T) {
	var _ hkdfguard.ProtectedCache = newCache(t)
	var _ hkdfguard.ProtectedReadOnlyCache = newReadOnly(t, &fakeSource{})
	var _ hkdfguard.ProtectedReadOnlyCache = NewCollection()
}
