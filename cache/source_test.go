package cache

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

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

func TestReadOnlyCache_ConcurrentMisses_InAnyASCIICase_ShareOneFetch(t *testing.T) {
	// The source is asked with whichever spelling starts the fetch; the fake must know them all.
	source := &fakeSource{values: map[string]string{"api-key": "v", "API-KEY": "v", "Api-Key": "v"}, block: make(chan struct{}), started: make(chan string, 64)}
	c := newReadOnly(t, source)

	var wg sync.WaitGroup
	results := make([]string, 16)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], _ = get(t, c, []string{"api-key", "API-KEY", "Api-Key"}[i%3])
		}()
	}
	<-source.started
	time.Sleep(50 * time.Millisecond) // let the others start waiting
	close(source.block)
	wg.Wait()

	if n := source.fetchCount(); n != 1 {
		t.Errorf("fetched %d times", n)
	}
	for i, got := range results {
		if got != "v" {
			t.Errorf("lookup %d: got %q", i, got)
		}
	}
}

func TestReadOnlyCache_AWaiterWhoseStarterWasCancelled_FetchesAgain(t *testing.T) {
	source := &fakeSource{values: map[string]string{"s": "v"}, block: make(chan struct{}), started: make(chan string, 4)}
	c := newReadOnly(t, source)

	starterCtx, cancel := context.WithCancel(bg)
	starterErr := make(chan error, 1)
	go func() {
		_, err := c.Decrypt(starterCtx, "s", make([]byte, 64))
		starterErr <- err
	}()
	<-source.started

	waiter := make(chan string, 1)
	go func() {
		got, _ := get(t, c, "s")
		waiter <- got
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	if err := <-starterErr; !errors.Is(err, context.Canceled) {
		t.Errorf("starter: got %v", err)
	}
	<-source.started // the waiter's own fetch
	close(source.block)
	if got := <-waiter; got != "v" {
		t.Errorf("waiter: got %q", got)
	}
}

func TestReadOnlyCache_AWaiterWhoseOwnContextEnds_StopsWaiting(t *testing.T) {
	source := &fakeSource{values: map[string]string{"s": "v"}, block: make(chan struct{}), started: make(chan string, 4)}
	c := newReadOnly(t, source)
	go func() { _, _ = c.Decrypt(bg, "s", make([]byte, 64)) }()
	<-source.started

	ctx, cancel := context.WithTimeout(bg, 20*time.Millisecond)
	defer cancel()
	if _, err := c.Decrypt(ctx, "s", make([]byte, 64)); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("got %v", err)
	}
	close(source.block)
}

func TestReadOnlyCache_APanickingSource_FailsTheLookup_AndReleasesWaiters(t *testing.T) {
	c := newReadOnly(t, SourceFunc(func(context.Context, string) ([]byte, bool, error) { panic("bad source") }))
	if _, err := c.Decrypt(bg, "s", make([]byte, 8)); err == nil || !strings.Contains(err.Error(), "panicked") {
		t.Errorf("got %v", err)
	}
	if _, _, err := c.MaxDecryptedLength(bg, "s"); err == nil || !strings.Contains(err.Error(), "panicked") {
		t.Errorf("got %v", err)
	}
}

func TestReadOnlyCache_TheLogger_RecordsEachFetchOnceItHasReturned_AndEveryFailure(t *testing.T) {
	withSensitiveLogging(t)
	logger, logs := newLogger()
	unreachable := errors.New("store unreachable")
	source := &fakeSource{values: map[string]string{"item": "v", "empty": ""}}
	ring, _ := newRing(t, 1)
	c := NewReadOnly(ring, source, WithLogger(logger))

	get(t, c, "item")
	get(t, c, "item") // cached: no fetch, nothing logged
	get(t, c, "absent")
	_, _ = c.Decrypt(bg, "empty", make([]byte, 8))
	source.err = unreachable
	_, _ = c.Decrypt(bg, "other", make([]byte, 8))

	// The item fetched and the one the source lacks completed; the empty value and the failure did not.
	completed := logs.withEventID(1)
	if len(completed) != 2 || !strings.Contains(completed[0].Message, "hkdfguard.cache.populate completed for item.") ||
		!strings.Contains(completed[1].Message, "hkdfguard.cache.populate completed for absent.") {
		t.Errorf("completed: %v", messages(completed))
	}
	failures := logs.withEventID(2)
	if len(failures) != 2 || !strings.Contains(attrText(failures[0], "error"), ErrEmptyValue.Error()) ||
		!strings.Contains(attrText(failures[1], "error"), unreachable.Error()) {
		t.Errorf("failures: %v", messages(failures))
	}
	for _, r := range logs.records {
		if strings.Contains(r.Message, "hkdfguard.cache.decrypt") {
			t.Errorf("a fetch failure was logged twice: %q", r.Message)
		}
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
