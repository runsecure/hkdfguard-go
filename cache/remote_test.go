package cache

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/runsecure/hkdfguard-go"
)

// fakeSecrets is a SecretStore over an in-memory map: each secret's value is handed over with
// SetBytesWithJSONKeys, so a JSON object's members become keys.
type fakeSecrets struct {
	values  map[string]string
	valid   func(string) bool
	err     error
	fetched atomic.Int32
	names   []string
	mu      sync.Mutex

	// block, when set, is waited on (or ctx) before each fetch hands anything over.
	block chan struct{}
	// started is signalled as each fetch begins.
	started chan string
	// lastSink is the sink the latest fetch was given.
	lastSink *SecretSink
	// handed records each plaintext handed over, to check it was zeroed.
	handed [][]byte
}

func (f *fakeSecrets) IsValidName(name string) bool {
	if f.valid != nil {
		return f.valid(name)
	}
	return name != ""
}

func (f *fakeSecrets) Fetch(ctx context.Context, name string, sink *SecretSink) error {
	f.fetched.Add(1)
	f.mu.Lock()
	f.names = append(f.names, name)
	f.lastSink = sink
	f.mu.Unlock()
	if f.started != nil {
		f.started <- name
	}
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if f.err != nil {
		return f.err
	}
	value, ok := f.values[name]
	if !ok {
		return nil
	}
	plaintext := []byte(value)
	f.mu.Lock()
	f.handed = append(f.handed, plaintext)
	f.mu.Unlock()
	return sink.SetBytesWithJSONKeys(plaintext)
}

func newRemote(t *testing.T, secrets SecretStore, options RemoteOptions) *RemoteCache {
	t.Helper()
	ring, _ := newRing(t, 1)
	c, err := NewRemote(ring, secrets, options)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRemoteCache_OneFetchCachesTheWholeValueAndEveryKey(t *testing.T) {
	secrets := &fakeSecrets{values: map[string]string{
		"app": `{"user":"app","password":"päss\"w","port":5432,"tls":true,"none":null,"nested":{"a":"b"},"list":[1]}`,
	}}
	c := newRemote(t, secrets, RemoteOptions{Matching: Exact})

	for name, want := range map[string]string{
		"app#user": "app", "app#password": "päss\"w", "app#port": "5432", "app#tls": "true",
	} {
		if got, ok := get(t, c, name); !ok || got != want {
			t.Errorf("%s: got %q, %v; want %q", name, got, ok, want)
		}
	}
	if got, ok := get(t, c, "app"); !ok || !strings.HasPrefix(got, `{"user"`) {
		t.Errorf("whole value: got %q, %v", got, ok)
	}
	for _, name := range []string{"app#none", "app#nested", "app#list"} {
		if _, ok := get(t, c, name); ok {
			t.Errorf("%s: a null, object or array member was cached", name)
		}
	}
	// One fetch for every key above, plus one each for the three keys the secret doesn't hold:
	// a missing key isn't remembered.
	if n := secrets.fetched.Load(); n != 4 {
		t.Errorf("fetched %d times, want 4", n)
	}
	if !hkdfguard.IsZero(secrets.handed[0]) {
		t.Error("the plaintext handed to the sink was not zeroed")
	}
}

func TestRemoteCache_ExactMatching_KeepsCaseDistinctSecretsApart(t *testing.T) {
	secrets := &fakeSecrets{values: map[string]string{"prod/Db": "upper", "prod/db": "lower"}}
	c := newRemote(t, secrets, RemoteOptions{Matching: Exact})

	if got, _ := get(t, c, "prod/Db"); got != "upper" {
		t.Errorf("prod/Db: got %q", got)
	}
	if got, _ := get(t, c, "prod/db"); got != "lower" {
		t.Errorf("prod/db: got %q", got)
	}
	if _, ok := get(t, c, "PROD/DB"); ok {
		t.Error("PROD/DB matched a secret of another case")
	}
	// A '!' marks case in entry names, so a name holding one is never fetched.
	if _, ok := get(t, c, "prod/!db"); ok {
		t.Error("a name holding '!' was found")
	}
	secrets.mu.Lock()
	defer secrets.mu.Unlock()
	for _, name := range secrets.names {
		if strings.Contains(name, "!") {
			t.Errorf("fetched %q", name)
		}
	}
}

func TestRemoteCache_IgnoreASCIICase_SharesOneEntry(t *testing.T) {
	secrets := &fakeSecrets{values: map[string]string{"Db-Password": "secret"}}
	c := newRemote(t, secrets, RemoteOptions{Matching: IgnoreASCIICase})

	if got, _ := get(t, c, "Db-Password"); got != "secret" {
		t.Fatalf("got %q", got)
	}
	if got, _ := get(t, c, "DB-PASSWORD"); got != "secret" {
		t.Errorf("another case: got %q", got)
	}
	if n := secrets.fetched.Load(); n != 1 {
		t.Errorf("fetched %d times", n)
	}
}

func TestRemoteCache_KeysAreMatchedExactly(t *testing.T) {
	secrets := &fakeSecrets{values: map[string]string{"s": `{"Key":"upper","key":"lower"}`}}
	c := newRemote(t, secrets, RemoteOptions{Matching: IgnoreASCIICase})

	if got, _ := get(t, c, "s#Key"); got != "upper" {
		t.Errorf("s#Key: got %q", got)
	}
	if got, _ := get(t, c, "S#key"); got != "lower" {
		t.Errorf("S#key: got %q", got)
	}
}

func TestRemoteCache_InvalidNamesAndKeys_AreMissingWithoutAFetch(t *testing.T) {
	secrets := &fakeSecrets{valid: func(n string) bool { return n == "ok" }, values: map[string]string{"ok": "v"}}
	c := newRemote(t, secrets, RemoteOptions{Matching: Exact})

	for _, name := range []string{"nope", "ConnectionStrings:Admin", "ok#", "ok#a b", "ok#a!b", "ok#a#b", "ok#" + strings.Repeat("k", MaxKeyLength+1), "ok#é"} {
		if n, ok, err := c.MaxDecryptedLength(bg, name); ok || n != 0 || err != nil {
			t.Errorf("%q: %d, %v, %v", name, n, ok, err)
		}
	}
	if n := secrets.fetched.Load(); n != 0 {
		t.Errorf("fetched %d times", n)
	}
}

func TestRemoteCache_DefaultKey_IsReadForANameWithoutOne(t *testing.T) {
	secrets := &fakeSecrets{values: map[string]string{"myapp/db": `{"value":"v","password":"p"}`}}
	c := newRemote(t, secrets, RemoteOptions{Matching: Exact, DefaultKey: "value"})

	if got, _ := get(t, c, "myapp/db"); got != "v" {
		t.Errorf("myapp/db: got %q", got)
	}
	if got, _ := get(t, c, "myapp/db#password"); got != "p" {
		t.Errorf("myapp/db#password: got %q", got)
	}
	if _, err := NewRemote(newRingOnly(t), secrets, RemoteOptions{DefaultKey: "a b"}); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("an invalid default key: %v", err)
	}
}

func TestRemoteCache_AMissingSecret_IsNotRemembered(t *testing.T) {
	secrets := &fakeSecrets{values: map[string]string{}}
	c := newRemote(t, secrets, RemoteOptions{})

	for range 2 {
		if _, ok := get(t, c, "later"); ok {
			t.Fatal("found a missing secret")
		}
	}
	secrets.values["later"] = "now"
	if got, _ := get(t, c, "later"); got != "now" {
		t.Errorf("got %q", got)
	}
	if n := secrets.fetched.Load(); n != 3 {
		t.Errorf("fetched %d times", n)
	}
}

func TestRemoteCache_AFailedFetch_ReturnsItsErrorAndCachesNothing(t *testing.T) {
	boom := errors.New("access denied")
	secrets := &fakeSecrets{values: map[string]string{"s": "v"}, err: boom}
	c := newRemote(t, secrets, RemoteOptions{})

	if _, err := c.Decrypt(bg, "s", make([]byte, 64)); !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
	secrets.err = nil
	if got, _ := get(t, c, "s"); got != "v" {
		t.Errorf("got %q", got)
	}
}

func TestRemoteCache_TheSinkRefusesValuesOnceTheFetchHasReturned(t *testing.T) {
	secrets := &fakeSecrets{values: map[string]string{"s": "v"}}
	c := newRemote(t, secrets, RemoteOptions{})
	get(t, c, "s")

	late := []byte("late")
	if err := secrets.lastSink.SetBytes(late); !errors.Is(err, ErrSinkRefused) {
		t.Errorf("got %v", err)
	}
	if !hkdfguard.IsZero(late) {
		t.Error("a refused value was not zeroed")
	}
}

func TestRemoteCache_SetTwice_IsRefused(t *testing.T) {
	ring := newRingOnly(t)
	var errs []error
	c, _ := NewRemote(ring, storeFunc(func(_ context.Context, _ string, sink *SecretSink) error {
		errs = append(errs, sink.SetBytes([]byte("a")), sink.SetBytes([]byte("b")),
			sink.SetKeyBytes("k", []byte("c")), sink.SetKeyBytes("k", []byte("d")), sink.SetKeyBytes("a b", []byte("e")))
		return nil
	}), RemoteOptions{})
	get(t, c, "s")

	if errs[0] != nil || !errors.Is(errs[1], ErrSinkRefused) || errs[2] != nil || !errors.Is(errs[3], ErrSinkRefused) || !errors.Is(errs[4], ErrInvalidKey) {
		t.Errorf("got %v", errs)
	}
}

func TestRemoteCache_ConcurrentLookups_ShareOneFetch(t *testing.T) {
	secrets := &fakeSecrets{values: map[string]string{"s": `{"a":"1","b":"2"}`}, block: make(chan struct{}), started: make(chan string, 64)}
	c := newRemote(t, secrets, RemoteOptions{})

	var wg sync.WaitGroup
	results := make([]string, 16)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], _ = get(t, c, []string{"s", "s#a", "s#b"}[i%3])
		}()
	}
	<-secrets.started
	time.Sleep(50 * time.Millisecond) // let the others start waiting
	close(secrets.block)
	wg.Wait()

	if n := secrets.fetched.Load(); n != 1 {
		t.Errorf("fetched %d times", n)
	}
	for i, got := range results {
		if want := []string{`{"a":"1","b":"2"}`, "1", "2"}[i%3]; got != want {
			t.Errorf("lookup %d: got %q, want %q", i, got, want)
		}
	}
}

func TestRemoteCache_AWaiterWhoseStarterWasCancelled_FetchesAgain(t *testing.T) {
	secrets := &fakeSecrets{values: map[string]string{"s": "v"}, block: make(chan struct{}), started: make(chan string, 4)}
	c := newRemote(t, secrets, RemoteOptions{})

	starterCtx, cancel := context.WithCancel(bg)
	starterErr := make(chan error, 1)
	go func() {
		_, err := c.Decrypt(starterCtx, "s", make([]byte, 64))
		starterErr <- err
	}()
	<-secrets.started

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
	<-secrets.started // the waiter's own fetch
	close(secrets.block)
	if got := <-waiter; got != "v" {
		t.Errorf("waiter: got %q", got)
	}
}

func TestRemoteCache_AWaiterWhoseOwnContextEnds_StopsWaiting(t *testing.T) {
	secrets := &fakeSecrets{values: map[string]string{"s": "v"}, block: make(chan struct{}), started: make(chan string, 4)}
	c := newRemote(t, secrets, RemoteOptions{})
	go func() { _, _ = c.Decrypt(bg, "s", make([]byte, 64)) }()
	<-secrets.started

	ctx, cancel := context.WithTimeout(bg, 20*time.Millisecond)
	defer cancel()
	if _, err := c.Decrypt(ctx, "s", make([]byte, 64)); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("got %v", err)
	}
	close(secrets.block)
}

func TestRemoteCache_APanickingStore_FailsTheLookup(t *testing.T) {
	c := newRemote(t, storeFunc(func(context.Context, string, *SecretSink) error { panic("bad store") }), RemoteOptions{})
	if _, err := c.Decrypt(bg, "s", make([]byte, 8)); err == nil || !strings.Contains(err.Error(), "panicked") {
		t.Errorf("got %v", err)
	}
}

func TestRemoteCache_EntryNamesRoundTrip(t *testing.T) {
	for _, name := range []string{"prod/Db", "ABC", "abc", "a-B_c.D"} {
		if got := unescapeCase(escapeCase(name)); got != name {
			t.Errorf("%q round-tripped as %q", name, got)
		}
		if strings.ToLower(escapeCase(name)) != escapeCase(name) {
			t.Errorf("%q escaped as %q, holding upper case", name, escapeCase(name))
		}
	}
	if escapeCase("prod/Db") != "prod/!db" {
		t.Errorf("got %q", escapeCase("prod/Db"))
	}
}

type storeFunc func(ctx context.Context, name string, sink *SecretSink) error

func (storeFunc) IsValidName(name string) bool { return name != "" }
func (f storeFunc) Fetch(ctx context.Context, name string, sink *SecretSink) error {
	return f(ctx, name, sink)
}

func newRingOnly(t *testing.T) hkdfguard.KeyRing {
	ring, _ := newRing(t, 1)
	return ring
}
