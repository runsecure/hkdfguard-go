package aesgcm256

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/diagnostics"
	"go.opentelemetry.io/otel/codes"
)

var errKEK = errors.New("KEK unavailable")

func TestNew_RevealsTheKeyEagerly_Once(t *testing.T) {
	wrapper := &fakeKeyWrapper{}
	newTestProvider(t, wrapper, hkdfguard.RefreshFailurePolicy{})

	if unwrap, _ := wrapper.calls(); unwrap != 1 {
		t.Errorf("unwrap called %d times", unwrap)
	}
}

func TestNew_WhenTheKeyWrapperFails_ReturnsItsError(t *testing.T) {
	_, err := New(context.Background(), &fakeKeyWrapper{unwrapErr: errKEK}, []byte("wrapped"), time.Minute, hkdfguard.RefreshFailurePolicy{})

	if !errors.Is(err, errKEK) {
		t.Errorf("error = %v", err)
	}
}

func TestNew_BadArgumentsOrACancelledContext_NeverReachTheKeyWrapper(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	cases := []struct {
		name   string
		ctx    context.Context
		expiry time.Duration
		policy hkdfguard.RefreshFailurePolicy
		want   error
	}{
		{"zero expiry", context.Background(), 0, hkdfguard.RefreshFailurePolicy{}, ErrInvalidExpiry},
		{"negative expiry", context.Background(), -time.Second, hkdfguard.RefreshFailurePolicy{}, ErrInvalidExpiry},
		{"expiry over 300s", context.Background(), 301 * time.Second, hkdfguard.RefreshFailurePolicy{}, ErrInvalidExpiry},
		{"fail closed after 0", context.Background(), time.Minute, hkdfguard.FailClosedAfter(0), hkdfguard.ErrInvalidRefreshFailurePolicy},
		{"cancelled", cancelled, time.Minute, hkdfguard.RefreshFailurePolicy{}, context.Canceled},
	}
	for _, c := range cases {
		wrapper := &fakeKeyWrapper{}
		if _, err := New(c.ctx, wrapper, []byte("wrapped"), c.expiry, c.policy); !errors.Is(err, c.want) {
			t.Errorf("%s: error = %v, want %v", c.name, err, c.want)
		}
		if unwrap, _ := wrapper.calls(); unwrap != 0 {
			t.Errorf("%s: unwrap called %d times", c.name, unwrap)
		}
	}
}

func TestNew_AWrongLengthKey_IsRefusedRatherThanUsed(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33} {
		wrapper := &fakeKeyWrapper{}
		wrapper.revealBytes(n)

		_, err := New(context.Background(), wrapper, []byte("wrapped"), time.Minute, hkdfguard.RefreshFailurePolicy{})
		if !errors.Is(err, ErrInvalidLength) || !strings.Contains(err.Error(), "revealed") {
			t.Errorf("%d bytes: error = %v", n, err)
		}
	}
}

func TestProvider_AllocationLengths(t *testing.T) {
	p, _ := newTestProvider(t, &fakeKeyWrapper{}, hkdfguard.RefreshFailurePolicy{})

	if got := p.EncryptedAllocationLength(10); got != 10+12+16 {
		t.Errorf("EncryptedAllocationLength(10) = %d", got)
	}
	if got := p.DecryptedAllocationLength(10 + 12 + 16); got != 10 {
		t.Errorf("DecryptedAllocationLength(38) = %d", got)
	}
	for _, n := range []int{0, 27, 28} {
		if got := p.DecryptedAllocationLength(n); got != 0 {
			t.Errorf("DecryptedAllocationLength(%d) = %d", n, got)
		}
	}
}

func TestRefresh_RevealsTheKeyAgain_AndDecryptsAcrossTheSwap(t *testing.T) {
	wrapper := &fakeKeyWrapper{fixedKey: randomKey(t)}
	p, r := newTestProvider(t, wrapper, hkdfguard.RefreshFailurePolicy{})
	ciphertext := mustEncrypt(t, p, []byte("before"), nil)

	r.tick(t)

	if unwrap, _ := wrapper.calls(); unwrap != 2 {
		t.Errorf("unwrap called %d times", unwrap)
	}
	if got := mustDecrypt(t, p, ciphertext, nil); string(got) != "before" {
		t.Errorf("decrypted %q", got)
	}
}

func TestTheRealTicker_RefreshesOnItsOwn(t *testing.T) {
	wrapper := &fakeKeyWrapper{}
	refreshed := make(chan struct{}, 4)
	p, err := New(context.Background(), wrapper, []byte("wrapped"), MinExpiry, hkdfguard.RefreshFailurePolicy{},
		withAfterRefresh(func() { refreshed <- struct{}{} }))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	select {
	case <-refreshed:
	case <-time.After(5 * time.Second):
		t.Fatal("no refresh within 5s of a 1s expiry")
	}
}

func TestRefreshFailures_AreRecordedOnTheSpan_AndKeepTheCurrentKey(t *testing.T) {
	recorder := useSpanRecorder(t)
	wrapper := &fakeKeyWrapper{fixedKey: randomKey(t)}
	p, r := newTestProvider(t, wrapper, hkdfguard.RefreshFailurePolicy{})
	ciphertext := mustEncrypt(t, p, []byte("still works"), nil)

	wrapper.failWith(errKEK)
	r.tick(t)
	wrapper.failWith(nil)
	wrapper.revealBytes(16)
	r.tick(t)

	var failed []string
	for _, span := range recorder.Ended() {
		if span.Name() == diagnostics.SpanCryptoProviderAESGCM256BackgroundRefresh && span.Status().Code == codes.Error {
			failed = append(failed, span.Status().Description)
		}
	}
	if len(failed) != 2 || !strings.Contains(failed[1], "revealed 16 bytes") {
		t.Errorf("failed refresh spans: %q", failed)
	}
	if got := mustDecrypt(t, p, ciphertext, nil); string(got) != "still works" {
		t.Errorf("decrypted %q", got)
	}
}

func TestClose_StopsTheRefresh_ZeroesTheWrappedKey_AndFailsLaterOperations(t *testing.T) {
	wrapper := &fakeKeyWrapper{}
	wrapped := []byte("wrapped payload")
	p, err := New(context.Background(), wrapper, wrapped, time.Minute, hkdfguard.RefreshFailurePolicy{})
	if err != nil {
		t.Fatal(err)
	}

	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if err := p.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}

	select {
	case <-p.done:
	default:
		t.Error("the refresh goroutine is still running")
	}
	if !hkdfguard.IsZero(wrapped) {
		t.Error("the wrapped payload was not zeroed")
	}
	if _, err := p.Encrypt(context.Background(), []byte{1}, nil, make([]byte, 64)); !errors.Is(err, hkdfguard.ErrClosed) {
		t.Errorf("Encrypt after Close: %v", err)
	}
	if _, err := p.Decrypt(context.Background(), make([]byte, 64), nil, make([]byte, 64)); !errors.Is(err, hkdfguard.ErrClosed) {
		t.Errorf("Decrypt after Close: %v", err)
	}
	if p.KeyAccessSuspended() {
		t.Error("a closed provider reports itself suspended")
	}
}

// blockingKeyWrapper reveals a key once; every later unwrap waits until its context is done, then
// fails with something other than the context's error - a network client torn down mid-call.
type blockingKeyWrapper struct {
	fakeKeyWrapper
	once           sync.Once
	refreshStarted chan struct{}
}

func (w *blockingKeyWrapper) Unwrap(ctx context.Context, wrapped, result []byte) (int, error) {
	first := false
	w.once.Do(func() { first = true })
	if first {
		return w.fakeKeyWrapper.Unwrap(ctx, wrapped, result)
	}
	close(w.refreshStarted)
	<-ctx.Done()
	return 0, errors.New("KMS connection closed during shutdown")
}

func TestClose_DuringAnInFlightRefresh_CancelsIt_AndReturnsCleanly(t *testing.T) {
	wrapper := &blockingKeyWrapper{refreshStarted: make(chan struct{})}
	logger, logs := newCapturingLogger()
	r := newRefresher()
	p, err := New(context.Background(), wrapper, []byte("wrapped"), time.Minute, hkdfguard.RefreshFailurePolicy{},
		append(r.options(), WithLogger(logger))...)
	if err != nil {
		t.Fatal(err)
	}

	r.ticks <- time.Now()
	<-wrapper.refreshStarted

	if err := p.Close(); err != nil {
		t.Errorf("Close = %v", err)
	}
	if logs.count() != 0 {
		t.Errorf("shutdown logged %d records; a cancelled refresh is not a failure", logs.count())
	}
}

func TestRefresh_UnderConcurrentLoad_NeverFailsAnOperationMidSwap(t *testing.T) {
	p, r := newTestProvider(t, &fakeKeyWrapper{fixedKey: randomKey(t)}, hkdfguard.RefreshFailurePolicy{})
	stop := make(chan struct{})
	var wg sync.WaitGroup

	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			plaintext := []byte("pounding on it")
			ciphertext := make([]byte, len(plaintext)+Overhead)
			decrypted := make([]byte, len(plaintext))
			for {
				select {
				case <-stop:
					return
				default:
				}
				n, err := p.Encrypt(context.Background(), bytes.Clone(plaintext), nil, ciphertext)
				if err == nil {
					_, err = p.Decrypt(context.Background(), ciphertext[:n], nil, decrypted)
				}
				if err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	for range 20 {
		r.tick(t)
	}
	close(stop)
	wg.Wait()
}

func TestEncrypt_PastTheKeysLimit_FailsWhileDecryptStillWorks(t *testing.T) {
	budget, _ := newEncryptionBudget(1, 2)
	p, _ := newTestProvider(t, &fakeKeyWrapper{fixedKey: randomKey(t)}, hkdfguard.RefreshFailurePolicy{}, withBudget(budget))
	ciphertext := mustEncrypt(t, p, []byte("value"), nil)
	mustEncrypt(t, p, []byte("value"), nil)

	_, err := p.Encrypt(context.Background(), []byte("value"), nil, make([]byte, 64))
	if !errors.Is(err, hkdfguard.ErrEncryptionLimitReached) || !strings.Contains(err.Error(), "must be rotated") {
		t.Errorf("third Encrypt: %v", err)
	}
	if p.EncryptionCount() != 2 {
		t.Errorf("EncryptionCount = %d", p.EncryptionCount())
	}
	if got := mustDecrypt(t, p, ciphertext, nil); string(got) != "value" {
		t.Errorf("decrypted %q", got)
	}
}

func TestEncryptionCount_SurvivesARefresh_BecauseTheKeyIsTheSame(t *testing.T) {
	budget, _ := newEncryptionBudget(1, 4)
	p, r := newTestProvider(t, &fakeKeyWrapper{fixedKey: randomKey(t)}, hkdfguard.RefreshFailurePolicy{}, withBudget(budget))
	mustEncrypt(t, p, []byte("one"), nil)
	mustEncrypt(t, p, []byte("two"), nil)

	r.tick(t)
	mustEncrypt(t, p, []byte("three"), nil)
	mustEncrypt(t, p, []byte("four"), nil)

	if p.EncryptionCount() != 4 {
		t.Errorf("EncryptionCount = %d", p.EncryptionCount())
	}
	if _, err := p.Encrypt(context.Background(), []byte("five"), nil, make([]byte, 64)); !errors.Is(err, hkdfguard.ErrEncryptionLimitReached) {
		t.Errorf("fifth Encrypt: %v", err)
	}
}

func TestCrossingTheWarningThreshold_RaisesOneSpanEventAndOneLogWarning(t *testing.T) {
	recorder := useSpanRecorder(t)
	logger, logs := newCapturingLogger()
	budget, _ := newEncryptionBudget(2, 10)
	p, _ := newTestProvider(t, &fakeKeyWrapper{fixedKey: randomKey(t)}, hkdfguard.RefreshFailurePolicy{}, withBudget(budget), WithLogger(logger))

	for range 4 {
		mustEncrypt(t, p, []byte("value"), nil)
	}

	events := 0
	for _, span := range recorder.Ended() {
		for _, e := range span.Events() {
			if e.Name == diagnostics.EventEncryptionBudgetWarning {
				events++
			}
		}
	}
	warnings := logs.withEventID(10)
	if events != 1 || len(warnings) != 1 || !strings.Contains(warnings[0].Message, "2 encryptions of its 10") {
		t.Errorf("%d span events, %d log warnings", events, len(warnings))
	}
}

func TestTwoProvidersRevealingTheSameKey_ShareOneCount_ThatOutlivesThem(t *testing.T) {
	key := randomKey(t)
	first, _ := newTestProvider(t, &fakeKeyWrapper{fixedKey: key}, hkdfguard.RefreshFailurePolicy{})
	second, _ := newTestProvider(t, &fakeKeyWrapper{fixedKey: key}, hkdfguard.RefreshFailurePolicy{})
	other, _ := newTestProvider(t, &fakeKeyWrapper{fixedKey: randomKey(t)}, hkdfguard.RefreshFailurePolicy{})

	mustEncrypt(t, first, []byte("one"), nil)
	mustEncrypt(t, second, []byte("two"), nil)
	mustEncrypt(t, second, []byte("three"), nil)

	if first.EncryptionCount() != 3 || second.EncryptionCount() != 3 || other.EncryptionCount() != 0 {
		t.Errorf("counts = %d, %d, %d", first.EncryptionCount(), second.EncryptionCount(), other.EncryptionCount())
	}

	_ = first.Close()
	_ = second.Close()
	rebuilt, _ := newTestProvider(t, &fakeKeyWrapper{fixedKey: key}, hkdfguard.RefreshFailurePolicy{})
	if rebuilt.EncryptionCount() != 3 {
		t.Errorf("a provider rebuilt from the same key starts at %d", rebuilt.EncryptionCount())
	}
}

func TestFailClosed_SuspendsAfterTheConfiguredFailures_UntilARefreshSucceeds(t *testing.T) {
	recorder := useSpanRecorder(t)
	logger, logs := newCapturingLogger()
	wrapper := &fakeKeyWrapper{fixedKey: randomKey(t)}
	p, r := newTestProvider(t, wrapper, hkdfguard.FailClosedAfter(2), WithLogger(logger))
	ciphertext := mustEncrypt(t, p, []byte("survives"), nil)

	wrapper.failWith(errKEK)
	r.tick(t)
	if p.KeyAccessSuspended() {
		t.Fatal("suspended after one failure of two")
	}
	r.tick(t)

	if !p.KeyAccessSuspended() {
		t.Fatal("not suspended after two failures")
	}
	plaintext := []byte("x")
	if _, err := p.Encrypt(context.Background(), plaintext, nil, make([]byte, 64)); !errors.Is(err, hkdfguard.ErrKeyAccessSuspended) {
		t.Errorf("Encrypt while suspended: %v", err)
	}
	if !hkdfguard.IsZero(plaintext) {
		t.Error("Encrypt while suspended left the plaintext")
	}
	if _, err := p.Decrypt(context.Background(), ciphertext, nil, make([]byte, 64)); !errors.Is(err, hkdfguard.ErrKeyAccessSuspended) {
		t.Errorf("Decrypt while suspended: %v", err)
	}

	failures := logs.withEventID(3)
	if len(failures) != 2 || !strings.Contains(failures[1].Message, "fail closed after 2 consecutive failures") {
		t.Errorf("refresh failures logged: %d", len(failures))
	}
	if len(logs.withEventID(4)) != 1 || len(logs.withEventID(5)) != 0 {
		t.Errorf("suspension logged %d times, resumption %d", len(logs.withEventID(4)), len(logs.withEventID(5)))
	}
	suspendedEvents := 0
	for _, span := range recorder.Ended() {
		for _, e := range span.Events() {
			if e.Name == diagnostics.EventKeyAccessSuspended {
				suspendedEvents++
			}
		}
	}
	if suspendedEvents != 1 {
		t.Errorf("%d key-access-suspended span events", suspendedEvents)
	}

	// The KEK comes back: the next successful refresh resumes service with the same DEK.
	wrapper.failWith(nil)
	r.tick(t)

	if p.KeyAccessSuspended() {
		t.Error("still suspended after a successful refresh")
	}
	if got := mustDecrypt(t, p, ciphertext, nil); string(got) != "survives" {
		t.Errorf("decrypted %q", got)
	}
	if len(logs.withEventID(5)) != 1 {
		t.Errorf("resumption logged %d times", len(logs.withEventID(5)))
	}
}

func TestFailClosed_CountsOnlyConsecutiveFailures(t *testing.T) {
	wrapper := &fakeKeyWrapper{fixedKey: randomKey(t)}
	p, r := newTestProvider(t, wrapper, hkdfguard.FailClosedAfter(2))

	wrapper.failWith(errKEK)
	r.tick(t)
	wrapper.failWith(nil)
	r.tick(t)
	wrapper.failWith(errKEK)
	r.tick(t)

	if p.KeyAccessSuspended() {
		t.Error("suspended after failures that were not consecutive")
	}
	requireRoundTrip(t, p)
}

func TestFailOpen_LogsEveryFailure_ButNeverSuspends(t *testing.T) {
	logger, logs := newCapturingLogger()
	wrapper := &fakeKeyWrapper{fixedKey: randomKey(t)}
	p, r := newTestProvider(t, wrapper, hkdfguard.FailOpen(), WithLogger(logger))

	wrapper.failWith(errKEK)
	for range 4 {
		r.tick(t)
	}
	wrapper.failWith(nil)
	r.tick(t)

	failures := logs.withEventID(3)
	if len(failures) != 4 || !strings.Contains(failures[1].Message, "(2 consecutive)") || !strings.Contains(failures[0].Message, "fail open") {
		t.Errorf("%d refresh failures logged", len(failures))
	}
	if len(logs.withEventID(4))+len(logs.withEventID(5)) != 0 || p.KeyAccessSuspended() {
		t.Error("fail-open suspended or resumed")
	}
	requireRoundTrip(t, p)
}

func TestSuccessfulRefreshes_LogNothing(t *testing.T) {
	logger, logs := newCapturingLogger()
	_, r := newTestProvider(t, &fakeKeyWrapper{}, hkdfguard.FailClosedAfter(1), WithLogger(logger))

	r.tick(t)
	r.tick(t)

	if logs.count() != 0 {
		t.Errorf("%d records logged", logs.count())
	}
}

func TestClose_WhileSuspended_ReportsClosedNotSuspended(t *testing.T) {
	wrapper := &fakeKeyWrapper{}
	p, r := newTestProvider(t, wrapper, hkdfguard.FailClosedAfter(1))
	wrapper.failWith(errKEK)
	r.tick(t)
	if !p.KeyAccessSuspended() {
		t.Fatal("not suspended")
	}

	if err := p.Close(); err != nil {
		t.Fatal(err)
	}

	if p.KeyAccessSuspended() {
		t.Error("a closed provider reports itself suspended")
	}
	if _, err := p.Encrypt(context.Background(), []byte{1}, nil, make([]byte, 64)); !errors.Is(err, hkdfguard.ErrClosed) {
		t.Errorf("Encrypt: %v", err)
	}
}

func TestEncrypt_ZeroesThePlaintext_OnEveryPath(t *testing.T) {
	p, _ := newTestProvider(t, &fakeKeyWrapper{}, hkdfguard.RefreshFailurePolicy{})

	ok := []byte("top secret")
	p.Encrypt(context.Background(), ok, nil, make([]byte, 64))
	tooSmall := []byte("top secret")
	if _, err := p.Encrypt(context.Background(), tooSmall, nil, make([]byte, 1)); !errors.Is(err, ErrInvalidLength) {
		t.Errorf("small result: %v", err)
	}
	_ = p.Close()
	closed := []byte("top secret")
	p.Encrypt(context.Background(), closed, []byte("aad"), make([]byte, 64))

	for name, b := range map[string][]byte{"success": ok, "failure": tooSmall, "closed": closed} {
		if !hkdfguard.IsZero(b) {
			t.Errorf("%s: plaintext left as %q", name, b)
		}
	}
}

func TestPolicy_DefaultsToFailClosedAfterThree(t *testing.T) {
	p, _ := newTestProvider(t, &fakeKeyWrapper{}, hkdfguard.RefreshFailurePolicy{})

	if limit, failsClosed := p.RefreshFailurePolicy().MaxFailures(); !failsClosed || limit != 3 {
		t.Errorf("policy = %d, %v", limit, failsClosed)
	}
}

// panickingHandler is a log handler that panics on every record.
type panickingHandler struct{}

func (panickingHandler) Enabled(context.Context, slog.Level) bool  { return true }
func (panickingHandler) Handle(context.Context, slog.Record) error { panic("logging sink is down") }
func (h panickingHandler) WithAttrs([]slog.Attr) slog.Handler      { return h }
func (h panickingHandler) WithGroup(string) slog.Handler           { return h }

func TestFailClosed_WhenTheLogHandlerPanics_StillSuspendsAtTheLimit(t *testing.T) {
	wrapper := &fakeKeyWrapper{fixedKey: randomKey(t)}
	p, r := newTestProvider(t, wrapper, hkdfguard.FailClosedAfter(2), WithLogger(slog.New(panickingHandler{})))

	wrapper.failWith(errKEK)
	r.tick(t)
	r.tick(t)

	if !p.KeyAccessSuspended() {
		t.Fatal("not suspended after two failures with a panicking log handler")
	}

	// A panicking "resumed" log can't turn a successful refresh into a failure either.
	wrapper.failWith(nil)
	r.tick(t)
	if p.KeyAccessSuspended() {
		t.Error("still suspended after a successful refresh")
	}
}

func TestFailClosed_WhenTheKeyWrapperHangs_CountsEachTimedOutRefresh_WithoutPilingUpCalls(t *testing.T) {
	logger, logs := newCapturingLogger()
	wrapper := &fakeKeyWrapper{fixedKey: randomKey(t)}
	p, r := newTestProvider(t, wrapper, hkdfguard.FailClosedAfter(2), WithLogger(logger), withRefreshTimeout(50*time.Millisecond))
	ciphertext := mustEncrypt(t, p, []byte("survives"), nil)
	release := make(chan struct{})
	wrapper.hangUntil(release)
	callsBefore, _ := wrapper.calls()

	r.tick(t) // the reveal hangs and times out: failure 1
	if p.KeyAccessSuspended() {
		t.Fatal("suspended after one failure of two")
	}
	r.tick(t) // the abandoned reveal is still running: failure 2, and no second call

	if !p.KeyAccessSuspended() {
		t.Fatal("not suspended after two timed-out refreshes")
	}
	if calls, _ := wrapper.calls(); calls != callsBefore+1 {
		t.Errorf("%d unwrap calls while the key wrapper hung; want 1", calls-callsBefore)
	}
	failures := logs.withEventID(3)
	if len(failures) != 2 {
		t.Fatalf("refresh failures logged: %d", len(failures))
	}

	// The key wrapper recovers: the abandoned call returns, its key discarded, and the next
	// refresh resumes service with the same DEK.
	wrapper.hangUntil(nil)
	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for p.KeyAccessSuspended() && time.Now().Before(deadline) {
		r.tick(t)
	}
	if p.KeyAccessSuspended() {
		t.Fatal("still suspended after the key wrapper recovered")
	}
	if got := mustDecrypt(t, p, ciphertext, nil); string(got) != "survives" {
		t.Errorf("decrypted %q", got)
	}
}

func TestClose_WhileTheKeyWrapperHangs_ReturnsWithoutWaitingForIt(t *testing.T) {
	wrapper := &fakeKeyWrapper{}
	r := newRefresher()
	p, err := New(context.Background(), wrapper, []byte("wrapped"), time.Minute, hkdfguard.FailClosedAfter(3), r.options()...)
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	defer close(release)
	wrapper.hangUntil(release)
	r.ticks <- time.Now() // a refresh is now stuck in the key wrapper, for up to a minute

	closed := make(chan struct{})
	go func() { _ = p.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("Close waited for a hung key wrapper")
	}
	if _, err := p.Encrypt(context.Background(), []byte("x"), nil, make([]byte, 64)); !errors.Is(err, hkdfguard.ErrClosed) {
		t.Errorf("Encrypt after Close: %v", err)
	}
}
