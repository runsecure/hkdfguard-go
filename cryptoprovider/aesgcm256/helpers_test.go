package aesgcm256

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/runsecure/hkdfguard-go"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func randomKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}

// fakeKeyWrapper reveals a key on every Unwrap - a fresh random one, or fixedKey every time (as a
// real wrapper does for one payload). Safe to reconfigure while the refresh goroutine calls it.
type fakeKeyWrapper struct {
	mu              sync.Mutex
	fixedKey        []byte
	unwrapErr       error
	writtenOverride *int
	unwrapCalls     int
	generateCalls   int
	block           chan struct{} // when set, Unwrap waits for it to close: a hung key wrapper
}

func (w *fakeKeyWrapper) Wrap(context.Context, []byte, []byte) (int, error) {
	return 0, errors.New("not supported")
}

func (w *fakeKeyWrapper) Unwrap(_ context.Context, _, result []byte) (int, error) {
	w.mu.Lock()
	w.unwrapCalls++
	block := w.block
	w.mu.Unlock()
	if block != nil {
		<-block // deliberately ignores ctx, as a native call does
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.unwrapErr != nil {
		return 0, w.unwrapErr
	}
	written := len(result)
	if w.writtenOverride != nil {
		written = *w.writtenOverride
	}
	target := result[:min(written, len(result))]
	if w.fixedKey == nil {
		_, _ = rand.Read(target)
	} else {
		copy(target, w.fixedKey)
	}
	return written, nil
}

func (w *fakeKeyWrapper) GenerateAndWrap(_ context.Context, result []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.generateCalls++
	_, _ = rand.Read(result[:32])
	return 32, nil
}

func (w *fakeKeyWrapper) ReadKeyFile(context.Context, string) ([]byte, error) {
	return nil, errors.New("unused: these tests read no key files")
}

func (w *fakeKeyWrapper) failWith(err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.unwrapErr = err
}

func (w *fakeKeyWrapper) hangUntil(release chan struct{}) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.block = release
}

func (w *fakeKeyWrapper) revealBytes(n int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writtenOverride = &n
}

func (w *fakeKeyWrapper) calls() (unwrap, generate int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.unwrapCalls, w.generateCalls
}

// refresher drives a provider's background refresh by hand.
type refresher struct {
	ticks     chan time.Time
	refreshed chan struct{}
}

func newRefresher() *refresher {
	return &refresher{ticks: make(chan time.Time), refreshed: make(chan struct{}, 16)}
}

func (r *refresher) options() []Option {
	return []Option{withTicks(r.ticks), withAfterRefresh(func() { r.refreshed <- struct{}{} })}
}

// tick runs one refresh and waits for it to finish.
func (r *refresher) tick(t *testing.T) {
	t.Helper()
	select {
	case r.ticks <- time.Now():
	case <-time.After(5 * time.Second):
		t.Fatal("the refresh loop did not take the tick")
	}
	select {
	case <-r.refreshed:
	case <-time.After(5 * time.Second):
		t.Fatal("the refresh did not finish")
	}
}

// newTestProvider creates a provider whose refreshes the test drives, closed when the test ends.
func newTestProvider(t *testing.T, wrapper hkdfguard.KeyWrapper, policy hkdfguard.RefreshFailurePolicy, opts ...Option) (*Provider, *refresher) {
	t.Helper()
	r := newRefresher()
	p, err := New(context.Background(), wrapper, []byte("wrapped"), time.Minute, policy, append(r.options(), opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p, r
}

func mustEncrypt(t *testing.T, p hkdfguard.CryptoProvider, plaintext, aad []byte) []byte {
	t.Helper()
	ciphertext := make([]byte, p.EncryptedAllocationLength(len(plaintext)))
	n, err := p.Encrypt(context.Background(), bytes.Clone(plaintext), aad, ciphertext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	return ciphertext[:n]
}

func mustDecrypt(t *testing.T, p hkdfguard.CryptoProvider, ciphertext, aad []byte) []byte {
	t.Helper()
	plaintext := make([]byte, p.DecryptedAllocationLength(len(ciphertext)))
	n, err := p.Decrypt(context.Background(), ciphertext, aad, plaintext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	return plaintext[:n]
}

func requireRoundTrip(t *testing.T, p hkdfguard.CryptoProvider) {
	t.Helper()
	plaintext := []byte("top secret")
	if got := mustDecrypt(t, p, mustEncrypt(t, p, plaintext, nil), nil); !bytes.Equal(got, plaintext) {
		t.Errorf("round trip gave %q", got)
	}
}

// capturingHandler records slog records.
type capturingHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *capturingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *capturingHandler) WithAttrs([]slog.Attr) slog.Handler       { return h }
func (h *capturingHandler) WithGroup(string) slog.Handler            { return h }
func (h *capturingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r)
	return nil
}

// withEventID returns the records carrying event.id == id.
func (h *capturingHandler) withEventID(id int64) []slog.Record {
	h.mu.Lock()
	defer h.mu.Unlock()
	var matched []slog.Record
	for _, r := range h.records {
		r.Attrs(func(a slog.Attr) bool {
			if a.Key == "event.id" && a.Value.Int64() == id {
				matched = append(matched, r)
				return false
			}
			return true
		})
	}
	return matched
}

func (h *capturingHandler) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.records)
}

func newCapturingLogger() (*slog.Logger, *capturingHandler) {
	h := &capturingHandler{}
	return slog.New(h), h
}

// useSpanRecorder installs a global tracer provider recording every span for this test.
func useSpanRecorder(t *testing.T) *tracetest.SpanRecorder {
	t.Helper()
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	otel.SetTracerProvider(provider)
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	return recorder
}

// testFormatProvider formats values as "enc::v<version>::<base64>", like the .NET
// DefaultFormatProvider.
type testFormatProvider struct{}

func (testFormatProvider) Format(_ context.Context, value hkdfguard.KeyTrackingValue) (string, error) {
	return fmt.Sprintf("enc::v%d::%s", value.KeyVersion, base64.StdEncoding.EncodeToString(value.Value)), nil
}

func (testFormatProvider) Parse(_ context.Context, encrypted string) (hkdfguard.KeyTrackingValue, error) {
	parts := strings.Split(encrypted, "::")
	if len(parts) != 3 || parts[0] != "enc" || !strings.HasPrefix(parts[1], "v") {
		return hkdfguard.KeyTrackingValue{}, errors.New("malformed value")
	}
	version, err := strconv.Atoi(parts[1][1:])
	if err != nil {
		return hkdfguard.KeyTrackingValue{}, err
	}
	value, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return hkdfguard.KeyTrackingValue{}, err
	}
	return hkdfguard.KeyTrackingValue{KeyVersion: version, Value: value}, nil
}

func (testFormatProvider) MaxDecryptedLength(_ context.Context, encrypted string) (int, error) {
	parts := strings.Split(encrypted, "::")
	if len(parts) != 3 {
		return 0, errors.New("malformed value")
	}
	return base64.StdEncoding.DecodedLen(len(parts[2])), nil
}
