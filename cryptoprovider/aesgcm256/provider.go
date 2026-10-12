package aesgcm256

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/diagnostics"
	"go.opentelemetry.io/otel/trace"
)

// The refresh interval (expiry) every provider accepts.
const (
	MinExpiry = time.Second
	MaxExpiry = 300 * time.Second
)

// ErrInvalidExpiry reports an expiry outside MinExpiry..MaxExpiry.
var ErrInvalidExpiry = errors.New("aesgcm256: invalid expiry")

// Provider is an AES-256-GCM hkdfguard.CryptoProvider bound to one wrapped DEK. A background
// goroutine, ticking every expiry, reveals the DEK fresh through the key wrapper and swaps in a
// new session, so Encrypt and Decrypt never pay the unwrap cost themselves; only New does, once.
// The replaced session is closed (zeroing its key) as soon as any operation still using it has
// finished.
//
// A refresh re-reveals the same DEK, so it is a periodic check that the KEK is still accessible,
// not a bound on how long the DEK exists in memory. What happens when that check fails is the
// hkdfguard.RefreshFailurePolicy: failing closed (the default) zeroes the key after that many
// consecutive failures and suspends Encrypt/Decrypt - they fail with
// hkdfguard.ErrKeyAccessSuspended - until a later refresh succeeds; failing open keeps the last
// good key in use indefinitely.
//
// Ciphertext is [12-byte random nonce | ciphertext | 16-byte tag], identical to the .NET port.
// A Provider is safe for concurrent use.
type Provider struct {
	wrapper hkdfguard.KeyWrapper
	wrapped []byte
	policy  hkdfguard.RefreshFailurePolicy
	logger  *slog.Logger
	budget  *encryptionBudget

	current atomic.Pointer[session] // nil while suspended or after Close
	swapMu  sync.Mutex              // serializes swapping current with Close
	closed  atomic.Bool

	cancel context.CancelFunc
	done   chan struct{}

	// Only the refresh goroutine touches this.
	consecutiveFailures int

	afterRefresh func() // test hook: called after every refresh attempt
}

var _ hkdfguard.CryptoProvider = (*Provider)(nil)

// Option configures a Provider or Factory.
type Option func(*options)

type options struct {
	logger       *slog.Logger
	budget       *encryptionBudget
	ticks        <-chan time.Time
	afterRefresh func()
}

// WithLogger sets where a provider logs each failed background refresh, key-access suspension and
// resumption, and an approaching encryption limit. Optional, but strongly recommended: without it
// (or a tracer provider) none of these is visible - and under fail-open a revoked KEK goes
// unnoticed.
func WithLogger(logger *slog.Logger) Option {
	return func(o *options) { o.logger = logger }
}

// Test hooks: a budget of the test's own, refresh ticks the test sends, and a callback after each
// refresh attempt so the test can wait for it.
func withBudget(b *encryptionBudget) Option   { return func(o *options) { o.budget = b } }
func withTicks(ticks <-chan time.Time) Option { return func(o *options) { o.ticks = ticks } }
func withAfterRefresh(callback func()) Option { return func(o *options) { o.afterRefresh = callback } }

// New creates a Provider: it reveals the DEK in wrapped through wrapper (honoring ctx) and starts
// the background refresh. The provider owns wrapped from here on and zeroes it when it's closed.
//
// expiry is the refresh interval, MinExpiry to MaxExpiry. Bad arguments are reported before the
// key wrapper is called. A wrapper that reveals anything but a KeySize-byte key is refused rather
// than used.
func New(ctx context.Context, wrapper hkdfguard.KeyWrapper, wrapped []byte, expiry time.Duration, policy hkdfguard.RefreshFailurePolicy, opts ...Option) (*Provider, error) {
	var o options
	for _, opt := range opts {
		opt(&o)
	}

	if err := validate(expiry, policy); err != nil {
		return nil, err
	}
	// Don't rely on the key wrapper to honor a context that's already done.
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	first, err := reveal(ctx, wrapper, wrapped, o.budget, o.logger)
	if err != nil {
		return nil, err
	}

	ticks := o.ticks
	var ticker *time.Ticker
	if ticks == nil {
		ticker = time.NewTicker(expiry)
		ticks = ticker.C
	}

	loopCtx, cancel := context.WithCancel(context.Background())
	p := &Provider{
		wrapper:      wrapper,
		wrapped:      wrapped,
		policy:       policy,
		logger:       o.logger,
		budget:       first.budget,
		cancel:       cancel,
		done:         make(chan struct{}),
		afterRefresh: o.afterRefresh,
	}
	p.current.Store(first)

	go p.refreshLoop(loopCtx, ticks, ticker)
	return p, nil
}

func validate(expiry time.Duration, policy hkdfguard.RefreshFailurePolicy) error {
	if expiry < MinExpiry || expiry > MaxExpiry {
		return fmt.Errorf("%w: expiry must be between %v and %v, got %v", ErrInvalidExpiry, MinExpiry, MaxExpiry, expiry)
	}
	return policy.Validate()
}

// reveal unwraps the DEK and builds a session around it. budget nil means the process-wide one
// for whichever key is revealed.
func reveal(ctx context.Context, wrapper hkdfguard.KeyWrapper, wrapped []byte, budget *encryptionBudget, logger *slog.Logger) (*session, error) {
	key := make([]byte, KeySize)
	written, err := wrapper.Unwrap(ctx, wrapped, key)
	if err != nil {
		hkdfguard.Wipe(key)
		return nil, err
	}
	// A wrapper that reveals fewer bytes (e.g. a misconfigured KMS returning a 128-bit data key)
	// would otherwise leave the rest of the key zero and silently weaken every session.
	if written != KeySize {
		hkdfguard.Wipe(key)
		return nil, fmt.Errorf("%w: key wrapper revealed %d bytes; a %d-byte DEK is required", ErrInvalidLength, written, KeySize)
	}

	if budget == nil {
		budget = budgetFor(key)
	}
	s, err := newSession(key, budget, logger)
	if err != nil {
		hkdfguard.Wipe(key)
		return nil, err
	}
	return s, nil
}

// RefreshFailurePolicy is the policy this provider applies when background refreshes fail.
func (p *Provider) RefreshFailurePolicy() hkdfguard.RefreshFailurePolicy { return p.policy }

// KeyAccessSuspended reports whether this provider has failed closed: its key is zeroed and every
// Encrypt/Decrypt fails until a background refresh succeeds.
func (p *Provider) KeyAccessSuspended() bool {
	return p.current.Load() == nil && !p.closed.Load()
}

// EncryptionCount is the number of encryptions performed under this provider's key so far - see
// MaxEncryptionsPerKey.
func (p *Provider) EncryptionCount() int64 { return p.budget.count.Load() }

// Encrypt encrypts plaintext, bound to aad (nil for none), into result and returns the number of
// bytes written: EncryptedAllocationLength(len(plaintext)). plaintext is zeroed before Encrypt
// returns, whether or not it succeeds. plaintext and result must not overlap.
func (p *Provider) Encrypt(ctx context.Context, plaintext, aad, result []byte) (int, error) {
	for {
		s := p.current.Load()
		if s == nil {
			// Suspended or closed: no session will run its own zeroing, so honor the contract here.
			hkdfguard.Wipe(plaintext)
			return 0, p.unavailable()
		}
		// ok == false means the session was retired after it was read here, before it started -
		// nothing was touched, so go round again for the one that replaced it. current is never
		// set to a closed session, so this ends.
		if n, ok, err := s.tryEncrypt(ctx, plaintext, aad, result); ok {
			return n, err
		}
	}
}

// Decrypt decrypts ciphertext encrypted with the same aad into result and returns the number of
// bytes written. A failed authentication is hkdfguard.ErrAuthenticationFailed.
func (p *Provider) Decrypt(ctx context.Context, ciphertext, aad, result []byte) (int, error) {
	for {
		s := p.current.Load()
		if s == nil {
			return 0, p.unavailable()
		}
		if n, ok, err := s.tryDecrypt(ctx, ciphertext, aad, result); ok {
			return n, err
		}
	}
}

func (p *Provider) unavailable() error {
	if p.closed.Load() {
		return hkdfguard.ErrClosed
	}
	limit, _ := p.policy.MaxFailures()
	return fmt.Errorf("%w: %d consecutive attempts to re-reveal the key through the key wrapper failed; operations resume once a refresh succeeds", hkdfguard.ErrKeyAccessSuspended, limit)
}

// EncryptedAllocationLength is the result size Encrypt needs for a plaintext of plaintextLength.
func (p *Provider) EncryptedAllocationLength(plaintextLength int) int {
	return plaintextLength + Overhead
}

// DecryptedAllocationLength is the result size Decrypt needs for a ciphertext of
// ciphertextLength. Never negative: input shorter than the nonce and tag can't be valid
// ciphertext, and Decrypt rejects it, but a size computed from it must still be usable.
func (p *Provider) DecryptedAllocationLength(ciphertextLength int) int {
	return max(0, ciphertextLength-Overhead)
}

func (p *Provider) refreshLoop(ctx context.Context, ticks <-chan time.Time, ticker *time.Ticker) {
	defer close(p.done)
	if ticker != nil {
		defer ticker.Stop()
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticks:
			p.refreshOnce(ctx)
			if p.afterRefresh != nil {
				p.afterRefresh()
			}
		}
	}
}

func (p *Provider) refreshOnce(ctx context.Context) {
	ctx, span := diagnostics.CryptoProviderAESGCM256.Start(ctx, diagnostics.SpanCryptoProviderAESGCM256BackgroundRefresh)
	defer span.End()

	fresh, err := reveal(ctx, p.wrapper, p.wrapped, p.budget, p.logger)
	if err != nil {
		if ctx.Err() != nil {
			// Shutdown: Close cancelled us; whatever the in-flight refresh failed with is moot.
			return
		}
		p.refreshFailed(ctx, span, err)
		return
	}

	if !p.swap(fresh) {
		fresh.close() // closed while the refresh was in flight
		return
	}

	previousFailures := p.consecutiveFailures
	p.consecutiveFailures = 0
	if limit, failsClosed := p.policy.MaxFailures(); failsClosed && previousFailures >= limit {
		diagnostics.KeyAccessResumed(ctx, p.logger, previousFailures)
	}
}

func (p *Provider) refreshFailed(ctx context.Context, span trace.Span, err error) {
	diagnostics.RecordError(span, err)

	p.consecutiveFailures++
	failures := p.consecutiveFailures
	// Logged on every failure, whatever the policy: under fail-open it is the only sign the KEK
	// is gone.
	diagnostics.KeyRefreshFailed(ctx, p.logger, failures, p.policy.String(), err)

	if limit, failsClosed := p.policy.MaxFailures(); failsClosed && failures == limit {
		// Fail closed: zero the revealed DEK and refuse operations until a refresh succeeds.
		p.swap(nil)
		span.AddEvent(diagnostics.EventKeyAccessSuspended, trace.WithAttributes(diagnostics.AttrConsecutiveFailures.Int(failures)))
		diagnostics.KeyAccessSuspended(ctx, p.logger, failures)
	}
}

// swap makes next the current session and closes the one it replaces, reporting false (and
// changing nothing) if the provider has been closed.
func (p *Provider) swap(next *session) bool {
	p.swapMu.Lock()
	defer p.swapMu.Unlock()
	if p.closed.Load() {
		return false
	}
	if previous := p.current.Swap(next); previous != nil {
		previous.close()
	}
	return true
}

// Close stops the background refresh - waiting for a refresh already in flight, whose context it
// cancels - then zeroes the wrapped payload and the revealed key. Every later operation fails with
// hkdfguard.ErrClosed. Safe to call more than once.
func (p *Provider) Close() error {
	p.swapMu.Lock()
	alreadyClosed := p.closed.Swap(true)
	p.swapMu.Unlock()
	if alreadyClosed {
		return nil
	}

	p.cancel()
	<-p.done

	hkdfguard.Wipe(p.wrapped)
	if s := p.current.Swap(nil); s != nil {
		s.close()
	}
	return nil
}
