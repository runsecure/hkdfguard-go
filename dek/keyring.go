package dek

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/diagnostics"
)

var (
	// ErrDuplicateVersion reports an Add for a version that is already registered.
	ErrDuplicateVersion = errors.New("dek: a key is already registered for this version")

	// ErrVersionOutOfRange reports a version outside the 32-bit range every port shares.
	ErrVersionOutOfRange = errors.New("dek: key version out of range")

	// ErrInvalidProtectorName reports a protector name that is empty, not valid UTF-8, or reserved
	// for protected caches.
	ErrInvalidProtectorName = errors.New("dek: invalid protector name")
)

// KeyRing tracks data encryption keys by version for highly concurrent workloads. Get is served
// from a lock-free map, so the hot read path never blocks (and records telemetry only on a miss);
// Add is serialized, since keys are registered only at startup and rotation.
//
// The highest registered version is the current one, automatically - there is no separate call to
// designate it, so it can never fall out of sync with what is registered. Versions are 32-bit, the
// range every port shares.
//
// The ring owns every key added to it: Close closes each one that is an io.Closer (a Key closes its
// provider, stopping its refresh and zeroing its DEK).
//
// A ring built with ephemeral keys also rotates its encryption key on a schedule (see
// Config.EphemeralKeyRotation): every interval it creates a fresh ephemeral key and adds it at
// CurrentVersion + 1, so every later Encrypt uses it. A superseded ephemeral key stays registered
// for the retention, so values encrypted under it still decrypt for that long; then a later
// rotation closes and removes it. Keys read from key files are never retired.
type KeyRing struct {
	formatProvider hkdfguard.EncryptedFormatProvider

	keys    sync.Map            // int -> hkdfguard.DataEncryptionKey
	current atomic.Pointer[int] // nil until a key is added
	addMu   sync.Mutex          // serializes Add, retirement and Close
	closed  bool                // guarded by addMu

	rotation *rotation // nil when this ring doesn't rotate
}

var _ hkdfguard.KeyRing = (*KeyRing)(nil)

// NewKeyRing returns an empty ring whose protectors format values with formatProvider (a
// DefaultFormatProvider when nil).
func NewKeyRing(formatProvider hkdfguard.EncryptedFormatProvider) *KeyRing {
	if formatProvider == nil {
		formatProvider = NewDefaultFormatProvider()
	}
	return &KeyRing{formatProvider: formatProvider}
}

// CurrentVersion is the version new values are encrypted under - the highest registered - or
// hkdfguard.ErrNoCurrentKey before any key is added.
func (r *KeyRing) CurrentVersion() (int, error) {
	if current := r.current.Load(); current != nil {
		return *current, nil
	}
	return 0, hkdfguard.ErrNoCurrentKey
}

// Add registers key for version. A version higher than every one registered so far becomes the
// current version. On success the ring owns key; on failure ownership stays with the caller.
func (r *KeyRing) Add(ctx context.Context, version int, key hkdfguard.DataEncryptionKey) error {
	telemetry := diagnostics.DataProtection
	_, span := telemetry.Start(ctx, diagnostics.SpanDataProtectionKeyRingAdd)
	defer span.End()

	r.addMu.Lock()
	defer r.addMu.Unlock()

	err := r.addLocked(version, key)
	if err != nil {
		diagnostics.RecordError(span, err)
		return err
	}
	current, _ := r.CurrentVersion()
	telemetry.LogSensitiveOperation(span, diagnostics.SpanDataProtectionKeyRingAdd,
		diagnostics.AttrKeyVersion.Int(version), diagnostics.AttrKeyRingBecameCurrent.Bool(current == version))
	return nil
}

func (r *KeyRing) addLocked(version int, key hkdfguard.DataEncryptionKey) error {
	switch {
	case r.closed:
		return hkdfguard.ErrClosed
	case key == nil:
		return errors.New("dek: a key is required")
	case version < math.MinInt32 || version > math.MaxInt32:
		return fmt.Errorf("%w: %d is not a 32-bit version", ErrVersionOutOfRange, version)
	}
	if _, loaded := r.keys.LoadOrStore(version, key); loaded {
		return fmt.Errorf("%w: version %d", ErrDuplicateVersion, version)
	}
	if current := r.current.Load(); current == nil || version > *current {
		r.current.Store(&version)
	}
	return nil
}

// Get returns the key registered for version, or an error wrapping hkdfguard.ErrKeyNotFound: it
// was never added, or was a superseded ephemeral key whose retention ran out.
func (r *KeyRing) Get(ctx context.Context, version int) (hkdfguard.DataEncryptionKey, error) {
	if key, ok := r.keys.Load(version); ok {
		return key.(hkdfguard.DataEncryptionKey), nil
	}

	_, span := diagnostics.DataProtection.Start(ctx, diagnostics.SpanDataProtectionKeyRingGet)
	defer span.End()
	err := fmt.Errorf("%w: version %d", hkdfguard.ErrKeyNotFound, version)
	diagnostics.RecordError(span, err)
	return nil, err
}

// TryGet returns the key registered for version, and false on a miss - for the hot path, where a
// routine miss should cost neither an error nor telemetry.
func (r *KeyRing) TryGet(_ context.Context, version int) (hkdfguard.DataEncryptionKey, bool) {
	key, ok := r.keys.Load(version)
	if !ok {
		return nil, false
	}
	return key.(hkdfguard.DataEncryptionKey), true
}

// Current returns the current version together with its key.
func (r *KeyRing) Current(ctx context.Context) (int, hkdfguard.DataEncryptionKey, error) {
	version, err := r.CurrentVersion()
	if err == nil {
		var key hkdfguard.DataEncryptionKey
		if key, err = r.Get(ctx, version); err == nil {
			return version, key, nil
		}
	}

	_, span := diagnostics.DataProtection.Start(ctx, diagnostics.SpanDataProtectionKeyRingGetCurrent)
	defer span.End()
	diagnostics.RecordError(span, err)
	return 0, nil, err
}

// CreateProtector returns a hkdfguard.DataProtector bound to this ring, using name (as UTF-8) as
// the Additional Authenticated Data of every value it protects. Encrypt resolves the current
// version on every call, so it follows rotation; Decrypt uses whichever version the value names.
//
// hkdfguard.ConfigurationPurpose(key) names the protector encrypted configuration reads a key
// with, which is how pipeline-protected values decrypt; that sharing is intended. The name must be
// non-empty valid UTF-8 and must not start with hkdfguard.CacheAADPrefix, whose AADs belong to
// protected caches.
func (r *KeyRing) CreateProtector(name string) (hkdfguard.DataProtector, error) {
	switch {
	case name == "":
		return nil, fmt.Errorf("%w: a protector name is required - an empty purpose binds nothing", ErrInvalidProtectorName)
	case !utf8.ValidString(name):
		return nil, fmt.Errorf("%w: the name is not valid UTF-8", ErrInvalidProtectorName)
	case strings.HasPrefix(name, hkdfguard.CacheAADPrefix):
		return nil, fmt.Errorf("%w: names starting with '%s' are reserved for protected caches", ErrInvalidProtectorName, hkdfguard.CacheAADPrefix)
	}
	return &protector{name: name, aad: []byte(name), ring: r}, nil
}

// EphemeralKeyRotationInterval is how often this ring adds a fresh ephemeral key, and false when
// it doesn't rotate.
func (r *KeyRing) EphemeralKeyRotationInterval() (time.Duration, bool) {
	if r.rotation == nil {
		return 0, false
	}
	return r.rotation.interval, true
}

// Close stops any rotation - waiting for one in flight - then closes every registered key that is
// an io.Closer. Keys stay registered, so a later operation fails with the key's own
// hkdfguard.ErrClosed; a later Add fails too. Safe to call more than once.
func (r *KeyRing) Close() error {
	r.addMu.Lock()
	alreadyClosed := r.closed
	r.closed = true
	r.addMu.Unlock()
	if alreadyClosed {
		return nil
	}

	if r.rotation != nil {
		r.rotation.stop()
	}

	var errs []error
	r.keys.Range(func(_, key any) bool {
		if closer, ok := key.(io.Closer); ok {
			if err := closer.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		return true
	})
	return errors.Join(errs...)
}

// remove deletes version from the ring and closes its key - retirement. It reports whether a key
// was removed.
func (r *KeyRing) remove(version int) (bool, error) {
	r.addMu.Lock()
	defer r.addMu.Unlock()
	if r.closed {
		return false, nil
	}

	key, ok := r.keys.LoadAndDelete(version)
	if !ok {
		return false, nil
	}
	if closer, ok := key.(io.Closer); ok {
		return true, closer.Close()
	}
	return true, nil
}

// --- Rotation -----------------------------------------------------------------------------------

// rotation is a ring's scheduled ephemeral key rotation. Only the single rotation goroutine (or a
// test driving one rotation at a time) touches its bookkeeping, so that needs no lock of its own.
type rotation struct {
	ring      *KeyRing
	interval  time.Duration
	retention time.Duration // 0: never retire
	createKey func(context.Context) (hkdfguard.DataEncryptionKey, error)
	logger    *slog.Logger

	ephemeral    map[int]bool
	supersededAt map[int]time.Time // monotonic, so a wall-clock jump can't retire early or never

	cancel context.CancelFunc
	done   chan struct{}
}

// startRotation begins adding a fresh ephemeral key every interval. ticks, when non-nil, replaces
// the ticker (tests drive rotations with it); afterRotate is called after each attempt.
func (r *KeyRing) startRotation(interval, retention time.Duration, ephemeralVersions []int,
	createKey func(context.Context) (hkdfguard.DataEncryptionKey, error), logger *slog.Logger,
	ticks <-chan time.Time, afterRotate func()) {

	rot := &rotation{
		ring: r, interval: interval, retention: retention, createKey: createKey, logger: logger,
		ephemeral: map[int]bool{}, supersededAt: map[int]time.Time{}, done: make(chan struct{}),
	}
	for _, v := range ephemeralVersions {
		rot.ephemeral[v] = true
	}
	r.rotation = rot

	var ticker *time.Ticker
	if ticks == nil {
		ticker = time.NewTicker(interval)
		ticks = ticker.C
	}
	ctx, cancel := context.WithCancel(context.Background())
	rot.cancel = cancel

	go func() {
		defer close(rot.done)
		if ticker != nil {
			defer ticker.Stop()
		}
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticks:
				rot.rotate(ctx)
				if afterRotate != nil {
					afterRotate()
				}
			}
		}
	}()
}

func (rot *rotation) stop() {
	rot.cancel()
	<-rot.done
}

// rotate creates a fresh key and adds it at CurrentVersion + 1, then retires every ephemeral key
// whose retention has run out. A failure - the key wrapper unavailable, the next version taken,
// versions exhausted - is recorded and logged, the current key stays in use, and the next interval
// tries again. It reports whether a new key became current.
func (rot *rotation) rotate(ctx context.Context) bool {
	ctx, span := diagnostics.DataProtection.Start(ctx, diagnostics.SpanDataProtectionKeyRingRotateEphemeral)
	defer span.End()

	current, err := rot.ring.CurrentVersion()
	if err == nil && current == math.MaxInt32 {
		err = fmt.Errorf("%w: version %d is current, so there is no higher version to rotate to; the current key stays in use", ErrVersionOutOfRange, current)
	}
	if err != nil {
		diagnostics.RecordError(span, err)
		diagnostics.EphemeralKeyRotationFailed(ctx, rot.logger, current, err)
		return false
	}

	next := current + 1
	key, err := rot.createKey(ctx)
	if err == nil {
		err = rot.ring.Add(ctx, next, key)
	}
	if err != nil {
		// Not added, so not owned by the ring: release its revealed key here.
		if closer, ok := key.(io.Closer); ok {
			_ = closer.Close()
		}
		if ctx.Err() != nil {
			return false // shutdown
		}
		diagnostics.RecordError(span, err)
		diagnostics.EphemeralKeyRotationFailed(ctx, rot.logger, current, err)
		return false
	}

	rot.ephemeral[next] = true
	span.SetAttributes(diagnostics.AttrKeyVersion.Int(next))
	diagnostics.EphemeralKeyRotated(ctx, rot.logger, next)

	rot.retire(ctx, time.Now())
	return true
}

// retire removes and closes every ephemeral key that stopped being current at least the retention
// ago. A key is first seen as superseded by the rotation after the one that replaced it, so it is
// kept for at least the retention - never less. Key-file versions are never touched.
func (rot *rotation) retire(ctx context.Context, now time.Time) {
	if rot.retention <= 0 {
		return
	}

	current, _ := rot.ring.CurrentVersion()
	for version := range rot.ephemeral {
		if _, seen := rot.supersededAt[version]; version != current && !seen {
			rot.supersededAt[version] = now
		}
	}

	for version, since := range rot.supersededAt {
		if version == current || now.Sub(since) < rot.retention {
			continue
		}
		delete(rot.supersededAt, version)
		delete(rot.ephemeral, version)

		removed, err := rot.ring.remove(version)
		switch {
		case err != nil:
			// Already out of the ring; a failure to release it must not stop the rotation.
			diagnostics.EphemeralKeyRetirementFailed(ctx, rot.logger, version, err)
		case removed:
			diagnostics.EphemeralKeyRetired(ctx, rot.logger, version)
		}
	}
}

// --- Protector ----------------------------------------------------------------------------------

// protector is the KeyRing's hkdfguard.DataProtector. Only CreateProtector makes one, so every
// instance is bound to a real ring.
type protector struct {
	name string
	aad  []byte
	ring *KeyRing
}

// Encrypt encrypts plaintext under the ring's current key and formats the result. plaintext is
// not zeroed: the caller owns it (the copy made here is zeroed).
func (p *protector) Encrypt(ctx context.Context, plaintext []byte) (string, error) {
	telemetry := diagnostics.DataProtection
	ctx, span := telemetry.Start(ctx, diagnostics.SpanDataProtectionProtectorEncrypt)
	defer span.End()
	telemetry.LogSensitiveOperation(span, diagnostics.SpanDataProtectionProtectorEncrypt,
		diagnostics.AttrName.String(p.name), diagnostics.AttrPlaintextLength.Int(len(plaintext)))

	version, key, err := p.ring.Current(ctx)
	if err != nil {
		return "", recordError(span, err)
	}

	// The key zeroes what it encrypts; the caller's plaintext is theirs to keep.
	scratch := make([]byte, len(plaintext))
	copy(scratch, plaintext)
	ciphertext, err := key.Encrypt(ctx, scratch, p.aad)
	hkdfguard.Wipe(scratch)
	if err != nil {
		return "", recordError(span, err)
	}

	formatted, err := p.ring.formatProvider.Format(ctx, hkdfguard.KeyTrackingValue{KeyVersion: version, Value: ciphertext})
	if err != nil {
		return "", recordError(span, err)
	}
	return formatted, nil
}

// Decrypt parses encrypted and decrypts it, under whichever version it names, into result,
// returning the number of bytes written. Size result with MaxDecryptedLength.
func (p *protector) Decrypt(ctx context.Context, encrypted string, result []byte) (int, error) {
	telemetry := diagnostics.DataProtection
	ctx, span := telemetry.Start(ctx, diagnostics.SpanDataProtectionProtectorDecrypt)
	defer span.End()
	telemetry.LogSensitiveOperation(span, diagnostics.SpanDataProtectionProtectorDecrypt,
		diagnostics.AttrName.String(p.name), diagnostics.AttrEncryptedLength.Int(len(encrypted)))

	value, err := p.ring.formatProvider.Parse(ctx, encrypted)
	if err != nil {
		return 0, recordError(span, err)
	}
	key, err := p.ring.Get(ctx, value.KeyVersion)
	if err != nil {
		return 0, recordError(span, err)
	}
	n, err := key.Decrypt(ctx, value.Value, p.aad, result)
	if err != nil {
		return 0, recordError(span, err)
	}
	return n, nil
}

// MaxDecryptedLength is an upper bound on how many bytes Decrypt will write for encrypted.
func (p *protector) MaxDecryptedLength(ctx context.Context, encrypted string) (int, error) {
	return p.ring.formatProvider.MaxDecryptedLength(ctx, encrypted)
}
