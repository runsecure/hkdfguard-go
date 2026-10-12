package dek

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/runsecure/hkdfguard-go"
)

// rotatingRing builds a ring with ephemeral key 1 whose rotations the test drives with tick.
type rotatingRing struct {
	*KeyRing
	factory *recordingFactory
	logs    *capturingHandler
	ticks   chan time.Time
	rotated chan struct{}
}

func newRotatingRing(t *testing.T, mutate func(*Config)) *rotatingRing {
	t.Helper()
	logger, logs := newCapturingLogger()
	r := &rotatingRing{factory: &recordingFactory{t: t}, logs: logs, ticks: make(chan time.Time), rotated: make(chan struct{}, 16)}
	config := baseConfig(r.factory)
	config.EphemeralKeys = []int{1}
	config.Logger = logger
	config.rotationTicks = r.ticks
	config.afterRotate = func() { r.rotated <- struct{}{} }
	if mutate != nil {
		mutate(&config)
	}
	r.KeyRing = mustBuild(t, config)
	return r
}

func (r *rotatingRing) tick(t *testing.T) {
	t.Helper()
	select {
	case r.ticks <- time.Now():
	case <-time.After(5 * time.Second):
		t.Fatal("the rotation loop did not take the tick")
	}
	<-r.rotated
}

func TestRotation_Defaults(t *testing.T) {
	ring := newRotatingRing(t, nil)

	if interval, ok := ring.EphemeralKeyRotationInterval(); !ok || interval != 24*time.Hour {
		t.Errorf("interval = %v, %v", interval, ok)
	}
	if ring.rotation.retention != 24*time.Hour {
		t.Errorf("retention = %v", ring.rotation.retention)
	}
}

func TestRotation_AddsAFreshCurrentVersionEachInterval_AndOldValuesStillDecrypt(t *testing.T) {
	ring := newRotatingRing(t, nil)
	protector, _ := ring.CreateProtector("rotation")
	underV1 := protect(t, protector, "written under v1")

	ring.tick(t)
	ring.tick(t)

	requireCurrent(t, ring.KeyRing, 3)
	if formatted := protect(t, protector, "now"); !strings.HasPrefix(formatted, "enc::v3::") {
		t.Errorf("new value = %q", formatted)
	}
	if got, err := unprotect(protector, underV1); err != nil || got != "written under v1" {
		t.Errorf("v1 value: %q, %v", got, err)
	}
	if len(ring.logs.withEventID(6)) != 2 {
		t.Errorf("%d rotations logged", len(ring.logs.withEventID(6)))
	}
	if ring.factory.ephemerals != 3 {
		t.Errorf("CreateEphemeral called %d times", ring.factory.ephemerals)
	}
}

func TestRotation_NeverRunsOnAKeyFileRing_OrWhenDisabled(t *testing.T) {
	f := &recordingFactory{t: t}
	config := baseConfig(f)
	config.KeyFiles = map[int]string{4: writeKeyFile(t, []byte("wrapped"))}
	if _, ok := mustBuild(t, config).EphemeralKeyRotationInterval(); ok {
		t.Error("a key-file ring rotates")
	}

	config = baseConfig(f)
	config.EphemeralKeys = []int{1}
	config.DisableEphemeralKeyRotation = true
	if _, ok := mustBuild(t, config).EphemeralKeyRotationInterval(); ok {
		t.Error("rotation was not disabled")
	}
}

func TestRotation_AFailureKeepsTheCurrentKey_AndTheNextIntervalSucceeds(t *testing.T) {
	ring := newRotatingRing(t, nil)

	ring.factory.fail(errors.New("KEK unavailable"))
	ring.tick(t)
	requireCurrent(t, ring.KeyRing, 1)
	if failures := ring.logs.withEventID(7); len(failures) != 1 || !strings.Contains(failures[0].Message, "version 1 stays current") {
		t.Errorf("%d rotation failures logged", len(failures))
	}

	ring.tick(t)
	requireCurrent(t, ring.KeyRing, 2)
}

func TestRotation_WhenTheNextVersionIsTaken_FailsAndClosesTheKeyItMade(t *testing.T) {
	ring := newRotatingRing(t, nil)
	// While the rotation is creating its key for version 2, something else registers version 2.
	ring.factory.onCreate = func() {
		key, _ := newTestKey(t)
		_ = ring.Add(bg, 2, key)
	}

	ring.tick(t)

	made := ring.factory.providers()
	if last := made[len(made)-1]; last.closes() != 1 {
		t.Errorf("the key the failed rotation made was closed %d times", last.closes())
	}
	if len(ring.logs.withEventID(7)) != 1 {
		t.Error("the failed rotation was not logged")
	}
}

func TestRotation_AtTheLastVersion_RefusesWithoutCreatingAKey(t *testing.T) {
	ring := newRotatingRing(t, nil)
	key, _ := newTestKey(t)
	_ = ring.Add(bg, math.MaxInt32, key)
	created := len(ring.factory.providers())

	if ring.rotation.rotate(context.Background()) {
		t.Fatal("rotated past the last version")
	}
	if len(ring.factory.providers()) != created {
		t.Error("a key was created")
	}
	if len(ring.logs.withEventID(7)) != 1 {
		t.Error("the refusal was not logged")
	}
}

func TestClose_StopsTheRotation(t *testing.T) {
	ring := newRotatingRing(t, nil)

	_ = ring.Close()

	select {
	case <-ring.rotation.done:
	default:
		t.Error("the rotation goroutine is still running")
	}
}

// --- Retirement -----------------------------------------------------------------------------

func TestRetire_KeepsASupersededKeyForItsRetention_ThenClosesAndRemovesIt(t *testing.T) {
	ring := newRotatingRing(t, func(c *Config) { c.EphemeralKeyRetention = time.Hour })
	protector, _ := ring.CreateProtector("retire")
	underV1 := protect(t, protector, "old")
	v1Provider := ring.factory.providers()[0]

	ring.tick(t) // v2 current; v1 first seen superseded now
	start := time.Now()

	ring.rotation.retire(bg, start.Add(59*time.Minute))
	if _, ok := ring.TryGet(bg, 1); !ok {
		t.Fatal("v1 retired before its retention")
	}

	ring.rotation.retire(bg, start.Add(61*time.Minute))
	if _, ok := ring.TryGet(bg, 1); ok {
		t.Fatal("v1 still registered after its retention")
	}
	if v1Provider.closes() != 1 {
		t.Errorf("v1's provider closed %d times", v1Provider.closes())
	}
	if _, err := unprotect(protector, underV1); !errors.Is(err, hkdfguard.ErrKeyNotFound) {
		t.Errorf("decrypting under a retired key: %v", err)
	}
	if len(ring.logs.withEventID(8)) != 1 {
		t.Error("the retirement was not logged")
	}
	requireCurrent(t, ring.KeyRing, 2)
}

func TestRetire_NeverTouchesKeyFileVersionsOrTheCurrentKey(t *testing.T) {
	ring := newRotatingRing(t, func(c *Config) {
		c.KeyFiles = map[int]string{0: writeKeyFile(t, []byte("wrapped"))}
		c.EphemeralKeyRetention = time.Minute
	})
	ring.tick(t)

	ring.rotation.retire(bg, time.Now().Add(24*time.Hour))
	ring.rotation.retire(bg, time.Now().Add(48*time.Hour))

	for version, want := range map[int]bool{0: true, 1: false, 2: true} {
		if _, ok := ring.TryGet(bg, version); ok != want {
			t.Errorf("version %d registered = %v, want %v", version, ok, want)
		}
	}
}

func TestRetire_WhenClosingAKeyFails_StillRemovesIt_AndLogsAnError(t *testing.T) {
	ring := newRotatingRing(t, func(c *Config) { c.EphemeralKeyRetention = time.Minute })
	ring.factory.providers()[0].closeErr = errors.New("close failed")
	ring.tick(t)

	ring.rotation.retire(bg, time.Now())
	ring.rotation.retire(bg, time.Now().Add(time.Hour))

	if _, ok := ring.TryGet(bg, 1); ok {
		t.Error("v1 still registered")
	}
	if len(ring.logs.withEventID(9)) != 1 {
		t.Error("the failed retirement was not logged")
	}
}
