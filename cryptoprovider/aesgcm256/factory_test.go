package aesgcm256

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/runsecure/hkdfguard-go"
)

func TestFactory_SatisfiesTheInterface_AndBuildsWorkingProviders(t *testing.T) {
	var factory hkdfguard.CryptoProviderFactory = NewFactory()

	created, err := factory.Create(context.Background(), &fakeKeyWrapper{}, []byte("wrapped"), time.Minute, hkdfguard.RefreshFailurePolicy{})
	if err != nil {
		t.Fatal(err)
	}
	defer created.Close()
	requireRoundTrip(t, created)

	ephemeral, err := factory.CreateEphemeral(context.Background(), &fakeKeyWrapper{}, time.Minute, hkdfguard.RefreshFailurePolicy{})
	if err != nil {
		t.Fatal(err)
	}
	defer ephemeral.Close()
	requireRoundTrip(t, ephemeral)
}

func TestCreateEphemeral_GeneratesOnce_ThenRevealsOnce(t *testing.T) {
	wrapper := &fakeKeyWrapper{}

	p, err := NewFactory().CreateEphemeral(context.Background(), wrapper, time.Minute, hkdfguard.RefreshFailurePolicy{})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	if unwrap, generate := wrapper.calls(); unwrap != 1 || generate != 1 {
		t.Errorf("unwrap %d, generate %d", unwrap, generate)
	}
}

func TestFactory_PassesThePolicyAndLoggerToEveryProvider(t *testing.T) {
	logger, logs := newCapturingLogger()
	factory := NewFactory(WithLogger(logger))

	created, _ := factory.Create(context.Background(), &fakeKeyWrapper{}, []byte("wrapped"), time.Minute, hkdfguard.FailClosedAfter(4))
	ephemeral, _ := factory.CreateEphemeral(context.Background(), &fakeKeyWrapper{}, time.Minute, hkdfguard.FailOpen())
	defer created.Close()
	defer ephemeral.Close()

	if limit, _ := created.(*Provider).RefreshFailurePolicy().MaxFailures(); limit != 4 {
		t.Errorf("created limit = %d", limit)
	}
	if _, failsClosed := ephemeral.(*Provider).RefreshFailurePolicy().MaxFailures(); failsClosed {
		t.Error("ephemeral fails closed")
	}
	if created.(*Provider).logger != logger || ephemeral.(*Provider).logger != logger {
		t.Error("the factory's logger was not handed on")
	}
	_ = logs
}

func TestFactory_BadArgumentsOrACancelledContext_NeverReachTheKeyWrapper(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	factory := NewFactory()
	cases := []struct {
		ctx    context.Context
		expiry time.Duration
		policy hkdfguard.RefreshFailurePolicy
	}{
		{context.Background(), 0, hkdfguard.RefreshFailurePolicy{}},
		{context.Background(), 301 * time.Second, hkdfguard.RefreshFailurePolicy{}},
		{context.Background(), time.Minute, hkdfguard.FailClosedAfter(0)},
		{context.Background(), time.Minute, hkdfguard.FailClosedAfter(101)},
		{cancelled, time.Minute, hkdfguard.RefreshFailurePolicy{}},
	}
	for i, c := range cases {
		wrapper := &fakeKeyWrapper{}
		if _, err := factory.Create(c.ctx, wrapper, []byte("wrapped"), c.expiry, c.policy); err == nil {
			t.Errorf("case %d: Create succeeded", i)
		}
		if _, err := factory.CreateEphemeral(c.ctx, wrapper, c.expiry, c.policy); err == nil {
			t.Errorf("case %d: CreateEphemeral succeeded", i)
		}
		if unwrap, generate := wrapper.calls(); unwrap+generate != 0 {
			t.Errorf("case %d: the key wrapper was called", i)
		}
	}
}

func TestFactory_WhenTheFirstRevealFails_ReturnsTheError(t *testing.T) {
	_, err := NewFactory().Create(context.Background(), &fakeKeyWrapper{unwrapErr: errKEK}, []byte("wrapped"), time.Minute, hkdfguard.RefreshFailurePolicy{})

	if !errors.Is(err, errKEK) {
		t.Errorf("error = %v", err)
	}
}
