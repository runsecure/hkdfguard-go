package aesgcm256

import (
	"context"
	"fmt"
	"time"

	"github.com/runsecure/hkdfguard-go"
)

// Factory mints AES-256-GCM Providers for a KeyRing - the hkdfguard.CryptoProviderFactory for
// this cipher. Its options (such as WithLogger) are handed to every provider it creates.
type Factory struct {
	opts []Option
}

var _ hkdfguard.CryptoProviderFactory = (*Factory)(nil)

// NewFactory returns a Factory whose providers are configured with opts.
func NewFactory(opts ...Option) *Factory {
	return &Factory{opts: opts}
}

// Create builds a Provider for an existing wrapped DEK - see New.
func (f *Factory) Create(ctx context.Context, wrapper hkdfguard.KeyWrapper, wrapped []byte, expiry time.Duration, policy hkdfguard.RefreshFailurePolicy) (hkdfguard.CryptoProvider, error) {
	return New(ctx, wrapper, wrapped, expiry, policy, f.opts...)
}

// CreateEphemeral has wrapper generate and wrap a fresh DEK, then builds a Provider that reveals
// it. Bad arguments are reported before the key wrapper is asked to generate anything.
func (f *Factory) CreateEphemeral(ctx context.Context, wrapper hkdfguard.KeyWrapper, expiry time.Duration, policy hkdfguard.RefreshFailurePolicy) (hkdfguard.CryptoProvider, error) {
	if err := validate(expiry, policy); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Sized to the same limit a key file is held to; trimmed to what GenerateAndWrap wrote.
	buffer := make([]byte, hkdfguard.MaxWrappedKeyBytes)
	n, err := wrapper.GenerateAndWrap(ctx, buffer)
	if err != nil {
		return nil, err
	}
	if n <= 0 || n > len(buffer) {
		return nil, fmt.Errorf("%w: key wrapper reported a %d-byte wrapped key in a %d-byte buffer", ErrInvalidLength, n, len(buffer))
	}
	return New(ctx, wrapper, buffer[:n], expiry, policy, f.opts...)
}
