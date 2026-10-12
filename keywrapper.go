package hkdfguard

import "context"

// MaxWrappedKeyBytes is the largest wrapped DEK, in bytes, this library will read from a key file
// or let a key wrapper generate. Today's native payloads are far smaller (156 bytes on macOS); the
// headroom allows larger keys for other symmetric algorithms and additional fingerprinting. Raise
// this one value to allow bigger payloads: key-file checks and the buffer CryptoProviderFactory
// implementations generate into both follow it.
const MaxWrappedKeyBytes = 512

// KeyWrapper protects (Wrap) and reveals (Unwrap) an encryption key against a single, implicitly
// identified KEK (e.g. a native KMS-backed key, identified by service name at construction, or a
// remote KMS/HSM key). Unwrap takes the wrapped payload as an explicit argument on every call, so
// one instance can reveal any number of different wrapped keys sharing the same KEK - it holds no
// wrapped payload of its own. Network-backed implementations (e.g. AWS KMS, CloudHSM) should
// honor ctx's cancellation and deadline; local implementations may ignore it.
type KeyWrapper interface {
	// Wrap protects the plaintext key, writing the wrapped key into result and returning the
	// number of bytes written.
	Wrap(ctx context.Context, plaintext, result []byte) (int, error)

	// Unwrap reveals a previously-wrapped key into result and returns the number of bytes
	// written. Implementations must write the complete key and return its exact length -
	// consumers reject any other count rather than use a partially-filled buffer - must fail
	// (never return unauthenticated bytes) when wrapped has been tampered with, and should zero
	// result on failure.
	Unwrap(ctx context.Context, wrapped, result []byte) (int, error)

	// GenerateAndWrap generates a fresh key and immediately protects it against the same KEK this
	// instance wraps/reveals against, writing the wrapped key into result and returning the number
	// of bytes written - the plaintext key never leaves this call.
	GenerateAndWrap(ctx context.Context, result []byte) (int, error)
}
