// Package aesgcm256 is the AES-256-GCM implementation of hkdfguard.CryptoProviderFactory,
// hkdfguard.CryptoProvider and hkdfguard.PipelineDataProtector - the Go port of the .NET
// HkdfGuard.CryptoProvider.AesGcm256 library.
//
// It is one interchangeable cipher: everything above it (key rings, protectors, caches) depends
// only on the hkdfguard interfaces, so another AEAD's module can replace it by supplying its own
// CryptoProviderFactory. Failures a caller may need to act on are reported with the cipher-neutral
// sentinel errors in package hkdfguard (ErrAuthenticationFailed, ErrKeyAccessSuspended,
// ErrEncryptionLimitReached, ErrClosed), so callers handle every cipher the same way.
//
// Ciphertext is [12-byte random nonce | ciphertext | 16-byte GCM tag], byte-compatible with the
// .NET port. With random nonces a key is limited to MaxEncryptionsPerKey encryptions, counted per
// key across every provider in the process.
//
// Memory: the revealed key is held in a []byte that is zeroed when its session is closed, but two
// copies are outside this package's reach. Go's crypto/aes keeps an expanded key schedule inside the
// cipher it builds, and the HMAC that names a key's encryption budget keeps the key bytes in its
// hash state; neither can be zeroed, and both stay in the heap until the garbage collector reclaims
// them. Process hardening, which blocks core dumps and debugger attachment, keeps them out of reach.
package aesgcm256
