package hkdfguard

import (
	"context"
	"io"
)

// DataEncryptionKey is one data encryption key (DEK): it AEAD-encrypts and decrypts byte payloads
// under it, bound to optional Additional Authenticated Data (nil means none).
//
// Encrypt consumes its plaintext. The plaintext slice is zeroed before Encrypt returns, whether or
// not it succeeds, so a secret handed in is never left behind in the caller's buffer. Callers that
// still need the value afterwards must pass a copy. Decrypt never modifies its ciphertext.
type DataEncryptionKey interface {
	// Encrypt encrypts plaintext under this key, bound to aad, and returns the ciphertext, ready
	// to be stored. plaintext is zeroed before this returns.
	Encrypt(ctx context.Context, plaintext, aad []byte) ([]byte, error)

	// Decrypt decrypts and authenticates ciphertext encrypted with the same aad, writing the
	// plaintext into result and returning the number of bytes written. The caller owns result and
	// should zero it (Wipe) once done.
	Decrypt(ctx context.Context, ciphertext, aad, result []byte) (int, error)
}

// KeyRing is a set of data encryption keys tracked by version, one of which is current. Anything
// that encrypts asks for the current key on every operation, so it follows rotation
// automatically; anything that decrypts asks for the exact version the value was encrypted under,
// so values encrypted before a rotation still decrypt.
type KeyRing interface {
	// CurrentVersion returns the version new values are encrypted under - the highest one
	// registered - or ErrNoCurrentKey if none is.
	CurrentVersion() (int, error)

	// Current returns the current version together with its key, read atomically, or
	// ErrNoCurrentKey if none is registered.
	Current(ctx context.Context) (int, DataEncryptionKey, error)

	// Get returns the key registered for version, or an error wrapping ErrKeyNotFound.
	Get(ctx context.Context, version int) (DataEncryptionKey, error)

	// TryGet returns the key registered for version, and false on a miss.
	TryGet(ctx context.Context, version int) (DataEncryptionKey, bool)
}

// KeyTrackingValue is an encrypted value together with the key version it was encrypted under -
// what an EncryptedFormatProvider formats into, and parses back out of, the stored string.
type KeyTrackingValue struct {
	// KeyVersion is the KeyRing version whose key encrypted Value.
	KeyVersion int

	// Value is the ciphertext.
	Value []byte
}

// EncryptedFormatProvider converts between a KeyTrackingValue and the string it is stored as.
type EncryptedFormatProvider interface {
	// Format renders value as its stored string.
	Format(ctx context.Context, value KeyTrackingValue) (string, error)

	// Parse reads a stored string back into the value it was formatted from.
	Parse(ctx context.Context, encrypted string) (KeyTrackingValue, error)

	// MaxDecryptedLength computes an upper bound on the decrypted plaintext's length in bytes
	// from the encoded payload's length alone, without decoding it. AEAD ciphertext is always at
	// least as long as the plaintext it encloses, so the actual decrypted length is this value or
	// less - always safe to size a result buffer to.
	MaxDecryptedLength(ctx context.Context, encrypted string) (int, error)
}

// DataProtector is a named, string-level data protector: the name given at construction is used
// as the Additional Authenticated Data for every Encrypt/Decrypt, binding a protected value to the
// purpose it was protected for so it can't be reused under a different one. Encrypt/Decrypt
// resolve the actual DataEncryptionKey to use from a KeyRing, rather than holding one key
// permanently.
//
// Plaintext travels as []byte (UTF-8), never as a string, because a string can't be zeroed.
type DataProtector interface {
	// Encrypt encrypts plaintext and formats the result via the configured
	// EncryptedFormatProvider. plaintext is not zeroed: the caller owns it and should Wipe it
	// once done (any copy made inside this call is zeroed).
	Encrypt(ctx context.Context, plaintext []byte) (string, error)

	// Decrypt parses a formatted encrypted string via the configured EncryptedFormatProvider and
	// decrypts it directly into result, returning the number of bytes written.
	Decrypt(ctx context.Context, encrypted string, result []byte) (int, error)

	// MaxDecryptedLength computes an upper bound on how many bytes Decrypt will write for
	// encrypted, so a result buffer can be sized without decrypting first.
	MaxDecryptedLength(ctx context.Context, encrypted string) (int, error)
}

// PipelineDataProtector is a short-lived, string-level protector for a pipeline that must encrypt
// secrets before a durable KEK exists. Unlike DataProtector, it is not bound to one purpose: every
// Encrypt/Decrypt names the secret it's protecting, so one instance - and therefore one key - can
// protect many secrets, each bound to its own identifier. It owns a single in-memory key for its
// whole lifetime, stamps every value with KeyVersion, and exposes that key once the pipeline is
// done so it can be wrapped under a real KEK. Close zeroes the key.
//
// The secret identifier is the configuration key the value will be stored under - its full path,
// e.g. "ConnectionStrings:Admin". It's bound into the value as Additional Authenticated Data via
// ConfigurationAAD, the same rule encrypted configuration reads with, so once this key is wrapped
// and registered at KeyVersion, the configuration reader reveals the value - and a value copied
// under any other key fails authentication. Identifiers are case-insensitive for ASCII letters
// only (see ConfigurationPurpose).
type PipelineDataProtector interface {
	io.Closer

	// KeyVersion is the version stamped on every value - the version this key will be
	// registered under.
	KeyVersion() int

	// Encrypt encrypts plaintext bound to secretIdentifier, and formats the result via the
	// configured EncryptedFormatProvider. plaintext is not zeroed: the caller owns it and should
	// Wipe it once done. Fails with ErrInvalidConfigurationKey if secretIdentifier is empty.
	Encrypt(ctx context.Context, plaintext []byte, secretIdentifier string) (string, error)

	// Decrypt parses and decrypts a formatted value directly into result, verifying it was
	// encrypted for secretIdentifier, and returns the number of bytes written. Fails with
	// ErrInvalidConfigurationKey if secretIdentifier is empty.
	Decrypt(ctx context.Context, encrypted, secretIdentifier string, result []byte) (int, error)

	// MaxDecryptedLength returns an upper bound on how many bytes Decrypt will write for encrypted.
	MaxDecryptedLength(ctx context.Context, encrypted string) (int, error)

	// KeyBase64 returns the key, base64-encoded, for handing to the native platform's wrap
	// process at the end of the pipeline. The slice is a buffer the protector owns and zeroes on
	// Close: consume it before closing, and never convert it to a string. Pass it to the wrap tool
	// on standard input (--dek-stdin), never as a command-line argument or environment variable,
	// which process listings and logs capture.
	KeyBase64() []byte
}
