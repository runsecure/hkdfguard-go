// Package encryptedconfig reads secrets that a deployment pipeline encrypted into configuration -
// the Go port of the .NET HkdfGuard.EncryptedConfiguration library.
//
// At deploy time a PipelineDataProtector encrypts each secret bound to the configuration key it is
// stored under (see hkdfguard.ConfigurationPurpose) and writes the enc::v<version>::<base64> value
// into configuration. At runtime a Reader looks that value up by the same key and decrypts it
// through the KeyRing the pipeline's key was registered in. A value moved to a different key fails
// authentication rather than decrypting.
//
// The Reader works with any configuration source: it takes a Lookup function from a key to its
// stored string. os.LookupEnv is one; EnvLookup, NewMapLookup and FlattenJSON adapt the conventions
// .NET configuration uses, so one set of pipeline output serves both ports.
package encryptedconfig

import (
	"context"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/diagnostics"
)

// Lookup returns the value stored under a configuration key, and false if there is none. Keys are
// the identifiers the pipeline encrypted under - full configuration paths such as
// "ConnectionStrings:Admin".
type Lookup func(key string) (value string, ok bool)

// ProtectorFactory creates the DataProtector for a purpose - satisfied by *dek.KeyRing.
type ProtectorFactory interface {
	CreateProtector(name string) (hkdfguard.DataProtector, error)
}

// Reader decrypts protected configuration values. It holds no plaintext and caches nothing: each
// Decrypt looks the value up fresh, so a configuration reload takes effect immediately. It is a
// hkdfguard.ProtectedReadOnlyCache, so it can sit in a cache.Collection beside other secret
// sources. Safe for concurrent use if lookup is.
type Reader struct {
	protectors ProtectorFactory
	lookup     Lookup
}

var _ hkdfguard.ProtectedReadOnlyCache = (*Reader)(nil)

// New returns a Reader that finds values with lookup and decrypts them with protectors.
func New(protectors ProtectorFactory, lookup Lookup) *Reader {
	return &Reader{protectors: protectors, lookup: lookup}
}

// Decrypt decrypts the value stored under the configuration key name into result and returns the
// number of bytes written, or 0 (and a nil error) if lookup has no value for name. Size result
// with MaxDecryptedLength.
//
// A protected empty value also decrypts to 0 bytes, so 0 alone doesn't say whether name is set: use
// TryDecrypt when an empty value and a missing one must be told apart.
//
// The value must have been encrypted for name, ignoring ASCII case; one written for any other key
// fails with hkdfguard.ErrAuthenticationFailed, and one that isn't a protected value fails to
// parse.
func (r *Reader) Decrypt(ctx context.Context, name string, result []byte) (int, error) {
	n, _, err := r.TryDecrypt(ctx, name, result)
	return n, err
}

// TryDecrypt is Decrypt, also reporting whether lookup has a value for name at all: found is false
// for a missing value, and true for one that is present - including one that decrypts to 0 bytes,
// an empty secret. Errors are Decrypt's.
func (r *Reader) TryDecrypt(ctx context.Context, name string, result []byte) (n int, found bool, err error) {
	telemetry := diagnostics.EncryptedConfiguration
	ctx, span := telemetry.Start(ctx, diagnostics.SpanEncryptedConfigurationDecrypt)
	defer span.End()
	telemetry.LogSensitiveOperation(span, diagnostics.SpanEncryptedConfigurationDecrypt, diagnostics.AttrName.String(name))

	value, ok := r.lookup(name)
	if !ok {
		return 0, false, nil
	}
	protector, err := r.protectorFor(name)
	if err == nil {
		if n, err = protector.Decrypt(ctx, value, result); err == nil {
			return n, true, nil
		}
	}
	diagnostics.RecordError(span, telemetry.LoggedError(err, name))
	return 0, true, err
}

// MaxDecryptedLength is an upper bound on how many bytes Decrypt will write for name; ok is false
// if lookup has no value for name.
func (r *Reader) MaxDecryptedLength(ctx context.Context, name string) (int, bool, error) {
	value, ok := r.lookup(name)
	if !ok {
		return 0, false, nil
	}
	protector, err := r.protectorFor(name)
	if err != nil {
		return 0, false, err
	}
	n, err := protector.MaxDecryptedLength(ctx, value)
	if err != nil {
		return 0, false, err
	}
	return n, true, nil
}

// protectorFor returns the protector bound to this one key, so a value copied in from another key
// fails its tag check.
func (r *Reader) protectorFor(name string) (hkdfguard.DataProtector, error) {
	purpose, err := hkdfguard.ConfigurationPurpose(name)
	if err != nil {
		return nil, err
	}
	return r.protectors.CreateProtector(purpose)
}
