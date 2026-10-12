package hkdfguard

import (
	"context"
	"errors"
	"fmt"
	"unicode/utf8"
)

// CacheAADPrefix begins the Additional Authenticated Data of every ProtectedCache entry, keeping
// it distinct from any other purpose. A KeyRing refuses protector names starting with it, so no
// protector can decrypt a cache entry or produce one a cache would accept.
const CacheAADPrefix = "HkdfGuard.Cache:"

// ErrInvalidCacheName reports a cache entry name that is not valid UTF-8.
var ErrInvalidCacheName = errors.New("hkdfguard: invalid cache name")

// CacheAAD returns the Additional Authenticated Data a cache entry stored under name is bound to:
// the UTF-8 bytes of CacheAADPrefix + name, with the ASCII letters a-z upper-cased and every other
// byte left as it is - the same rule, and the same matching, every port uses. Names that differ
// only in ASCII case share an entry and an AAD; "café" and "CAFÉ" are two names. A name that isn't
// valid UTF-8 is refused with ErrInvalidCacheName, since it has no unambiguous AAD.
func CacheAAD(name string) ([]byte, error) {
	if !utf8.ValidString(name) {
		return nil, fmt.Errorf("%w: the name is not valid UTF-8", ErrInvalidCacheName)
	}
	aad := make([]byte, 0, len(CacheAADPrefix)+len(name))
	aad = append(aad, CacheAADPrefix...)
	aad = append(aad, name...)
	upperASCII(aad[len(CacheAADPrefix):])
	return aad, nil
}

// ProtectedReadOnlyCache is the read surface of a highly concurrent name -> encrypted-value cache.
// Names are compared ignoring ASCII case only ("Item" and "ITEM" are the same name; "café" and
// "CAFÉ" are not), and each value is bound to its name, so a value can only be revealed under the
// name it was stored for. Nothing here ever holds plaintext beyond the duration of a single
// Decrypt call - only the encrypted bytes are retained internally.
type ProtectedReadOnlyCache interface {
	// Decrypt decrypts the value stored under name into result and returns the number of bytes
	// written, or 0 (and a nil error) if no value is stored under name. The caller owns result
	// and should Wipe it once done.
	Decrypt(ctx context.Context, name string, result []byte) (int, error)

	// MaxDecryptedLength computes an upper bound on how many bytes Decrypt will write for the
	// value stored under name, so a result buffer can be sized without decrypting first. ok is
	// false if no value is stored under name.
	MaxDecryptedLength(ctx context.Context, name string) (maxLength int, ok bool, err error)
}

// ProtectedCache is the read/write surface of a ProtectedReadOnlyCache: Add/AddOrUpdate protect
// and store plaintext under a name. Nothing here ever holds plaintext beyond the duration of a
// single Add/AddOrUpdate call - only the encrypted bytes are retained internally.
type ProtectedCache interface {
	ProtectedReadOnlyCache

	// Add encrypts plaintext and stores it under name. plaintext is zeroed as a side effect of
	// encrypting it. Fails with an error wrapping ErrAlreadyExists if a value is already stored
	// under name.
	Add(ctx context.Context, name string, plaintext []byte) error

	// AddOrUpdate encrypts plaintext and stores it under name, replacing any value already stored
	// under that name. plaintext is zeroed as a side effect of encrypting it.
	AddOrUpdate(ctx context.Context, name string, plaintext []byte) error
}
