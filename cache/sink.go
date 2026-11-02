package cache

import (
	"context"
	"errors"
	"fmt"

	"github.com/runsecure/hkdfguard-go"
)

// ErrSinkRefused reports a value a SecretSink won't take: one already set for the same secret or
// key, or one handed over after the fetch it belongs to has returned.
var ErrSinkRefused = errors.New("cache: secret value refused")

// SecretSink receives what a SecretStore's Fetch read, and encrypts each value at once, bound to its
// own name within the secret being fetched - nothing else can be stored through it, and it refuses
// every call once that fetch has returned. Set the secret's whole value at most once, and each key
// at most once; an empty value counts as none. Every method zeroes the plaintext it is given,
// whether or not it succeeds. Use it only from the goroutine Fetch runs on.
type SecretSink struct {
	ctx         context.Context
	store       *store
	secretEntry string
	values      map[string]*hkdfguard.KeyTrackingValue
	closed      bool
}

// SetBytes encrypts plaintext as the secret's whole value, and zeroes it. It fails with
// ErrSinkRefused when the value was already set or the fetch has returned.
func (s *SecretSink) SetBytes(plaintext []byte) error { return s.set(s.secretEntry, plaintext) }

// SetKeyBytes encrypts plaintext as the value of one key the secret holds - looked up as
// "name#key" - and zeroes it. It fails with ErrInvalidKey when key isn't one a name can hold (see
// IsValidKey), and with ErrSinkRefused when that key was already set or the fetch has returned.
func (s *SecretSink) SetKeyBytes(key string, plaintext []byte) error {
	if !IsValidKey(key) {
		hkdfguard.Wipe(plaintext)
		return fmt.Errorf("%w: '%s' isn't a key: 1-%d printable ASCII characters other than space, '!' and '#'", ErrInvalidKey, key, MaxKeyLength)
	}
	return s.set(s.secretEntry+string(KeySeparator)+escapeCase(key), plaintext)
}

// SetBytesWithJSONKeys encrypts plaintext as the secret's whole value and, when it is a JSON object -
// such as an AWS Secrets Manager key/value secret - each of its top-level members as a key: a string
// as its UTF-8 bytes, a number, true or false as its JSON text. A member that is null, an object or
// an array, or whose name isn't a key a name can hold, is left out. Anything that isn't a JSON
// object - plain text, an array, malformed JSON - is the whole value only. plaintext is zeroed, and
// so is every buffer a member was unescaped into once it is encrypted.
//
// It fails with ErrInvalidSecretData when the JSON object holds a member name more than once, and
// with ErrSinkRefused when the value or a key was already set or the fetch has returned.
func (s *SecretSink) SetBytesWithJSONKeys(plaintext []byte) error {
	defer hkdfguard.Wipe(plaintext)
	if err := setJSONKeys(plaintext, s); err != nil {
		return err
	}
	return s.SetBytes(plaintext)
}

func (s *SecretSink) close() { s.closed = true }

func (s *SecretSink) set(entry string, plaintext []byte) error {
	defer hkdfguard.Wipe(plaintext)
	if s.closed {
		return fmt.Errorf("%w: the fetch this value belongs to has already returned", ErrSinkRefused)
	}
	if _, set := s.values[entry]; set {
		return fmt.Errorf("%w: a value has already been set for this secret or key", ErrSinkRefused)
	}
	if len(plaintext) == 0 {
		return nil
	}
	value, err := s.store.encrypt(s.ctx, entry, plaintext)
	if err != nil {
		return err
	}
	s.values[entry] = value
	return nil
}
