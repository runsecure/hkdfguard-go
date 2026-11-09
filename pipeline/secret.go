package pipeline

import (
	"context"
	"unicode/utf8"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/internal/secretjson"
)

// Secret is what a SecretStore's ReadSecret encrypts one secret's values into: the requests made of
// that secret - its whole value, a key, or both - and each value encrypted so far, by file name. Its
// Protect methods encrypt a value bound to its request's file name at once; nothing else can be
// kept through it. Plaintext handed to them is the caller's to zero (hkdfguard.Wipe), but every
// buffer they unescape a value into is zeroed once it is encrypted. Use it only from the goroutine
// ReadSecret runs on.
type Secret struct {
	protector hkdfguard.PipelineDataProtector
	requests  []SecretRequest
	values    map[string]string
}

// Requests is what to read from the secret: its whole value (Key ""), a key, or both.
func (s *Secret) Requests() []SecretRequest { return append([]SecretRequest(nil), s.requests...) }

// Reset drops every value encrypted so far, for a store whose capture runs once per attempt: an
// attempt that is retried leaves nothing behind for the next.
func (s *Secret) Reset() { clear(s.values) }

// ProtectSecret encrypts a secret's whole value for each request without a key, and, when it is
// exactly one JSON object, the value of each requested key it holds (see ProtectKeys). An empty
// secret holds nothing. secret is the caller's to zero.
//
// It fails with ErrInvalidSecretData when a value isn't UTF-8 text, or the object holds a key more
// than once; and as the protector does.
func (s *Secret) ProtectSecret(ctx context.Context, secret []byte) error {
	if len(secret) == 0 {
		return nil
	}
	hasKeys := false
	for _, request := range s.requests {
		if request.Key != "" {
			hasKeys = true
			continue
		}
		if err := s.protect(ctx, secret, request.FileName); err != nil {
			return err
		}
	}
	if hasKeys {
		return s.ProtectKeys(ctx, secret)
	}
	return nil
}

// ProtectKeys encrypts the value of each requested key that json holds, when it is exactly one JSON
// object: a string as its text, a number, true or false as its JSON text. A null, object, array or
// empty value is left out, and so is anything that isn't one JSON object - plain text that merely
// starts like JSON included. json is the caller's to zero; each value is unescaped into a buffer
// that is zeroed once encrypted.
//
// It fails with ErrInvalidSecretData when the object holds a key more than once or a value isn't
// UTF-8 text; and as the protector does.
func (s *Secret) ProtectKeys(ctx context.Context, json []byte) error {
	if !secretjson.IsObject(json) {
		return nil
	}
	return s.protectObject(ctx, json, secretjson.SkipSpace(json, 0))
}

// ProtectBodyKeys encrypts, as ProtectKeys does, the value of each requested key in the object a
// response body leads to through objectPath's member names - nil for the top-level object, ["data",
// "data"] for a HashiCorp Vault KV version 2 read, {"data":{"data":{"password":"..."}}}. A path
// that leads to no object holds nothing. body is the caller's to zero.
//
// It fails with ErrInvalidSecretData when body isn't exactly one JSON object, or the object holds a
// key more than once or a value that isn't UTF-8 text; and as the protector does.
func (s *Secret) ProtectBodyKeys(ctx context.Context, body []byte, objectPath []string) error {
	if !secretjson.IsObject(body) {
		// Never quoting where it failed: that byte may be in the secret.
		return invalidData("the response body isn't a JSON object")
	}
	i := secretjson.SkipSpace(body, 0)
	for _, name := range objectPath {
		next := -1
		secretjson.Members(body, i, func(m secretjson.Member) bool {
			if m.NameIs(name) && secretjson.KindAt(body, m.Start) == secretjson.Object {
				next = m.Start
				return false
			}
			return true
		})
		if next < 0 {
			return nil
		}
		i = next
	}
	return s.protectObject(ctx, body, i)
}

// ProtectBodyValue encrypts, as ProtectSecret does, the string value of textProperty in a response
// body's top-level object - Secrets Manager's {"SecretString":"..."}, Key Vault's {"value":"..."} -
// unescaped into a buffer that is zeroed once encrypted. A missing, empty or non-string value holds
// nothing. When binaryProperty isn't "", a non-empty string value under it - Secrets Manager's
// SecretBinary - is refused: the protector encrypts text. body is the caller's to zero.
//
// It fails with ErrInvalidSecretData when body isn't exactly one JSON object, holds textProperty's
// value more than once, holds a value under binaryProperty, or the value isn't UTF-8 text or is a
// JSON object holding a key more than once; and as the protector does.
func (s *Secret) ProtectBodyValue(ctx context.Context, body []byte, textProperty, binaryProperty string) error {
	if !secretjson.IsObject(body) {
		return invalidData("the response body isn't a JSON object")
	}
	var err error
	found := false
	secretjson.Members(body, secretjson.SkipSpace(body, 0), func(m secretjson.Member) bool {
		isText := m.NameIs(textProperty)
		isBinary := !isText && binaryProperty != "" && m.NameIs(binaryProperty)
		if !(isText || isBinary) || secretjson.KindAt(body, m.Start) != secretjson.String || m.End-m.Start <= 2 {
			return true
		}
		switch {
		case isBinary:
			err = invalidData("a binary secret value can't be protected: the pipeline protector encrypts text")
		case found:
			err = invalidData("the response body holds more than one secret value")
		default:
			found = true
			err = protectString(secretjson.StringContent(body, m.Start, m.End), func(text []byte) error {
				return s.ProtectSecret(ctx, text)
			})
		}
		return err == nil
	})
	return err
}

// protectObject encrypts the value of each requested key of the object starting at data[i], a
// document secretjson.Valid accepted.
func (s *Secret) protectObject(ctx context.Context, data []byte, i int) error {
	var err error
	seen := map[string]struct{}{}
	secretjson.Members(data, i, func(m secretjson.Member) bool {
		key := m.Name()
		// Not named: a key is part of a secret name, which is never logged.
		if _, dup := seen[key]; dup {
			err = invalidData("the secret holds a key more than once")
			return false
		}
		seen[key] = struct{}{}
		request := s.find(key)
		if request == nil {
			return true
		}
		switch secretjson.KindAt(data, m.Start) {
		case secretjson.String:
			err = protectString(secretjson.StringContent(data, m.Start, m.End), func(text []byte) error {
				return s.protectValue(ctx, text, request.FileName)
			})
		case secretjson.Number, secretjson.True, secretjson.False:
			// Its JSON text, copied so the buffer encrypted from is one zeroed here.
			text := append([]byte(nil), data[m.Start:m.End]...)
			err = s.protectValue(ctx, text, request.FileName)
			hkdfguard.Wipe(text)
		}
		return err == nil
	})
	return err
}

// protectString unescapes a string's raw content into a buffer of its own, hands it to protect, and
// zeroes it.
func protectString(raw []byte, protect func([]byte) error) error {
	// Unescaped, a string is never longer than it is escaped.
	text := make([]byte, len(raw))
	defer hkdfguard.Wipe(text)
	return protect(text[:secretjson.Unescape(text, raw)])
}

// protectValue encrypts a key's value, unless it is empty.
func (s *Secret) protectValue(ctx context.Context, value []byte, fileName string) error {
	if len(value) == 0 {
		return nil
	}
	return s.protect(ctx, value, fileName)
}

// protect encrypts plaintext bound to fileName and keeps it.
func (s *Secret) protect(ctx context.Context, plaintext []byte, fileName string) error {
	// The protector encrypts text: a value that isn't would be written as something else.
	if !utf8.Valid(plaintext) {
		return invalidData("the secret isn't UTF-8 text: the pipeline protector encrypts text")
	}
	if _, set := s.values[fileName]; set {
		// Not named: the file name holds a key, part of a secret name, which is never logged.
		return invalidData("the secret holds more than one value for one secret name")
	}
	encrypted, err := s.protector.Encrypt(ctx, plaintext, fileName)
	if err != nil {
		return err
	}
	s.values[fileName] = encrypted
	return nil
}

// find is the request for key, if any.
func (s *Secret) find(key string) *SecretRequest {
	for i := range s.requests {
		if s.requests[i].Key != "" && s.requests[i].Key == key {
			return &s.requests[i]
		}
	}
	return nil
}
