package cache

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/internal/secretjson"
)

// MaxJSONBodyLength is the largest response body CaptureJSONBody and CaptureJSONKeys read: far beyond
// any secret store's response, so a larger one is refused.
const MaxJSONBodyLength = 1024 * 1024

const initialBodyBuffer = 16 * 1024

// ErrInvalidSecretData reports a secret, or a response holding one, that can't be read: a body that
// isn't a JSON object or is too large, one holding more than one secret value, a base64 value that
// isn't base64, or a JSON object holding a member name more than once. The message never quotes the
// data.
var ErrInvalidSecretData = errors.New("cache: invalid secret data")

// CaptureJSONBody takes a secret out of a JSON response body before an SDK can turn it into a
// string - for a SecretStore whose client parses responses itself. It reads body to its end into a
// buffer of its own, hands the value of textProperty (as UTF-8 bytes, with
// SecretSink.SetBytesWithJSONKeys, so a JSON object's members are keys too) or base64Property (as
// the bytes it encodes, whole; "" for none) to sink, and returns the body with both values replaced
// by "" - for the SDK to parse as usual, holding nothing secret. The properties are looked for in
// the object reached through objectPath's member names - nil for the top-level object, ["data"] for
// {"data":{"value":"..."}}; a path that leads to no object hands nothing over, and so does a
// missing, null or empty property. Every buffer that held the value is zeroed before returning.
//
// It fails with ErrInvalidSecretData when body isn't a JSON object, is MaxJSONBodyLength bytes or
// more, holds more than one non-empty secret value, or a base64 value that isn't base64, or the text
// value is a JSON object holding a member name more than once; with the reader's error when body
// can't be read; and as the sink does.
func CaptureJSONBody(body io.Reader, sink *SecretSink, objectPath []string, textProperty, base64Property string) ([]byte, error) {
	if textProperty == "" {
		return nil, errors.New("cache: a text property is required")
	}
	t := &captureTarget{text: textProperty, base64: base64Property, sink: sink}
	return capture(body, objectPath, t)
}

// CaptureJSONKeys reads body to its end and hands each member of the object reached through
// objectPath's member names to sink as a key, as SecretSink.SetBytesWithJSONKeys describes - for a
// store whose secrets are sets of keys, such as HashiCorp Vault's KV: ["data", "data"] for
// {"data":{"data":{"username":"...","password":"..."}}}. A path that leads to no object hands
// nothing over. Every buffer that held a value is zeroed before returning.
//
// It fails with ErrInvalidSecretData when body isn't a JSON object or is MaxJSONBodyLength bytes or
// more, or the object holds a member name more than once; with the reader's error when body can't
// be read; and as the sink does.
func CaptureJSONKeys(body io.Reader, sink *SecretSink, objectPath []string) error {
	_, err := capture(body, objectPath, &captureTarget{sink: sink})
	return err
}

// captureTarget is what one capture looks for - a text (and base64) property, or, with no text
// property, every member as a key - and what it has found so far.
type captureTarget struct {
	text, base64 string
	sink         *SecretSink
	secrets      [][2]int // the offsets of every secret value's token, its quotes included
	keys         map[string]struct{}
	handedOver   bool
	err          error
}

func capture(body io.Reader, objectPath []string, t *captureTarget) ([]byte, error) {
	if body == nil || t.sink == nil {
		return nil, errors.New("cache: a body and a sink are required")
	}
	for _, name := range objectPath {
		if name == "" {
			return nil, errors.New("cache: a member name in the path is empty")
		}
	}
	buffer, err := readAll(body)
	defer hkdfguard.Wipe(buffer)
	if err != nil {
		return nil, err
	}
	if !secretjson.IsObject(buffer) {
		// Never quoting where it failed: that byte may be in the secret.
		return nil, fmt.Errorf("%w: the response body isn't a JSON object", ErrInvalidSecretData)
	}
	t.keys = map[string]struct{}{}
	readObject(buffer, secretjson.SkipSpace(buffer, 0), objectPath, t)
	if t.err != nil {
		return nil, t.err
	}
	if t.text == "" {
		return nil, nil
	}
	return redact(buffer, t.secrets), nil
}

// readObject reads the members of the object starting at data[i], descending objectPath.
func readObject(data []byte, i int, objectPath []string, t *captureTarget) {
	if len(objectPath) == 0 && t.text == "" {
		t.err = setKeys(data, i, t.sink, t.keys)
		return
	}
	secretjson.Members(data, i, func(m secretjson.Member) bool {
		if len(objectPath) > 0 {
			if m.NameIs(objectPath[0]) && secretjson.KindAt(data, m.Start) == secretjson.Object {
				readObject(data, m.Start, objectPath[1:], t)
			}
		} else {
			readProperty(data, m, t)
		}
		return t.err == nil
	})
}

// readProperty reads one member of the object holding the secret.
func readProperty(data []byte, m secretjson.Member, t *captureTarget) {
	isText := m.NameIs(t.text)
	isBase64 := !isText && t.base64 != "" && m.NameIs(t.base64)
	if !(isText || isBase64) || secretjson.KindAt(data, m.Start) != secretjson.String {
		return
	}
	if m.End-m.Start > 2 {
		if t.handedOver {
			t.err = fmt.Errorf("%w: the response body holds more than one secret value", ErrInvalidSecretData)
			return
		}
		if t.err = handOver(secretjson.StringContent(data, m.Start, m.End), isBase64, t.sink); t.err != nil {
			return
		}
		t.handedOver = true
	}
	t.secrets = append(t.secrets, [2]int{m.Start, m.End})
}

func handOver(raw []byte, isBase64 bool, sink *SecretSink) error {
	// Unescaped, a string is never longer than it is escaped.
	text := make([]byte, len(raw))
	defer hkdfguard.Wipe(text)
	text = text[:secretjson.Unescape(text, raw)]
	if !isBase64 {
		return sink.SetBytesWithJSONKeys(text)
	}

	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(text)))
	defer hkdfguard.Wipe(decoded)
	n, err := base64.StdEncoding.Decode(decoded, text)
	if err != nil {
		return fmt.Errorf("%w: the response body's binary secret value isn't base64", ErrInvalidSecretData)
	}
	return sink.SetBytes(decoded[:n])
}

// setJSONKeys hands each member of plaintext over as a key when it is exactly one JSON object;
// anything else - plain text that merely starts like JSON included - hands nothing over. The whole
// value is checked first, so malformed JSON never hands over part of its members.
func setJSONKeys(plaintext []byte, sink *SecretSink) error {
	if !secretjson.IsObject(plaintext) {
		return nil
	}
	return setKeys(plaintext, secretjson.SkipSpace(plaintext, 0), sink, map[string]struct{}{})
}

// setKeys hands each member of the object starting at data[i] over as a key. A string is handed
// over as its UTF-8 bytes; a number, true or false as its JSON text; null, an object, an array, an
// empty string, or a member whose name isn't a key a name can hold, isn't handed over. seen collects
// the member names, across every object handed over for one secret.
func setKeys(data []byte, i int, sink *SecretSink, seen map[string]struct{}) error {
	var err error
	secretjson.Members(data, i, func(m secretjson.Member) bool {
		key := m.Name()
		// Not named: a key is part of a lookup name, logged only with sensitive logging on.
		if _, dup := seen[key]; dup {
			err = fmt.Errorf("%w: the secret holds a key more than once", ErrInvalidSecretData)
			return false
		}
		seen[key] = struct{}{}
		if !IsValidKey(key) {
			return true
		}
		switch secretjson.KindAt(data, m.Start) {
		case secretjson.String:
			raw := secretjson.StringContent(data, m.Start, m.End)
			buffer := make([]byte, len(raw))
			err = sink.SetKeyBytes(key, buffer[:secretjson.Unescape(buffer, raw)])
			hkdfguard.Wipe(buffer)
		case secretjson.Number, secretjson.True, secretjson.False:
			buffer := append([]byte(nil), data[m.Start:m.End]...)
			err = sink.SetKeyBytes(key, buffer)
		}
		return err == nil
	})
	return err
}

// redact is the body with each secret value's token - its quotes included - replaced by "".
func redact(data []byte, secrets [][2]int) []byte {
	redacted := make([]byte, 0, len(data))
	from := 0
	for _, s := range secrets {
		redacted = append(redacted, data[from:s[0]]...)
		redacted = append(redacted, '"', '"')
		from = s[1]
	}
	return append(redacted, data[from:]...)
}

// readAll reads body to its end into a buffer of its own - grown by copying and zeroing, never
// through a bytes.Buffer or io.ReadAll, whose discarded arrays would keep the secret - which the
// caller zeroes, even on failure.
func readAll(body io.Reader) ([]byte, error) {
	buffer := make([]byte, initialBodyBuffer)
	n := 0
	for {
		read, err := body.Read(buffer[n:])
		n += read
		if err == io.EOF {
			return buffer[:n], nil
		}
		if err != nil {
			return buffer, err
		}
		if n == len(buffer) {
			if len(buffer) >= MaxJSONBodyLength {
				return buffer, fmt.Errorf("%w: the response body is %d bytes or more", ErrInvalidSecretData, MaxJSONBodyLength)
			}
			larger := make([]byte, min(2*len(buffer), MaxJSONBodyLength))
			copy(larger, buffer)
			hkdfguard.Wipe(buffer)
			buffer = larger
		}
	}
}
