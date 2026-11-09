package configurationresolver

import (
	"bytes"
	"errors"
	"io"
	"sync/atomic"

	"github.com/runsecure/hkdfguard-go"
)

// KeyReader is what a resolver needs from a reader: the keys it may resolve. It is the Keys
// member of .NET's IConfigurationItemReader; *ConfigurationItemReader implements it.
type KeyReader interface {
	// Keys returns the keys of the most recent read.
	Keys() []string
}

// ConfigurationItemReader reads text and extracts the keys of the configuration items delimited
// by a token's start and end sequences: the port of ConfigurationItemReader.
//
// Keys are trimmed of surrounding whitespace, and empty keys are skipped. A start sequence with no
// matching end sequence is ignored, and so is a start sequence preceded by the token's escape
// sequence. Each read replaces the keys Keys returns. Safe for concurrent use.
type ConfigurationItemReader struct {
	token *ConfigurationItemToken
	keys  atomic.Pointer[[]string]
}

var _ KeyReader = (*ConfigurationItemReader)(nil)

// NewConfigurationItemReader returns a reader for token's items. It fails when token is nil.
func NewConfigurationItemReader(token *ConfigurationItemToken) (*ConfigurationItemReader, error) {
	if token == nil {
		return nil, errors.New("configurationresolver: a token is required")
	}
	return &ConfigurationItemReader{token: token}, nil
}

// Keys returns the keys extracted by the most recent read, or none if nothing has been read.
func (r *ConfigurationItemReader) Keys() []string {
	keys := r.keys.Load()
	if keys == nil {
		return []string{}
	}
	return append([]string(nil), (*keys)...)
}

// ReadKeys extracts the keys of the configuration items in the UTF-8 text, in the order they
// appear.
func (r *ConfigurationItemReader) ReadKeys(utf8Text []byte) []string {
	return r.store(r.addKeys(utf8Text, nil))
}

// ReadKeysString extracts the keys of the configuration items in text, in the order they appear.
func (r *ConfigurationItemReader) ReadKeysString(text string) []string {
	return r.ReadKeys([]byte(text))
}

// ReadKeysAll extracts the keys of the configuration items in each of several texts, such as the
// values of a configuration, and keeps the keys from all of them: in the order they appear, text
// by text. Each text is read on its own, so an item can't start in one text and end in the next.
func (r *ConfigurationItemReader) ReadKeysAll(texts []string) []string {
	var keys []string
	for _, text := range texts {
		keys = r.addKeys([]byte(text), keys)
	}
	return r.store(keys)
}

// ReadKeysFrom reads source to its end as text and extracts the keys of the configuration items
// it contains. The text is UTF-8 unless it starts with a byte order mark, which selects UTF-8,
// UTF-16 or UTF-32. What was read is wiped once its keys are extracted; source is not closed.
func (r *ConfigurationItemReader) ReadKeysFrom(source io.Reader) ([]string, error) {
	if source == nil {
		return nil, errors.New("configurationresolver: a reader to read from is required")
	}
	data, err := readAllWiping(source)
	defer hkdfguard.Wipe(data[:cap(data)])
	if err != nil {
		return nil, err
	}
	text := decodeText(data)
	defer hkdfguard.Wipe(text)
	return r.ReadKeys(text), nil
}

// readAllWiping reads source to its end into a buffer of its own, grown by copying and zeroing
// the smaller one - never through io.ReadAll or a bytes.Buffer, whose discarded arrays would keep
// the text, secrets and all. The caller wipes the result to its capacity, even on failure.
func readAllWiping(source io.Reader) ([]byte, error) {
	buffer := make([]byte, 0, 4096)
	for {
		read, err := source.Read(buffer[len(buffer):cap(buffer)])
		buffer = buffer[:len(buffer)+read]
		if err == io.EOF {
			return buffer, nil
		}
		if err != nil {
			return buffer, err
		}
		if len(buffer) == cap(buffer) {
			larger := make([]byte, len(buffer), 2*cap(buffer))
			copy(larger, buffer)
			hkdfguard.Wipe(buffer)
			buffer = larger
		}
	}
}

func (r *ConfigurationItemReader) store(keys []string) []string {
	if keys == nil {
		keys = []string{}
	}
	stored := append([]string(nil), keys...)
	r.keys.Store(&stored)
	return keys
}

func (r *ConfigurationItemReader) addKeys(text []byte, keys []string) []string {
	start := []byte(r.token.start)
	end := []byte(r.token.end)
	escape := []byte(r.token.escape)

	for {
		startIndex := bytes.Index(text, start)
		if startIndex < 0 {
			return keys
		}

		escaped := len(escape) > 0 && bytes.HasSuffix(text[:startIndex], escape)
		text = text[startIndex+len(start):]
		if escaped {
			continue
		}

		endIndex := bytes.Index(text, end)
		if endIndex < 0 {
			return keys
		}

		if key := itemKey(text[:endIndex]); key != "" {
			keys = append(keys, key)
		}
		text = text[endIndex+len(end):]
	}
}
