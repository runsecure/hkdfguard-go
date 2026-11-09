package configurationresolver

import (
	"bytes"
	"context"
	"errors"
	"io"
	"slices"
	"testing"
	"unicode/utf16"
)

// The port of .NET's ReaderAndTokenScenarioTests, with tests of what .NET's decoding gives a key:
// a byte order mark selecting a stream's encoding, invalid UTF-8 replaced per maximal subpart, and
// trimming of Unicode whitespace.

const readerTestText = "this is my ${ value 1 }, and this is ${value2} and lastly this is ${value3}"

func mustDefaultTokenReader(t testing.TB) *ConfigurationItemReader {
	t.Helper()
	reader, err := NewConfigurationItemReader(NewDefaultToken())
	if err != nil {
		t.Fatal(err)
	}
	return reader
}

func mustCustomTokenReader(t testing.TB, start, end, escape string) *ConfigurationItemReader {
	t.Helper()
	reader, err := NewConfigurationItemReader(mustCustomToken(t, start, end, escape))
	if err != nil {
		t.Fatal(err)
	}
	return reader
}

func requireKeys(t testing.TB, got []string, want ...string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Errorf("keys = %q, want %q", got, want)
	}
}

func TestReadKeys_FromStringBytesAndStream_ReturnTheSameKeys(t *testing.T) {
	reader := mustDefaultTokenReader(t)
	expected := []string{"value 1", "value2", "value3"}

	requireKeys(t, reader.ReadKeysString(readerTestText), expected...)
	requireKeys(t, reader.ReadKeys([]byte(readerTestText)), expected...)
	keys, err := reader.ReadKeysFrom(bytes.NewReader([]byte(readerTestText)))
	if err != nil {
		t.Fatal(err)
	}
	requireKeys(t, keys, expected...)
}

func TestReadKeys_StreamIsReadFromItsPosition(t *testing.T) {
	reader := mustDefaultTokenReader(t)
	stream := bytes.NewReader([]byte("${skipped} ${read}"))
	if _, err := stream.Seek(int64(len("${skipped} ")), io.SeekStart); err != nil {
		t.Fatal(err)
	}

	keys, err := reader.ReadKeysFrom(stream)

	if err != nil {
		t.Fatal(err)
	}
	requireKeys(t, keys, "read")
	if stream.Len() != 0 {
		t.Errorf("%d bytes left unread, want the stream read to its end", stream.Len())
	}
}

// failingReader returns its data and then err.
type failingReader struct {
	data []byte
	err  error
}

func (f *failingReader) Read(p []byte) (int, error) {
	if len(f.data) == 0 {
		return 0, f.err
	}
	n := copy(p, f.data)
	f.data = f.data[n:]
	return n, nil
}

func TestReadKeysFrom_StreamError_IsReturned(t *testing.T) {
	reader := mustDefaultTokenReader(t)
	streamErr := io.ErrUnexpectedEOF

	keys, err := reader.ReadKeysFrom(&failingReader{data: []byte("${a}"), err: streamErr})

	if err != streamErr || keys != nil {
		t.Errorf("ReadKeysFrom = %q, %v; want nil, the stream's error", keys, err)
	}
}

func TestReadKeysFrom_ByteOrderMark_SelectsTheEncoding(t *testing.T) {
	// .NET's StreamReader defaults to UTF-8 and lets a byte order mark select the encoding.
	const text = "${ café 😀 }"
	const key = "café 😀"

	utf16Units := utf16.Encode([]rune(text))
	encode16 := func(bigEndian bool) []byte {
		var b []byte
		for _, u := range utf16Units {
			if bigEndian {
				b = append(b, byte(u>>8), byte(u))
			} else {
				b = append(b, byte(u), byte(u>>8))
			}
		}
		return b
	}
	encode32 := func(bigEndian bool) []byte {
		var b []byte
		for _, r := range text {
			if bigEndian {
				b = append(b, byte(r>>24), byte(r>>16), byte(r>>8), byte(r))
			} else {
				b = append(b, byte(r), byte(r>>8), byte(r>>16), byte(r>>24))
			}
		}
		return b
	}

	tests := map[string][]byte{
		"no BOM":    []byte(text),
		"UTF-8":     append([]byte{0xEF, 0xBB, 0xBF}, text...),
		"UTF-16LE":  append([]byte{0xFF, 0xFE}, encode16(false)...),
		"UTF-16BE":  append([]byte{0xFE, 0xFF}, encode16(true)...),
		"UTF-32LE":  append([]byte{0xFF, 0xFE, 0x00, 0x00}, encode32(false)...),
		"UTF-32BE":  append([]byte{0x00, 0x00, 0xFE, 0xFF}, encode32(true)...),
		"only BOM":  {0xEF, 0xBB, 0xBF},
		"empty":     {},
		"latin1 é":  []byte("${ caf\xe9 }"), // not UTF-8 and no BOM: read as UTF-8, so U+FFFD
		"short BOM": {0xEF, 0xBB},
	}
	want := map[string][]string{
		"only BOM":  {},
		"empty":     {},
		"latin1 é":  {"caf\uFFFD"},
		"short BOM": {},
	}

	for name, encoded := range tests {
		t.Run(name, func(t *testing.T) {
			reader := mustDefaultTokenReader(t)

			keys, err := reader.ReadKeysFrom(bytes.NewReader(encoded))

			if err != nil {
				t.Fatal(err)
			}
			expected, ok := want[name]
			if !ok {
				expected = []string{key}
			}
			requireKeys(t, keys, expected...)
		})
	}
}

func TestReadKeys_InvalidUTF8_IsReplacedPerMaximalSubpart(t *testing.T) {
	// As .NET's UTF-8 decoder does: each maximal ill-formed subsequence becomes one U+FFFD.
	tests := []struct{ text, key string }{
		{"${a\xffb}", "a\uFFFDb"},
		{"${a\xe0\x80b}", "a\uFFFD\uFFFDb"},       // E0 must be followed by A0-BF
		{"${a\xf0\x9f\x98b}", "a\uFFFDb"},         // a truncated four-byte sequence
		{"${\xed\xa0\x80}", "\uFFFD\uFFFD\uFFFD"}, // an encoded surrogate
		{"${a\xc0\xafb}", "a\uFFFD\uFFFDb"},       // an overlong encoding
		{"${a\xe2\x82}", "a\uFFFD"},               // truncated at the end of the item
	}
	for _, tc := range tests {
		reader := mustDefaultTokenReader(t)

		requireKeys(t, reader.ReadKeys([]byte(tc.text)), tc.key)
	}
}

func TestResolve_InvalidUTF8Key_IsTheReadersKey(t *testing.T) {
	resolver := newReadingResolver(t, NewDefaultToken(), newMapValueProvider(map[string]string{"a\uFFFDb": "value"}))

	if got := mustResolveToString(t, resolver, "[${ a\xffb }]"); got != "[value]" {
		t.Errorf("Resolve = %q, want [value]", got)
	}
}

func TestReadKeys_TrimsUnicodeWhitespace(t *testing.T) {
	// .NET's string.Trim removes what char.IsWhiteSpace reports, as unicode.IsSpace does.
	tests := []struct {
		text string
		keys []string
	}{
		{"${\u00a0Name\u3000}", []string{"Name"}},
		{"${\u0085\u2028Name\u2029\v\f\r}", []string{"Name"}},
		{"${\u200bName}", []string{"\u200bName"}}, // ZERO WIDTH SPACE is not whitespace
		{"${\u00a0\u2003}", []string{}},
	}
	for _, tc := range tests {
		reader := mustDefaultTokenReader(t)

		requireKeys(t, reader.ReadKeysString(tc.text), tc.keys...)
	}
}

func TestReadKeys_SkipsEmptyUnterminatedAndEscapedItems(t *testing.T) {
	tests := []struct {
		text     string
		expected []string
	}{
		{"", []string{}},
		{"no items", []string{}},
		{"${} ${ } ${a}", []string{"a"}},
		{"${a} ${unterminated", []string{"a"}},
		{"${a}${b}", []string{"a", "b"}},
		{"$${a} ${b} $${", []string{"b"}},
		{"$$${a} $${b ${c}}", []string{"c"}},
	}
	for _, tc := range tests {
		t.Run(tc.text, func(t *testing.T) {
			reader := mustDefaultTokenReader(t)

			requireKeys(t, reader.ReadKeysString(tc.text), tc.expected...)
		})
	}
}

func TestKeys_ReturnsTheMostRecentRead(t *testing.T) {
	reader := mustDefaultTokenReader(t)
	if keys := reader.Keys(); len(keys) != 0 {
		t.Fatalf("Keys() = %q before any read, want none", keys)
	}

	reader.ReadKeysString("${first}")
	reader.ReadKeysString("${second}")

	requireKeys(t, reader.Keys(), "second")
}

func TestReadKeys_WithCustomToken_UsesItsSequences(t *testing.T) {
	reader := mustCustomTokenReader(t, "{{", "}}", "")

	requireKeys(t, reader.ReadKeysString("{{a}} ${b}"), "a")
}

func TestReadKeys_WithCustomEscapeSequence_SkipsOnlyItsEscapedItems(t *testing.T) {
	withEscape := mustCustomTokenReader(t, "{{", "}}", `\`)
	withoutEscape := mustCustomTokenReader(t, "{{", "}}", "")

	requireKeys(t, withEscape.ReadKeysString(`\{{a}} ${{b}}`), "b")
	requireKeys(t, withoutEscape.ReadKeysString(`\{{a}} ${{b}}`), "a", "b")
}

func TestReadKeys_FromSeveralTexts_KeepsTheKeysOfAllOfThem(t *testing.T) {
	reader := mustDefaultTokenReader(t)
	reader.ReadKeysString("${old}")

	keys := reader.ReadKeysAll([]string{"${a} ${b}", "", "${c", "}${d}", "${a}"})

	requireKeys(t, keys, "a", "b", "d", "a")
	requireKeys(t, reader.Keys(), keys...)
}

func TestReader_NullArguments_Fail(t *testing.T) {
	if reader, err := NewConfigurationItemReader(nil); err == nil || reader != nil {
		t.Errorf("NewConfigurationItemReader(nil) = %v, %v; want an error", reader, err)
	}
	if keys, err := mustDefaultTokenReader(t).ReadKeysFrom(nil); err == nil || keys != nil {
		t.Errorf("ReadKeysFrom(nil) = %q, %v; want an error", keys, err)
	}
}

func TestToken_DefaultsAndOverrides(t *testing.T) {
	defaults := NewDefaultToken()
	custom := mustCustomToken(t, "<%", "%>", "")

	if defaults.StartSequence() != DefaultStartSequence || defaults.EndSequence() != DefaultEndSequence || defaults.EscapeSequence() != DefaultEscapeSequence {
		t.Errorf("default token = %q %q %q, want %q %q %q", defaults.StartSequence(), defaults.EndSequence(), defaults.EscapeSequence(),
			DefaultStartSequence, DefaultEndSequence, DefaultEscapeSequence)
	}
	if DefaultStartSequence != "${" || DefaultEndSequence != "}" || DefaultEscapeSequence != "$" {
		t.Errorf("defaults = %q %q %q, want ${ } $", DefaultStartSequence, DefaultEndSequence, DefaultEscapeSequence)
	}
	if custom.StartSequence() != "<%" || custom.EndSequence() != "%>" || custom.EscapeSequence() != "" {
		t.Errorf("custom token = %q %q %q, want <%% %%> and no escape", custom.StartSequence(), custom.EndSequence(), custom.EscapeSequence())
	}
}

func TestToken_EmptyEscapeSequence_MeansNone(t *testing.T) {
	// .NET rejects an empty escape sequence; in Go "" is how a token has none.
	token := mustCustomToken(t, "${", "}", "")
	reader, err := NewConfigurationItemReader(token)
	if err != nil {
		t.Fatal(err)
	}
	reader.ReadKeysString("$${a}")
	resolver, err := NewConfigurationItemResolver(token, reader, newMapValueProvider(map[string]string{"a": "A"}))
	if err != nil {
		t.Fatal(err)
	}

	requireKeys(t, reader.Keys(), "a")
	destination := make([]byte, 8)
	written, err := resolver.Resolve(context.Background(), []byte("$${a}"), destination)
	if err != nil || string(destination[:written]) != "$A" {
		t.Errorf("Resolve = %q, %v; want $A", destination[:written], err)
	}
}

func TestToken_NullOrEmptySequence_Fails(t *testing.T) {
	// .NET's null and empty sequences are both "" in Go.
	tests := []struct{ start, end string }{
		{"", "}"},
		{"${", ""},
		{"", ""},
	}
	for _, tc := range tests {
		if token, err := NewConfigurationItemToken(tc.start, tc.end, ""); err == nil || token != nil {
			t.Errorf("NewConfigurationItemToken(%q, %q) = %v, %v; want an error", tc.start, tc.end, token, err)
		}
	}
}

// recordingReader hands out data a chunk at a time, keeping every buffer it was given to read into.
type recordingReader struct {
	data   []byte
	chunk  int
	given  [][]byte
	failAt error
}

func (r *recordingReader) Read(p []byte) (int, error) {
	r.given = append(r.given, p)
	if len(r.data) == 0 {
		if r.failAt != nil {
			return 0, r.failAt
		}
		return 0, io.EOF
	}
	n := copy(p[:min(len(p), r.chunk)], r.data)
	r.data = r.data[n:]
	return n, nil
}

// end is the last byte of the array p is a window onto, which identifies the array.
func end(p []byte) *byte {
	full := p[:cap(p)]
	return &full[len(full)-1]
}

// Growing the buffer leaves no copy of the text behind: each array outgrown is zeroed, and only the
// one returned - which ReadKeysFrom wipes - holds it.
func TestReadAllWiping_ZeroesEveryOutgrownBuffer(t *testing.T) {
	text := bytes.Repeat([]byte("${secret-name}"), 1000) // 14,000 bytes: grown 4 KiB, 8 KiB, 16 KiB
	for _, failure := range []error{nil, errors.New("the stream broke")} {
		r := &recordingReader{data: text, chunk: 1000, failAt: failure}
		got, err := readAllWiping(r)
		if err != failure {
			t.Fatalf("err = %v, want %v", err, failure)
		}
		if !bytes.Equal(got, text) {
			t.Fatalf("read %d bytes, not the text", len(got))
		}
		outgrown := 0
		for _, p := range r.given {
			if end(p) == end(got) {
				continue
			}
			outgrown++
			if full := p[:cap(p)]; !bytes.Equal(full, make([]byte, len(full))) {
				t.Fatal("an outgrown buffer still holds text")
			}
		}
		if outgrown == 0 {
			t.Fatal("the buffer never grew")
		}
	}
}
