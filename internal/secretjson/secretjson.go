// Package secretjson walks a JSON document that may hold secrets without turning any value into a
// string: a string value is located by its byte offsets and unescaped straight into a buffer the
// caller owns and zeroes. encoding/json can't do that - every string it decodes, even through
// json.Decoder.Token, is a new Go string the garbage collector may copy and that can never be
// zeroed. Member names are not secret, and are compared or returned as strings.
//
// Every walk starts from a document Valid accepted, so the walker itself never meets malformed
// JSON: it trusts the structure Valid checked and never allocates for a value.
//
// Internal to this repository: its API changes with the modules that use it.
package secretjson

import (
	"encoding/json"
	"unicode/utf16"
	"unicode/utf8"
)

// Valid reports whether data is exactly one JSON value, with only whitespace around it, and is
// valid UTF-8 throughout - as .NET's Utf8JsonReader requires; encoding/json alone would accept an
// invalid byte inside a string and decode it as U+FFFD. Both validators scan in place: they copy
// nothing out of data.
func Valid(data []byte) bool { return utf8.Valid(data) && json.Valid(data) }

// IsObject reports whether data is exactly one JSON object, with only whitespace around it.
func IsObject(data []byte) bool {
	if !Valid(data) {
		return false
	}
	i := SkipSpace(data, 0)
	return i < len(data) && data[i] == '{'
}

// Kind is the kind of the value starting at an offset.
type Kind byte

// The kinds of JSON value, by the byte each starts with.
const (
	Object Kind = '{'
	Array  Kind = '['
	String Kind = '"'
	True   Kind = 't'
	False  Kind = 'f'
	Null   Kind = 'n'
	Number Kind = '0'
)

// KindAt is the kind of the value starting at data[i] (after SkipSpace).
func KindAt(data []byte, i int) Kind {
	switch c := data[i]; c {
	case '{', '[', '"', 't', 'f', 'n':
		return Kind(c)
	default:
		return Number
	}
}

// SkipSpace returns the offset of the first byte at or after i that isn't JSON whitespace.
func SkipSpace(data []byte, i int) int {
	for i < len(data) {
		switch data[i] {
		case ' ', '\t', '\n', '\r':
			i++
		default:
			return i
		}
	}
	return i
}

// Member is one member of an object: its name's raw (still escaped) bytes, between the quotes, and
// the offsets of its value - Start at its first byte, End just past its last.
type Member struct {
	RawName    []byte
	Start, End int
}

// NameIs reports whether the member's name, unescaped, is name.
func (m Member) NameIs(name string) bool {
	if !hasEscape(m.RawName) {
		return string(m.RawName) == name
	}
	return m.Name() == name
}

// Name is the member's name, unescaped.
func (m Member) Name() string {
	if !hasEscape(m.RawName) {
		return string(m.RawName)
	}
	buf := make([]byte, len(m.RawName))
	return string(buf[:Unescape(buf, m.RawName)])
}

// Members calls visit for each member of the object starting at data[i], in order, and returns the
// offset just past the object. visit returning false stops the walk early (the offset returned is
// then meaningless).
func Members(data []byte, i int, visit func(Member) bool) int {
	i = SkipSpace(data, i+1) // past '{'
	if data[i] == '}' {
		return i + 1
	}
	for {
		nameEnd := StringEnd(data, i)
		rawName := data[i+1 : nameEnd-1]
		i = SkipSpace(data, nameEnd)
		i = SkipSpace(data, i+1) // past ':'
		end := ValueEnd(data, i)
		if !visit(Member{RawName: rawName, Start: i, End: end}) {
			return end
		}
		i = SkipSpace(data, end)
		if data[i] == '}' {
			return i + 1
		}
		i = SkipSpace(data, i+1) // past ','
	}
}

// Elements calls visit with the offsets of each element of the array starting at data[i], and
// returns the offset just past the array.
func Elements(data []byte, i int, visit func(start, end int)) int {
	i = SkipSpace(data, i+1) // past '['
	if data[i] == ']' {
		return i + 1
	}
	for {
		end := ValueEnd(data, i)
		visit(i, end)
		i = SkipSpace(data, end)
		if data[i] == ']' {
			return i + 1
		}
		i = SkipSpace(data, i+1) // past ','
	}
}

// ValueEnd returns the offset just past the value starting at data[i].
func ValueEnd(data []byte, i int) int {
	switch KindAt(data, i) {
	case String:
		return StringEnd(data, i)
	case Object, Array:
		depth := 0
		for ; ; i++ {
			switch data[i] {
			case '"':
				i = StringEnd(data, i) - 1
			case '{', '[':
				depth++
			case '}', ']':
				depth--
				if depth == 0 {
					return i + 1
				}
			}
		}
	default: // a number, true, false or null: up to the next delimiter
		for i < len(data) {
			switch data[i] {
			case ',', '}', ']', ' ', '\t', '\n', '\r':
				return i
			}
			i++
		}
		return i
	}
}

// StringEnd returns the offset just past the closing quote of the string starting at data[i].
func StringEnd(data []byte, i int) int {
	for i++; ; i++ {
		switch data[i] {
		case '\\':
			i++
		case '"':
			return i + 1
		}
	}
}

// StringContent is the raw (still escaped) content of the string value at [start, end): its bytes
// between the quotes.
func StringContent(data []byte, start, end int) []byte { return data[start+1 : end-1] }

func hasEscape(raw []byte) bool {
	for _, c := range raw {
		if c == '\\' {
			return true
		}
	}
	return false
}

// Unescape writes raw - a string's content between its quotes, as Valid accepted it - unescaped
// into dst as UTF-8, and returns the length written. dst must hold len(raw) bytes: unescaped, a
// string is never longer than it is escaped. A \u escape naming a lone surrogate becomes U+FFFD, as
// encoding/json decodes it. Nothing else is written or allocated.
func Unescape(dst, raw []byte) int {
	n := 0
	for i := 0; i < len(raw); {
		c := raw[i]
		if c != '\\' {
			dst[n] = c
			n++
			i++
			continue
		}
		switch raw[i+1] {
		case '"', '\\', '/':
			dst[n] = raw[i+1]
		case 'b':
			dst[n] = '\b'
		case 'f':
			dst[n] = '\f'
		case 'n':
			dst[n] = '\n'
		case 'r':
			dst[n] = '\r'
		case 't':
			dst[n] = '\t'
		case 'u':
			r := hex4(raw[i+2:])
			i += 6
			if utf16.IsSurrogate(r) {
				r2 := utf8.RuneError
				if i+6 <= len(raw) && raw[i] == '\\' && raw[i+1] == 'u' {
					r2 = hex4(raw[i+2:])
				}
				if paired := utf16.DecodeRune(r, r2); paired != utf8.RuneError {
					r = paired
					i += 6
				} else {
					r = utf8.RuneError
				}
			}
			n += utf8.EncodeRune(dst[n:], r)
			continue
		}
		n++
		i += 2
	}
	return n
}

func hex4(b []byte) rune {
	var r rune
	for _, c := range b[:4] {
		r <<= 4
		switch {
		case c >= '0' && c <= '9':
			r |= rune(c - '0')
		case c >= 'a' && c <= 'f':
			r |= rune(c - 'a' + 10)
		default:
			r |= rune(c - 'A' + 10)
		}
	}
	return r
}
