package configurationresolver

import (
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

// itemKey is an item's key: its UTF-8 text, each ill-formed sequence replaced with U+FFFD as .NET
// decodes it, trimmed of the whitespace .NET's string.Trim removes. unicode.IsSpace and .NET's
// char.IsWhiteSpace are the same set: U+0009-U+000D, U+0020, U+0085, U+00A0 and the Zs, Zl and Zp
// characters.
func itemKey(item []byte) string {
	return strings.TrimFunc(decodeUTF8(item), unicode.IsSpace)
}

// decodeUTF8 returns text as a string, replacing each maximal ill-formed subsequence with one
// U+FFFD - the Unicode-recommended practice .NET's UTF-8 decoder follows. (Go's own conversions
// replace each invalid byte, or each run of them, instead.)
func decodeUTF8(text []byte) string {
	if utf8.Valid(text) {
		return string(text)
	}
	var b strings.Builder
	b.Grow(len(text) + 8)
	for len(text) > 0 {
		r, size := utf8.DecodeRune(text)
		if r != utf8.RuneError || size > 1 {
			b.WriteRune(r)
			text = text[size:]
			continue
		}
		b.WriteRune(utf8.RuneError)
		text = text[maximalSubpart(text):]
	}
	return b.String()
}

// maximalSubpart is the length of the ill-formed sequence text starts with: its lead byte and the
// continuation bytes after it that could still have begun a well-formed sequence - at least 1.
func maximalSubpart(text []byte) int {
	lead := text[0]
	var need int
	lo, hi := byte(0x80), byte(0xBF) // the range of the byte after the lead
	switch {
	case lead >= 0xC2 && lead <= 0xDF:
		need = 1
	case lead == 0xE0:
		need, lo = 2, 0xA0
	case lead == 0xED:
		need, hi = 2, 0x9F
	case lead >= 0xE1 && lead <= 0xEF:
		need = 2
	case lead == 0xF0:
		need, lo = 3, 0x90
	case lead == 0xF4:
		need, hi = 3, 0x8F
	case lead >= 0xF1 && lead <= 0xF3:
		need = 3
	default:
		return 1
	}
	n := 1
	for i := 0; i < need && n < len(text); i++ {
		c := text[n]
		if i > 0 {
			lo, hi = 0x80, 0xBF
		}
		if c < lo || c > hi {
			break
		}
		n++
	}
	return n
}

// decodeText converts text read from a stream to UTF-8, as a .NET StreamReader that defaults to
// UTF-8 and detects byte order marks does: a UTF-8, UTF-16 (LE or BE) or UTF-32 (LE or BE) BOM
// selects that encoding and is dropped; without one the text is UTF-8. The result is text itself
// when no conversion is needed, or a new slice; the caller wipes both.
func decodeText(text []byte) []byte {
	switch {
	case hasPrefix(text, 0xEF, 0xBB, 0xBF):
		return text[3:]
	case hasPrefix(text, 0xFF, 0xFE, 0x00, 0x00):
		return decodeUTF32(text[4:], false)
	case hasPrefix(text, 0x00, 0x00, 0xFE, 0xFF):
		return decodeUTF32(text[4:], true)
	case hasPrefix(text, 0xFF, 0xFE):
		return decodeUTF16(text[2:], false)
	case hasPrefix(text, 0xFE, 0xFF):
		return decodeUTF16(text[2:], true)
	default:
		return text
	}
}

func hasPrefix(text []byte, prefix ...byte) bool {
	if len(text) < len(prefix) {
		return false
	}
	for i, b := range prefix {
		if text[i] != b {
			return false
		}
	}
	return true
}

// decodeUTF16 converts UTF-16 to UTF-8, an unpaired surrogate or a trailing odd byte becoming
// U+FFFD.
func decodeUTF16(text []byte, bigEndian bool) []byte {
	units := make([]uint16, len(text)/2)
	defer clear(units)
	for i := range units {
		if bigEndian {
			units[i] = uint16(text[2*i])<<8 | uint16(text[2*i+1])
		} else {
			units[i] = uint16(text[2*i+1])<<8 | uint16(text[2*i])
		}
	}
	runes := utf16.Decode(units)
	defer wipeRunes(runes)
	return encodeRunes(runes, len(text)%2 != 0)
}

// decodeUTF32 converts UTF-32 to UTF-8, a value that isn't a scalar value, or trailing bytes,
// becoming U+FFFD.
func decodeUTF32(text []byte, bigEndian bool) []byte {
	runes := make([]rune, 0, len(text)/4)
	defer func() { wipeRunes(runes) }()
	for i := 0; i+4 <= len(text); i += 4 {
		var v uint32
		if bigEndian {
			v = uint32(text[i])<<24 | uint32(text[i+1])<<16 | uint32(text[i+2])<<8 | uint32(text[i+3])
		} else {
			v = uint32(text[i+3])<<24 | uint32(text[i+2])<<16 | uint32(text[i+1])<<8 | uint32(text[i])
		}
		r := rune(v)
		if v > unicode.MaxRune || !utf8.ValidRune(r) {
			r = utf8.RuneError
		}
		runes = append(runes, r)
	}
	return encodeRunes(runes, len(text)%4 != 0)
}

// encodeRunes returns runes as UTF-8, followed by U+FFFD when truncated is set, in one exactly
// sized allocation, so no copy is left behind unwiped.
func encodeRunes(runes []rune, truncated bool) []byte {
	n := 0
	for _, r := range runes {
		n += utf8.RuneLen(r)
	}
	if truncated {
		n += utf8.RuneLen(utf8.RuneError)
	}
	out := make([]byte, 0, n)
	for _, r := range runes {
		out = utf8.AppendRune(out, r)
	}
	if truncated {
		out = utf8.AppendRune(out, utf8.RuneError)
	}
	return out
}

func wipeRunes(runes []rune) {
	clear(runes[:cap(runes)])
}
