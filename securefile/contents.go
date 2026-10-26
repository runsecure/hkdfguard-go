package securefile

import (
	"errors"
	"io"

	"github.com/runsecure/hkdfguard-go"
)

// PlaintextKeyLength is the length of an unwrapped DEK; a key file this size is probably a
// plaintext key.
const PlaintextKeyLength = 32

// plaintextTextScanLimit bounds the text scanned for a key written as text: a 32-byte key is at
// most 64 hex digits, and this allows surrounding whitespace.
const plaintextTextScanLimit = 96

// readContents reads at most one byte past hkdfguard.MaxWrappedKeyBytes through read - so a wrong
// path (a log, a device) can't make startup allocate an unbounded buffer - and refuses an empty
// file, one over the limit, and one that looks like an unwrapped key. Whatever is read is zeroed
// once copied out or refused.
//
// read reads into the slice it is given, returning the count; 0 (or io.EOF) at the end. An error it
// returns is passed on as it is.
func readContents(read func([]byte) (int, error), path string) ([]byte, error) {
	buffer := make([]byte, hkdfguard.MaxWrappedKeyBytes+1)
	defer hkdfguard.Wipe(buffer)

	total := 0
	for total < len(buffer) {
		count, err := read(buffer[total:])
		if count > 0 {
			total += count
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if count <= 0 {
			break
		}
	}

	if total == 0 {
		return nil, keyFileError(hkdfguard.ErrInvalidKeyFile, path, "Key file '%s' is empty.", path)
	}
	if total > hkdfguard.MaxWrappedKeyBytes {
		return nil, keyFileError(hkdfguard.ErrInvalidKeyFile, path,
			"Key file '%s' is larger than %d bytes (MaxWrappedKeyBytes); a wrapped key never is.", path, hkdfguard.MaxWrappedKeyBytes)
	}
	if looksLikePlaintextKey(buffer[:total]) {
		return nil, keyFileError(hkdfguard.ErrInvalidKeyFile, path,
			"Key file '%s' holds what looks like an unwrapped 32-byte key, not a wrapped one. "+
				"Treat that key as exposed: replace it, and write key files with the key wrapper.", path)
	}

	// Copied straight from the buffer: no intermediate copy outlives the zeroing above.
	result := make([]byte, total)
	copy(result, buffer)
	return result, nil
}

// looksLikePlaintextKey is the native library's test for a plaintext key written to disk: exactly
// 32 bytes, or a 32-byte key as 64 hex digits or as base64 (standard or URL-safe, padded or not),
// with any surrounding whitespace. It reads contents in place, making no copy of it.
func looksLikePlaintextKey(contents []byte) bool {
	if len(contents) == PlaintextKeyLength {
		return true
	}
	if len(contents) > plaintextTextScanLimit {
		return false
	}

	start, end := 0, len(contents)
	for start < end && isWhitespace(contents[start]) {
		start++
	}
	for end > start && isWhitespace(contents[end-1]) {
		end--
	}
	return isHexKey(contents[start:end]) || isBase64Key(contents[start:end])
}

// isWhitespace is what .NET trims: space, tab, LF, VT, FF and CR.
func isWhitespace(c byte) bool { return c == ' ' || (c >= 0x09 && c <= 0x0d) }

func isDigit(c byte) bool    { return c >= '0' && c <= '9' }
func isHexDigit(c byte) bool { return isDigit(c) || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f') }
func isAlphanumeric(c byte) bool {
	return isDigit(c) || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

func isHexKey(text []byte) bool {
	if len(text) != PlaintextKeyLength*2 {
		return false
	}
	for _, c := range text {
		if !isHexDigit(c) {
			return false
		}
	}
	return true
}

func isBase64Key(text []byte) bool {
	// 32 bytes: 43 characters, then one '=' when padded.
	if len(text) == 44 && text[43] == '=' {
		text = text[:43]
	}
	if len(text) != 43 {
		return false
	}

	urlSafe, standard := false, false
	for _, c := range text {
		switch {
		case isAlphanumeric(c):
		case c == '+' || c == '/':
			standard = true
		case c == '-' || c == '_':
			urlSafe = true
		default:
			return false
		}
	}
	return !(urlSafe && standard)
}
