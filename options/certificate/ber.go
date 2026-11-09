package certificate

import (
	"errors"

	"github.com/runsecure/hkdfguard-go"
)

// PKCS#12 files are BER, not always DER: some tools (NSS, Java's older keytool) write indefinite
// lengths and constructed OCTET STRINGs, which encoding/asn1 refuses. berToDER rewrites both into
// their definite, primitive DER forms and leaves everything else as it is, so a DER file comes
// back unchanged.
//
// What it converts may be decrypted contents holding a key, so every buffer it makes along the
// way - each converted child, each buffer outgrown, each content once it is encoded - is zeroed
// before it is dropped, on failure too. Only the result is left, for the caller to wipe; the input
// is the caller's, and is never written.

const maxBERDepth = 32

var errBadBER = errors.New("malformed BER")

// berToDER returns ber's DER form, in a new buffer the caller wipes.
func berToDER(ber []byte) ([]byte, error) {
	out, rest, err := convertBER(ber, 0)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errBadBER
	}
	return out, nil
}

// convertBER converts the one element at the start of in, returning its DER and what follows it.
func convertBER(in []byte, depth int) ([]byte, []byte, error) {
	if depth > maxBERDepth {
		return nil, nil, errBadBER
	}
	if len(in) < 2 {
		return nil, nil, errBadBER
	}
	// The identifier: one byte, or a high tag number in several.
	idLen := 1
	if in[0]&0x1f == 0x1f {
		for idLen < len(in) && in[idLen]&0x80 != 0 {
			idLen++
		}
		idLen++
		if idLen >= len(in) {
			return nil, nil, errBadBER
		}
	}
	identifier := in[:idLen]
	constructed := in[0]&0x20 != 0
	rest := in[idLen:]

	// content is owned when it is a buffer made here, not a window onto in.
	var content []byte
	owned := false
	if rest[0] == 0x80 { // indefinite length: children up to an end-of-contents 00 00
		if !constructed {
			return nil, nil, errBadBER
		}
		rest = rest[1:]
		var children []byte
		for {
			if len(rest) < 2 {
				hkdfguard.Wipe(children)
				return nil, nil, errBadBER
			}
			if rest[0] == 0 && rest[1] == 0 {
				rest = rest[2:]
				break
			}
			child, after, err := convertBER(rest, depth+1)
			if err != nil {
				hkdfguard.Wipe(children)
				return nil, nil, err
			}
			children = appendWiping(children, child)
			hkdfguard.Wipe(child)
			rest = after
		}
		content, owned = children, true
	} else {
		length, lengthLen, err := berLength(rest)
		if err != nil {
			return nil, nil, err
		}
		rest = rest[lengthLen:]
		if length > len(rest) {
			return nil, nil, errBadBER
		}
		body := rest[:length]
		rest = rest[length:]
		if constructed {
			var children []byte
			for len(body) > 0 {
				child, after, err := convertBER(body, depth+1)
				if err != nil {
					hkdfguard.Wipe(children)
					return nil, nil, err
				}
				children = appendWiping(children, child)
				hkdfguard.Wipe(child)
				body = after
			}
			content, owned = children, true
		} else {
			content = body
		}
	}

	if owned {
		defer hkdfguard.Wipe(content)
	}
	// A constructed OCTET STRING becomes the primitive one its segments make.
	if identifier[0] == 0x24 && idLen == 1 {
		flat, err := concatenateOctetStrings(content)
		if err != nil {
			return nil, nil, err
		}
		defer hkdfguard.Wipe(flat)
		return encodeTLV([]byte{0x04}, flat), rest, nil
	}
	return encodeTLV(identifier, content), rest, nil
}

// appendWiping appends src to dst as append does, except that when dst must grow, the array it
// outgrows is zeroed rather than left holding a copy.
func appendWiping(dst, src []byte) []byte {
	if len(dst)+len(src) <= cap(dst) {
		return append(dst, src...)
	}
	grown := make([]byte, len(dst), max(2*cap(dst), len(dst)+len(src)))
	copy(grown, dst)
	hkdfguard.Wipe(dst[:cap(dst)])
	return append(grown, src...)
}

// berLength parses a definite length, returning it and how many bytes it took.
func berLength(in []byte) (int, int, error) {
	if in[0]&0x80 == 0 {
		return int(in[0]), 1, nil
	}
	n := int(in[0] & 0x7f)
	if n == 0 || n > 4 || len(in) < 1+n {
		return 0, 0, errBadBER
	}
	length := 0
	for _, b := range in[1 : 1+n] {
		length = length<<8 | int(b)
	}
	if length < 0 {
		return 0, 0, errBadBER
	}
	return length, 1 + n, nil
}

// concatenateOctetStrings joins the contents of a run of DER OCTET STRINGs into a new buffer,
// zeroing any it outgrows, and on failure what it had joined.
func concatenateOctetStrings(der []byte) ([]byte, error) {
	var out []byte
	for len(der) > 0 {
		if der[0] != 0x04 || len(der) < 2 {
			hkdfguard.Wipe(out)
			return nil, errBadBER
		}
		length, lengthLen, err := berLength(der[1:])
		if err != nil || 1+lengthLen+length > len(der) {
			hkdfguard.Wipe(out)
			return nil, errBadBER
		}
		out = appendWiping(out, der[1+lengthLen:1+lengthLen+length])
		der = der[1+lengthLen+length:]
	}
	return out, nil
}

// encodeTLV encodes identifier, content's DER length and content.
func encodeTLV(identifier, content []byte) []byte {
	out := make([]byte, 0, len(identifier)+5+len(content))
	out = append(out, identifier...)
	switch n := len(content); {
	case n < 0x80:
		out = append(out, byte(n))
	case n <= 0xff:
		out = append(out, 0x81, byte(n))
	case n <= 0xffff:
		out = append(out, 0x82, byte(n>>8), byte(n))
	case n <= 0xffffff:
		out = append(out, 0x83, byte(n>>16), byte(n>>8), byte(n))
	default:
		out = append(out, 0x84, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	return append(out, content...)
}
