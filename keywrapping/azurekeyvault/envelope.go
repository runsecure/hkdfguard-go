package azurekeyvault

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"regexp"
	"unicode/utf8"
)

// The wrapped-DEK format KeyWrapper writes and reads, byte for byte the .NET
// AzureKeyVaultKeyWrapper's, the Java AzureKeyVaultKeyWrapperImpl's, and the Python and Node
// AzureKeyVaultKeyWrapper's:
//
//	offset  length  field
//	0       4       magic "HGKV"
//	4       1       format version (1)
//	5       16      wrapping key version (Key Vault's 32 hex digits, as bytes)
//	21      2       n, the RSA-OAEP-256 ciphertext's length (big-endian)
//	23      n       the DEK, wrapped under that version of the wrapping key
//	23+n    16      signing key version
//	39+n    64      ES256 signature (r || s) by that version of the signing key
//
// Only key versions are stored: the vault and key names are the wrapper's own, so a key file can
// never point it at another key. The signature covers signedData: a domain string, the wrapper's
// context, and every byte before the signing key version.

const (
	formatVersion    = 1
	keyVersionLength = 16
	signatureLength  = 64

	// headerLength is the magic, format version, wrapping key version and ciphertext length.
	headerLength = 4 + 1 + keyVersionLength + 2

	// overhead is everything besides the RSA ciphertext.
	overhead = headerLength + keyVersionLength + signatureLength

	maxFieldLength = 0xffff
)

var (
	magic      = []byte("HGKV")
	domain     = []byte("HkdfGuard-AzureKeyVault-wrap-v1\x00")
	hexVersion = regexp.MustCompile(`^[0-9A-Fa-f]{32}$`)
)

// fail makes the error a malformed envelope or Key Vault answer fails with: the wrapper's *Error.
type fail func(format string, args ...any) error

// parts is a parsed envelope: the parts, and where the signed part ends.
type parts struct {
	wrappingKeyVersion string
	wrappedDEK         []byte
	signingKeyVersion  string
	signature          []byte
	unsignedLength     int
}

// buildUnsigned is the header and ciphertext: everything the signature covers besides the domain
// and context. It fails with the fail error when the version isn't Key Vault's form, or the
// ciphertext is empty or too long to encode.
func buildUnsigned(wrappingKeyVersion string, wrappedDEK []byte, fail fail) ([]byte, error) {
	if len(wrappedDEK) == 0 || len(wrappedDEK) > maxFieldLength {
		return nil, fail("Azure Key Vault returned a %d-byte wrapped key.", len(wrappedDEK))
	}
	version, err := versionBytes(wrappingKeyVersion, fail)
	if err != nil {
		return nil, err
	}
	unsigned := make([]byte, 0, headerLength+len(wrappedDEK))
	unsigned = append(unsigned, magic...)
	unsigned = append(unsigned, formatVersion)
	unsigned = append(unsigned, version...)
	unsigned = binary.BigEndian.AppendUint16(unsigned, uint16(len(wrappedDEK)))
	return append(unsigned, wrappedDEK...), nil
}

// signedData is what the signing key signs: the domain, the length-prefixed context, then unsigned.
func signedData(unsigned, context []byte) []byte {
	data := make([]byte, 0, len(domain)+2+len(context)+len(unsigned))
	data = append(data, domain...)
	data = binary.BigEndian.AppendUint16(data, uint16(len(context)))
	data = append(data, context...)
	return append(data, unsigned...)
}

// write writes the complete envelope into result, returning the number of bytes written. It fails
// with ErrInvalidArgument when result is too small, and with the fail error when the version or
// signature isn't the expected form; either way result is left as it was.
func write(unsigned []byte, signingKeyVersion string, signature, result []byte, fail fail) (int, error) {
	if len(signature) != signatureLength {
		return 0, fail("Azure Key Vault returned a %d-byte signature; an ES256 signature is %d. The signing key must be an EC P-256 key.",
			len(signature), signatureLength)
	}
	version, err := versionBytes(signingKeyVersion, fail)
	if err != nil {
		return 0, err
	}
	length := len(unsigned) + keyVersionLength + signatureLength
	if length > len(result) {
		return 0, invalidArgument("The wrapped DEK is %d bytes; result holds %d.", length, len(result))
	}
	copy(result, unsigned)
	copy(result[len(unsigned):], version)
	copy(result[len(unsigned)+keyVersionLength:], signature)
	return length, nil
}

// parse splits an envelope into its parts, refusing anything that isn't exactly one. The parts are
// copies.
func parse(envelope []byte, fail fail) (parts, error) {
	if len(envelope) < overhead+1 || !bytes.Equal(envelope[:len(magic)], magic) {
		return parts{}, fail("This is not a wrapped DEK written by AzureKeyVaultKeyWrapper.")
	}
	if envelope[4] != formatVersion {
		return parts{}, fail("This wrapped DEK is format version %d; only version %d is supported.", envelope[4], formatVersion)
	}
	wrappedLength := int(binary.BigEndian.Uint16(envelope[21:]))
	if wrappedLength == 0 || len(envelope) != overhead+wrappedLength {
		return parts{}, fail("This wrapped DEK is %d bytes, but its header describes %d.", len(envelope), overhead+wrappedLength)
	}
	unsignedLength := headerLength + wrappedLength
	return parts{
		wrappingKeyVersion: hex.EncodeToString(envelope[5 : 5+keyVersionLength]),
		wrappedDEK:         bytes.Clone(envelope[headerLength:unsignedLength]),
		signingKeyVersion:  hex.EncodeToString(envelope[unsignedLength : unsignedLength+keyVersionLength]),
		signature:          bytes.Clone(envelope[unsignedLength+keyVersionLength:]),
		unsignedLength:     unsignedLength,
	}, nil
}

// encodeContext is the UTF-8 bytes of a context, refusing one too long to length-prefix, or one that
// isn't valid UTF-8, which the other ports could not have been given. "" is no context.
func encodeContext(context string) ([]byte, error) {
	if !utf8.ValidString(context) {
		return nil, invalidArgument("The context isn't valid UTF-8.")
	}
	if len(context) > maxFieldLength {
		return nil, invalidArgument("The context is %d bytes in UTF-8; at most %d are allowed.", len(context), maxFieldLength)
	}
	return []byte(context), nil
}

// versionBytes is a Key Vault key version - 32 hex digits - as the 16 bytes they spell.
func versionBytes(version string, fail fail) ([]byte, error) {
	if !hexVersion.MatchString(version) {
		return nil, fail("Azure Key Vault returned key version %q, not 32 hex digits.", version)
	}
	decoded, _ := hex.DecodeString(version)
	return decoded, nil
}
