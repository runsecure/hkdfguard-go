package dek

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/diagnostics"
	"go.opentelemetry.io/otel/trace"
)

// DefaultMaxEncryptedLength is the longest formatted value, in characters, a DefaultFormatProvider
// produces or accepts unless configured otherwise - room for about 3 KB of UTF-8 plaintext.
const DefaultMaxEncryptedLength = 4096

// ErrInvalidFormat reports a stored value that isn't in the enc::v<version>::<base64> form, or is
// over the provider's length limit.
var ErrInvalidFormat = errors.New("dek: invalid encrypted format")

const (
	encPrefix     = "enc"
	delimiter     = "::"
	versionPrefix = "v"
)

// DefaultFormatProvider is the enc::v<version>::<base64> wire format, identical across ports.
// Formatted values are capped at MaxEncryptedLength characters: Parse rejects anything longer
// before decoding it, so oversized input can't force a large allocation ahead of any
// cryptographic check, and Format refuses to produce a value Parse would then reject.
type DefaultFormatProvider struct {
	maxEncryptedLength int
}

var _ hkdfguard.EncryptedFormatProvider = (*DefaultFormatProvider)(nil)

// NewDefaultFormatProvider returns a provider limited to DefaultMaxEncryptedLength characters.
func NewDefaultFormatProvider() *DefaultFormatProvider {
	return &DefaultFormatProvider{maxEncryptedLength: DefaultMaxEncryptedLength}
}

// NewDefaultFormatProviderWithLimit returns a provider limited to maxEncryptedLength characters,
// which must be positive.
func NewDefaultFormatProviderWithLimit(maxEncryptedLength int) (*DefaultFormatProvider, error) {
	if maxEncryptedLength <= 0 {
		return nil, fmt.Errorf("dek: the maximum encrypted length must be positive, got %d", maxEncryptedLength)
	}
	return &DefaultFormatProvider{maxEncryptedLength: maxEncryptedLength}, nil
}

// MaxEncryptedLength is the longest formatted value, in characters, Format produces or Parse
// accepts.
func (f *DefaultFormatProvider) MaxEncryptedLength() int { return f.maxEncryptedLength }

// Format renders value as enc::v<version>::<base64>.
func (f *DefaultFormatProvider) Format(ctx context.Context, value hkdfguard.KeyTrackingValue) (string, error) {
	_, span := diagnostics.DataProtection.Start(ctx, diagnostics.SpanDataProtectionFormatProviderFormat)
	defer span.End()
	diagnostics.DataProtection.LogSensitiveOperation(span, diagnostics.SpanDataProtectionFormatProviderFormat,
		diagnostics.AttrKeyVersion.Int(value.KeyVersion), diagnostics.AttrValueLength.Int(len(value.Value)))

	formatted := encPrefix + delimiter + versionPrefix + strconv.Itoa(value.KeyVersion) + delimiter + base64.StdEncoding.EncodeToString(value.Value)
	if len(formatted) > f.maxEncryptedLength {
		return "", recordError(span, fmt.Errorf("%w: the formatted value would be %d characters, over the %d-character limit", ErrInvalidFormat, len(formatted), f.maxEncryptedLength))
	}
	return formatted, nil
}

// Parse reads a stored value back into the version and ciphertext it was formatted from.
func (f *DefaultFormatProvider) Parse(ctx context.Context, encrypted string) (hkdfguard.KeyTrackingValue, error) {
	_, span := diagnostics.DataProtection.Start(ctx, diagnostics.SpanDataProtectionFormatProviderParse)
	defer span.End()
	diagnostics.DataProtection.LogSensitiveOperation(span, diagnostics.SpanDataProtectionFormatProviderParse,
		diagnostics.AttrEncryptedLength.Int(len(encrypted)))

	version, payload, err := f.parseSegments(encrypted)
	if err != nil {
		return hkdfguard.KeyTrackingValue{}, recordError(span, err)
	}
	value, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return hkdfguard.KeyTrackingValue{}, recordError(span, fmt.Errorf("%w: the encrypted value is not valid base64", ErrInvalidFormat))
	}
	return hkdfguard.KeyTrackingValue{KeyVersion: version, Value: value}, nil
}

// MaxDecryptedLength returns the decoded payload's length - an upper bound on the plaintext, since
// AEAD ciphertext is never shorter than what it encloses - without decoding it.
func (f *DefaultFormatProvider) MaxDecryptedLength(ctx context.Context, encrypted string) (int, error) {
	_, span := diagnostics.DataProtection.Start(ctx, diagnostics.SpanDataProtectionFormatProviderGetMaxDecryptedLength)
	defer span.End()
	diagnostics.DataProtection.LogSensitiveOperation(span, diagnostics.SpanDataProtectionFormatProviderGetMaxDecryptedLength,
		diagnostics.AttrEncryptedLength.Int(len(encrypted)))

	_, payload, err := f.parseSegments(encrypted)
	if err != nil {
		return 0, recordError(span, err)
	}
	length, ok := base64DecodedLength(payload)
	if !ok {
		return 0, recordError(span, fmt.Errorf("%w: the encrypted value is not valid base64", ErrInvalidFormat))
	}
	return length, nil
}

// parseSegments splits a value into its version and base64 payload, accepting only the canonical
// form Format writes - shared by Parse and MaxDecryptedLength so both agree on what is well-formed.
func (f *DefaultFormatProvider) parseSegments(encrypted string) (int, string, error) {
	if len(encrypted) > f.maxEncryptedLength {
		return 0, "", fmt.Errorf("%w: the encrypted value is %d characters, over the %d-character limit", ErrInvalidFormat, len(encrypted), f.maxEncryptedLength)
	}

	malformed := fmt.Errorf("%w: expected '%s%s%s<version>%s<base64>'", ErrInvalidFormat, encPrefix, delimiter, versionPrefix, delimiter)
	prefix, rest, ok := strings.Cut(encrypted, delimiter)
	if !ok || prefix != encPrefix {
		return 0, "", malformed
	}
	versionSegment, payload, ok := strings.Cut(rest, delimiter)
	if !ok || !strings.HasPrefix(versionSegment, versionPrefix) {
		return 0, "", malformed
	}

	// ASCII digits with an optional leading '-', within the 32-bit range every port shares - no
	// whitespace or '+'.
	digits := versionSegment[len(versionPrefix):]
	if !isCanonicalInteger(digits) {
		return 0, "", malformed
	}
	version, err := strconv.ParseInt(digits, 10, 32)
	if err != nil {
		return 0, "", malformed
	}

	// Go's decoder skips line breaks, so whitespace is refused here rather than silently dropped.
	if strings.ContainsAny(payload, " \t\r\n") {
		return 0, "", malformed
	}
	return int(version), payload, nil
}

func isCanonicalInteger(s string) bool {
	s = strings.TrimPrefix(s, "-")
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// base64DecodedLength validates padded standard base64 by its characters alone, without decoding
// it, and returns the length it decodes to.
func base64DecodedLength(s string) (int, bool) {
	if len(s)%4 != 0 {
		return 0, false
	}
	padding := len(s) - len(strings.TrimRight(s, "="))
	if padding > 2 {
		return 0, false
	}
	for i := 0; i < len(s)-padding; i++ {
		c := s[i]
		if !('A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '+' || c == '/') {
			return 0, false
		}
	}
	return len(s)/4*3 - padding, true
}

func recordError(span trace.Span, err error) error {
	diagnostics.RecordError(span, err)
	return err
}
