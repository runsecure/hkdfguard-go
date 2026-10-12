package hkdfguard

import (
	"fmt"
	"unicode/utf8"
)

// ConfigurationPurposePrefix is the prefix every configuration purpose starts with.
const ConfigurationPurposePrefix = "HkdfGuard.EncryptedConfiguration"

// ConfigurationPurpose returns the purpose that binds an encrypted configuration value to the
// configuration key it's stored under - the single rule whoever writes a value (e.g. a pipeline
// via PipelineDataProtector) and whoever reads it must both derive, so a value copied to a
// different key fails authentication instead of being accepted. Keys are full configuration paths
// (e.g. "ConnectionStrings:Admin").
//
// The rule, which every language port implements identically: the purpose is
// ConfigurationPurposePrefix + ":" + key with the ASCII letters a-z upper-cased and every other
// character left exactly as it is; the AAD (ConfigurationAAD) is that purpose's UTF-8 bytes. A key
// that isn't valid UTF-8 is rejected with ErrInvalidConfigurationKey, as is an empty one.
//
// Keys differing only in ASCII case share a purpose. Keys differing in any other way - including
// non-ASCII case, such as "café" and "CAFÉ" - never do; reading a value under such a variant fails
// authentication rather than revealing it.
func ConfigurationPurpose(configurationKey string) (string, error) {
	aad, err := ConfigurationAAD(configurationKey)
	if err != nil {
		return "", err
	}
	return string(aad), nil
}

// ConfigurationAAD returns ConfigurationPurpose(configurationKey) as UTF-8 bytes - the Additional
// Authenticated Data a value stored under configurationKey is encrypted with.
func ConfigurationAAD(configurationKey string) ([]byte, error) {
	if configurationKey == "" {
		return nil, fmt.Errorf("%w: the configuration key must not be empty", ErrInvalidConfigurationKey)
	}
	if !utf8.ValidString(configurationKey) {
		return nil, fmt.Errorf("%w: the configuration key is not valid UTF-8", ErrInvalidConfigurationKey)
	}

	aad := make([]byte, 0, len(ConfigurationPurposePrefix)+1+len(configurationKey))
	aad = append(aad, ConfigurationPurposePrefix...)
	aad = append(aad, ':')
	aad = append(aad, configurationKey...)
	upperASCII(aad[len(ConfigurationPurposePrefix)+1:])
	return aad, nil
}

// upperASCII upper-cases the ASCII letters a-z in b in place. Working at the byte level is exact:
// in UTF-8, bytes 0x61-0x7A only ever encode those ASCII letters.
func upperASCII(b []byte) {
	for i, c := range b {
		if 'a' <= c && c <= 'z' {
			b[i] = c - ('a' - 'A')
		}
	}
}
