// Package gsmcheck holds the rules the Google Secret Manager secret modules -
// cache/googlesecretmanager and pipeline/googlesecretmanager - apply to names, project IDs and
// Secret Manager's responses. It needs only the standard library, so neither module takes a
// dependency for it; Response returns why it refuses ("" when it accepts), which the module wraps in
// its own error.
package gsmcheck

import (
	"fmt"
	"hash/crc32"
	"strings"
)

// MaxSecretNameLength is the longest ID Secret Manager accepts for a secret.
const MaxSecretNameLength = 255

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// IsValidSecretName reports whether Secret Manager accepts name as a secret ID: 1-255 ASCII letters,
// digits, hyphens and underscores.
func IsValidSecretName(name string) bool {
	if name == "" || len(name) > MaxSecretNameLength {
		return false
	}
	for i := 0; i < len(name); i++ {
		if c := name[i]; !isASCIILetterOrDigit(c) && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

// IsProjectID reports whether id can be spliced into a resource name as its project: 1 or more
// ASCII letters, digits, hyphens, dots and colons.
func IsProjectID(id string) bool {
	if id == "" {
		return false
	}
	for i := 0; i < len(id); i++ {
		if c := id[i]; !isASCIILetterOrDigit(c) && c != '-' && c != '.' && c != ':' {
			return false
		}
	}
	return true
}

func isASCIILetterOrDigit(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9'
}

// Response returns why an AccessSecretVersion response for the secret name is refused: its resource
// name, responseName, isn't a version of that secret (its project comes back as a number, so only
// the secret ID can be compared), or its payload doesn't match checksum, the payload's DataCrc32C
// (nil when the response has none).
func Response(name, responseName string, checksum *int64, payload []byte) string {
	if secret, ok := SecretOfVersion(responseName); !ok || secret != name {
		return fmt.Sprintf("Secret Manager answered a request for secret '%s' with '%s'.", name, responseName)
	}
	if checksum != nil && *checksum != CRC32C(payload) {
		return fmt.Sprintf("The payload of secret '%s' doesn't match its CRC32C: it was corrupted in transit.", name)
	}
	return ""
}

// SecretOfVersion is the secret ID in a secret version's resource name,
// projects/{project}/secrets/{secret}/versions/{version}; ok is false for anything else.
func SecretOfVersion(resourceName string) (string, bool) {
	parts := strings.Split(resourceName, "/")
	if len(parts) != 6 || parts[0] != "projects" || parts[2] != "secrets" || parts[4] != "versions" ||
		parts[1] == "" || parts[3] == "" || parts[5] == "" {
		return "", false
	}
	return parts[3], true
}

// CRC32C is the CRC32C (Castagnoli) checksum of data, as Secret Manager checksums payloads.
func CRC32C(data []byte) int64 { return int64(crc32.Checksum(data, castagnoli)) }
