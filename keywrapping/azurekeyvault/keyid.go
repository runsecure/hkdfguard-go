package azurekeyvault

import (
	"regexp"
	"strconv"
	"strings"
)

// keyIDPattern is a key identifier, parsed by hand rather than with net/url: url.Parse accepts user
// info, percent-encoding, "." and ".." segments and IPv6 literals, all of which the other ports
// refuse. Key Vault's own rules: names are 1-127 letters, digits and dashes; versions are 32 hex
// digits in Key Vault and Managed HSM alike, but only their characters are checked here: a version
// recorded in a wrapped DEK must be exactly 32 (see envelope.go). The scheme ignores case, as in the
// other ports, but "keys" doesn't; the host is letters, digits, dots and dashes, with no user info or
// IPv6 literal.
var keyIDPattern = regexp.MustCompile(`^[Hh][Tt][Tt][Pp][Ss]://([0-9A-Za-z](?:[0-9A-Za-z.-]*[0-9A-Za-z])?)(?::([0-9]{1,5}))?/keys/([0-9A-Za-z-]{1,127})(?:/([0-9A-Za-z]{1,64}))?/?$`)

// keyID is a Key Vault key identifier, https://{vault}/keys/{name}[/{version}], parsed strictly: the
// SDK's own parsing accepts any two- or three-segment path (a secret's, say), and this one decides
// which keys a wrapper is pinned to.
type keyID struct {
	// vault is the vault's URL - scheme, host and any port - without a trailing slash; the host in
	// lower case.
	vault string
	// name is the key's name.
	name string
	// version is the key's version, or "" for its current one.
	version string
}

// parseKeyID parses a key identifier, failing with ErrInvalidArgument when it isn't a Key Vault
// key's.
func parseKeyID(id string) (keyID, error) {
	match := keyIDPattern.FindStringSubmatch(id)
	if match == nil {
		return keyID{}, invalidArgument("%q isn't a Key Vault key identifier: https://{vault}.vault.azure.net/keys/{name}, optionally followed by /{version}.", id)
	}
	host, port, name, version := match[1], match[2], match[3], match[4]
	vault := "https://" + strings.ToLower(host)
	if port != "" {
		number, _ := strconv.Atoi(port) // at most 5 digits
		if number > 65535 {
			return keyID{}, invalidArgument("%q isn't a Key Vault key identifier: port %s is out of range.", id, port)
		}
		vault += ":" + strconv.Itoa(number)
	}
	return keyID{vault: vault, name: name, version: version}, nil
}

// withVersion is the same key, at version.
func (k keyID) withVersion(version string) keyID {
	k.version = version
	return k
}

// sameKey reports whether other names the same key, in any version: Key Vault's host and key names
// ignore case.
func (k keyID) sameKey(other keyID) bool {
	return k.vault == other.vault && strings.EqualFold(k.name, other.name)
}

// String is the identifier, with its version if it has one.
func (k keyID) String() string {
	if k.version == "" {
		return k.vault + "/keys/" + k.name
	}
	return k.vault + "/keys/" + k.name + "/" + k.version
}
