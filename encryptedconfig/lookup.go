package encryptedconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// ErrDuplicateKey reports two configuration keys that differ only in ASCII case, which would make
// a case-insensitive lookup ambiguous.
var ErrDuplicateKey = errors.New("encryptedconfig: duplicate configuration key")

// asciiUpper upper-cases a-z and leaves every other byte alone - the same rule
// hkdfguard.ConfigurationPurpose applies, so a lookup matches exactly the keys a value
// authenticates under.
func asciiUpper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'a' <= c && c <= 'z' {
			b[i] = c - ('a' - 'A')
		}
	}
	return string(b)
}

// NewMapLookup returns a Lookup over values that matches keys ignoring ASCII case, as .NET
// configuration does for ASCII keys. Keys that differ only in ASCII case are refused with
// ErrDuplicateKey.
func NewMapLookup(values map[string]string) (Lookup, error) {
	byKey := make(map[string]string, len(values))
	for key, value := range values {
		upper := asciiUpper(key)
		if _, exists := byKey[upper]; exists {
			return nil, fmt.Errorf("%w: '%s' differs from another key only in case", ErrDuplicateKey, key)
		}
		byKey[upper] = value
	}
	return func(key string) (string, bool) {
		value, ok := byKey[asciiUpper(key)]
		return value, ok
	}, nil
}

// EnvLookup reads keys from environment variables the way .NET's environment configuration does:
// each ':' in the key becomes "__", after prefix - so with prefix "APP_", the key
// "ConnectionStrings:Admin" reads APP_ConnectionStrings__Admin. Variable names are matched
// exactly, as the environment itself does on Linux and macOS.
func EnvLookup(prefix string) Lookup {
	return func(key string) (string, bool) {
		return os.LookupEnv(prefix + strings.ReplaceAll(key, ":", "__"))
	}
}

// FlattenJSON flattens a JSON document into configuration keys the way .NET's JSON configuration
// does: nested object members join with ':' ("ConnectionStrings:Admin"), and array elements use
// their index ("Hosts:0"). Strings are taken as they are, numbers as written, booleans as "true" or
// "false", and null as "". Pass the result to NewMapLookup. Keys that differ only in ASCII case
// are refused with ErrDuplicateKey.
func FlattenJSON(document []byte) (map[string]string, error) {
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.UseNumber()

	var root any
	if err := decoder.Decode(&root); err != nil {
		return nil, fmt.Errorf("encryptedconfig: invalid JSON: %w", err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errors.New("encryptedconfig: invalid JSON: unexpected data after the document")
	}
	if _, ok := root.(map[string]any); !ok {
		return nil, errors.New("encryptedconfig: invalid JSON: the document must be an object")
	}

	values := map[string]string{}
	seen := map[string]string{}
	var walk func(prefix string, node any) error
	walk = func(prefix string, node any) error {
		switch v := node.(type) {
		case map[string]any:
			for name, child := range v {
				key := name
				if prefix != "" {
					key = prefix + ":" + name
				}
				if err := walk(key, child); err != nil {
					return err
				}
			}
			return nil
		case []any:
			for i, child := range v {
				if err := walk(prefix+":"+strconv.Itoa(i), child); err != nil {
					return err
				}
			}
			return nil
		}

		if other, exists := seen[asciiUpper(prefix)]; exists {
			return fmt.Errorf("%w: '%s' and '%s' differ only in case", ErrDuplicateKey, prefix, other)
		}
		seen[asciiUpper(prefix)] = prefix
		switch v := node.(type) {
		case string:
			values[prefix] = v
		case json.Number:
			values[prefix] = v.String()
		case bool:
			values[prefix] = strconv.FormatBool(v)
		default: // null
			values[prefix] = ""
		}
		return nil
	}
	if err := walk("", root); err != nil {
		return nil, err
	}
	return values, nil
}
