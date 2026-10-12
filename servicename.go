package hkdfguard

import (
	"fmt"
	"unicode/utf8"
)

// MaxServiceNameLength is the longest service name, in characters (each is ASCII, so also in
// bytes).
const MaxServiceNameLength = 128

// IsValidServiceName reports whether name satisfies every ValidateServiceName rule.
func IsValidServiceName(name string) bool { return ValidateServiceName(name) == nil }

// ValidateServiceName checks name against the rule for a service name - the identity of a KEK in
// the native KMS library: 1 to MaxServiceNameLength characters, each an ASCII letter, digit or
// '.', not starting with '.' and never containing "..". Typically reverse-DNS, e.g.
// "com.example.orders". Enforce it before any native call, so a bad name fails with a clear
// message instead of a native status code and is never passed across the boundary at all.
//
// It returns nil for a valid name, and otherwise an error wrapping ErrInvalidServiceName whose
// message says which rule the name breaks.
func ValidateServiceName(name string) error {
	if problem := serviceNameProblem(name); problem != "" {
		return fmt.Errorf("%w: %s", ErrInvalidServiceName, problem)
	}
	return nil
}

// serviceNameProblem describes why name is not a valid service name, or returns "" if it is. The
// messages match every other port's.
func serviceNameProblem(name string) string {
	if name == "" {
		return "A service name is required."
	}

	if length := utf8.RuneCountInString(name); length > MaxServiceNameLength {
		return fmt.Sprintf("A service name is at most %d characters; this one is %d.", MaxServiceNameLength, length)
	}

	if name[0] == '.' {
		return "A service name can't start with '.'."
	}

	// Every character before the first non-ASCII one is a single byte, so the byte index of the
	// first offending character is also its character position.
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c == '.':
			if name[i-1] == '.' {
				return "A service name can't contain '..'."
			}
		case !isASCIILetterOrDigit(c):
			r, _ := utf8.DecodeRuneInString(name[i:])
			return fmt.Sprintf("A service name may contain only ASCII letters, digits and '.'; it has U+%04X at position %d.", r, i)
		}
	}

	return ""
}

func isASCIILetterOrDigit(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9'
}
