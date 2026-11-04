package configurationresolver

import (
	"errors"
	"fmt"
	"strconv"
)

// ErrDestinationTooSmall reports a destination too small for the resolved text: the port of the
// ArgumentException a .NET resolver throws for its destination.
var ErrDestinationTooSmall = errors.New("configurationresolver: the destination is too small for the resolved text")

// ErrStringValuesNotAllowed reports a ProtectedCacheValueProvider asked for a value as a string
// without WithAllowStringValues set.
var ErrStringValuesNotAllowed = errors.New("configurationresolver: ProtectedCacheValueProvider doesn't return values as strings unless AllowStringValues is set")

// ErrResolvedValueTooLong reports a ResolvingProtectedCacheCollection value whose template
// resolves to more than its MaxResolvedLength.
var ErrResolvedValueTooLong = errors.New("configurationresolver: the value resolves to more than MaxResolvedLength")

// ConfigurationKeyErrorCode says why a configuration item could not be resolved: the port of the
// ConfigurationKeyError enum.
type ConfigurationKeyErrorCode int

const (
	// KeyNotAllowed: the key was not read by the configuration item reader, so no value provider
	// was asked for it.
	KeyNotAllowed ConfigurationKeyErrorCode = iota

	// KeyNotFound: the key was allowed, but no value provider has a value for it.
	KeyNotFound

	// KeyValueUnstable: the value kept changing size while it was read, such as a secret being
	// replaced.
	KeyValueUnstable

	// KeyCycle: the key's value, resolved through the items in it, leads back to the same key.
	KeyCycle
)

// String returns the code's .NET name: NotAllowed, NotFound, ValueUnstable or Cycle.
func (c ConfigurationKeyErrorCode) String() string {
	switch c {
	case KeyNotAllowed:
		return "NotAllowed"
	case KeyNotFound:
		return "NotFound"
	case KeyValueUnstable:
		return "ValueUnstable"
	case KeyCycle:
		return "Cycle"
	default:
		return "ConfigurationKeyErrorCode(" + strconv.Itoa(int(c)) + ")"
	}
}

// ConfigurationKeyError reports a configuration key whose value could not be resolved: the port
// of ConfigurationKeyException. Match it with errors.As.
//
// Its message holds only the item's position and the Code, so it is safe to log. Key may come
// from the source text, which may be untrusted: treat it as untrusted input before logging or
// displaying it.
type ConfigurationKeyError struct {
	// Key is the configuration key. When returned by a resolver it is the item's trimmed key, from
	// the source text.
	Key string

	// Code says why the value could not be resolved.
	Code ConfigurationKeyErrorCode

	// SourceIndex is the byte index in the source where the item's start sequence begins; it is
	// set only when HasSourceIndex is.
	SourceIndex int

	// HasSourceIndex is false when the error was returned outside a resolver, such as by a value
	// provider called directly.
	HasSourceIndex bool

	// Err is the error that caused this one, if any: for an error a value provider returned, the
	// provider's own error, without a SourceIndex.
	Err error
}

func (e *ConfigurationKeyError) Error() string {
	if e.HasSourceIndex {
		return fmt.Sprintf("configurationresolver: the configuration item at index %d could not be resolved (%s)", e.SourceIndex, e.Code)
	}
	return fmt.Sprintf("configurationresolver: the value for a configuration key could not be resolved (%s)", e.Code)
}

// Unwrap returns Err.
func (e *ConfigurationKeyError) Unwrap() error { return e.Err }

func keyError(key string, code ConfigurationKeyErrorCode, sourceIndex int) *ConfigurationKeyError {
	return &ConfigurationKeyError{Key: key, Code: code, SourceIndex: sourceIndex, HasSourceIndex: true}
}
