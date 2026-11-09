package configurationresolver

import (
	"context"
	"errors"
	"strconv"

	"github.com/runsecure/hkdfguard-go"
)

// ValueStatus is the result of asking a ValueProvider for a value.
type ValueStatus int

const (
	// NotFound: the key was not found. Nothing was written.
	NotFound ValueStatus = iota

	// Found: the key was found and its value was written.
	Found

	// DestinationTooSmall: the key was found, but its value does not fit in the destination.
	// Nothing usable was written.
	DestinationTooSmall
)

// String returns the status's .NET name: Found, NotFound or DestinationTooSmall.
func (s ValueStatus) String() string {
	switch s {
	case Found:
		return "Found"
	case NotFound:
		return "NotFound"
	case DestinationTooSmall:
		return "DestinationTooSmall"
	default:
		return "ValueStatus(" + strconv.Itoa(int(s)) + ")"
	}
}

// ValueProvider provides configuration values by key: the port of IValueProvider. Go strings are
// UTF-8, so .NET's TryGetChar is TryGetBytes here. A provider returns an error for a failure that
// is neither NotFound nor DestinationTooSmall - a *ConfigurationKeyError such as KeyValueUnstable,
// or its source's own error - and a resolver returns it, wiping its destination.
type ValueProvider interface {
	// TryGetValue returns the value for key as a string. A string cannot be wiped once created:
	// prefer TryGetBytes for secrets. It returns Found or NotFound.
	TryGetValue(ctx context.Context, key string) (value string, status ValueStatus, err error)

	// TryGetBytes writes the UTF-8 value for key into destination and returns the number of bytes
	// written, 0 unless Found, and whether the value was found and fit in destination.
	TryGetBytes(ctx context.Context, key string, destination []byte) (written int, status ValueStatus, err error)
}

// ByteValueProvider is what a provider whose values are bytes - files, decrypted data - implements
// for ValueProviderBase to build TryGetValue on.
type ByteValueProvider interface {
	// TryGetBytes is ValueProvider.TryGetBytes.
	TryGetBytes(ctx context.Context, key string, destination []byte) (written int, status ValueStatus, err error)

	// TryGetByteCount returns the number of UTF-8 bytes needed to hold key's value - the buffer
	// size TryGetBytes needs - and found == false if the key was not found.
	TryGetByteCount(ctx context.Context, key string) (byteCount int, found bool, err error)
}

// maxReadAttempts is how many times a value is re-read when it grows between being sized and
// being read.
const maxReadAttempts = 3

// ValueProviderBase makes a ValueProvider of a ByteValueProvider: the port of ValueProviderBase.
// Its TryGetBytes is the ByteValueProvider's; TryGetValue reads the value's bytes into a buffer
// sized by TryGetByteCount, makes the string, and wipes the buffer. A value that keeps outgrowing
// its size, read after read, fails with a *ConfigurationKeyError with KeyValueUnstable.
//
//	provider := configurationresolver.ValueProviderBase{ByteValueProvider: mySettings}
type ValueProviderBase struct {
	ByteValueProvider
}

var _ ValueProvider = ValueProviderBase{}

// TryGetValue returns key's value as a string, Found or NotFound.
func (b ValueProviderBase) TryGetValue(ctx context.Context, key string) (string, ValueStatus, error) {
	var buffer []byte
	defer func() { hkdfguard.Wipe(buffer) }()

	for range maxReadAttempts {
		byteCount, found, err := b.TryGetByteCount(ctx, key)
		if err != nil || !found {
			return "", NotFound, err
		}

		// A previous attempt's buffer is wiped and dropped.
		hkdfguard.Wipe(buffer)
		buffer = make([]byte, byteCount)

		written, status, err := b.TryGetBytes(ctx, key, buffer)
		if err != nil {
			return "", NotFound, err
		}
		switch status {
		case Found:
			return string(buffer[:written]), Found, nil
		case DestinationTooSmall:
			continue
		default:
			return "", status, nil
		}
	}
	return "", NotFound, &ConfigurationKeyError{Key: key, Code: KeyValueUnstable}
}

// CompositeValueProvider provides values from several value providers, in priority order.
//
// Each lookup asks the providers in the order given, and the first provider that has the key
// supplies the value; the providers after it are not asked. A provider that has the key but whose
// value doesn't fit in the destination ends the lookup with DestinationTooSmall, rather than
// falling through to a lower-priority value. An error a provider returns ends the lookup too. Put
// the provider you trust most first.
type CompositeValueProvider struct {
	providers []ValueProvider
}

var _ ValueProvider = (*CompositeValueProvider)(nil)

// NewCompositeValueProvider returns a provider over providers, highest priority first. It fails
// when providers is empty or holds nil.
func NewCompositeValueProvider(providers ...ValueProvider) (*CompositeValueProvider, error) {
	if len(providers) == 0 {
		return nil, errors.New("configurationresolver: at least one value provider is required")
	}
	for _, provider := range providers {
		if provider == nil {
			return nil, errors.New("configurationresolver: the value providers cannot contain nil")
		}
	}
	return &CompositeValueProvider{providers: append([]ValueProvider(nil), providers...)}, nil
}

// Providers returns the providers, highest priority first.
func (c *CompositeValueProvider) Providers() []ValueProvider {
	return append([]ValueProvider(nil), c.providers...)
}

// TryGetValue returns the value from the first provider that has key.
func (c *CompositeValueProvider) TryGetValue(ctx context.Context, key string) (string, ValueStatus, error) {
	for _, provider := range c.providers {
		value, status, err := provider.TryGetValue(ctx, key)
		if err != nil {
			return "", NotFound, err
		}
		if status == Found {
			return value, Found, nil
		}
	}
	return "", NotFound, nil
}

// TryGetBytes writes the value from the first provider that has key.
func (c *CompositeValueProvider) TryGetBytes(ctx context.Context, key string, destination []byte) (int, ValueStatus, error) {
	for _, provider := range c.providers {
		written, status, err := provider.TryGetBytes(ctx, key, destination)
		if err != nil {
			return 0, NotFound, err
		}
		if status != NotFound {
			return written, status, nil
		}
	}
	return 0, NotFound, nil
}
