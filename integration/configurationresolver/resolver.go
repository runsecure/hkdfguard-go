package configurationresolver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/runsecure/hkdfguard-go"
)

// ConfigurationResolver resolves text by replacing its configuration items, such as ${Name}, with
// their values: the port of IConfigurationResolver.
type ConfigurationResolver interface {
	// Resolve copies the UTF-8 source to destination, replacing each configuration item with its
	// UTF-8 value, and returns the number of bytes written. destination must not overlap source.
	// It fails with ErrDestinationTooSmall when destination is too small for the resolved text,
	// and with a *ConfigurationKeyError when an item's key is not allowed, has no value, or its
	// value kept changing while it was read.
	Resolve(ctx context.Context, source, destination []byte) (int, error)
}

// ConfigurationItemResolver resolves text by replacing the configuration items a token delimits
// with values from one or more ValueProviders, for only the keys a reader read: the port of
// ConfigurationItemResolver.
//
// Keys are trimmed of surrounding whitespace, as ConfigurationItemReader trims them. Only keys
// the reader's Keys returns are looked up, so read the keys from a trusted template first; any
// other key fails with KeyNotAllowed without a provider being asked for it. With several value
// providers, each key is looked up in the order the providers were given, and the first that has
// the key supplies the value, as with CompositeValueProvider. A key no provider has fails with
// KeyNotFound, unless WithIgnoreUnresolvablePlaceholders is set. A *ConfigurationKeyError's
// message doesn't hold the key.
//
// The reader's keys are read on each Resolve, so the most recent read applies. Empty items such
// as ${} and a start sequence with no matching end sequence are copied unchanged, and a start
// sequence preceded by the token's escape sequence is copied without the escape sequence. By
// default values are inserted as they are; WithMaxResolutionDepth resolves the items inside values
// too.
//
// Values are written by their provider straight into the destination and are never read as
// strings. If resolving fails, the whole destination is wiped, so no partially resolved values
// are left behind. A resolver is immutable and, given safe providers and reader, safe for
// concurrent use.
type ConfigurationItemResolver struct {
	reader                         KeyReader
	valueProvider                  ValueProvider
	start, end, escape             []byte
	ignoreUnresolvablePlaceholders bool
	maxResolutionDepth             int
}

var _ ConfigurationResolver = (*ConfigurationItemResolver)(nil)

// NewConfigurationItemResolver returns a resolver for token's items, resolving only reader's keys,
// from valueProviders, highest priority first. It fails when token or reader is nil, or
// valueProviders is empty or holds nil.
func NewConfigurationItemResolver(token *ConfigurationItemToken, reader KeyReader, valueProviders ...ValueProvider) (*ConfigurationItemResolver, error) {
	if token == nil {
		return nil, errors.New("configurationresolver: a token is required")
	}
	if reader == nil {
		return nil, errors.New("configurationresolver: a reader is required")
	}
	composite, err := NewCompositeValueProvider(valueProviders...)
	if err != nil {
		return nil, err
	}

	var provider ValueProvider = composite
	if len(composite.providers) == 1 {
		provider = composite.providers[0]
	}
	return &ConfigurationItemResolver{
		reader:             reader,
		valueProvider:      provider,
		start:              []byte(token.start),
		end:                []byte(token.end),
		escape:             []byte(token.escape),
		maxResolutionDepth: 1,
	}, nil
}

// IgnoreUnresolvablePlaceholders reports whether an allowed key that no value provider has is
// copied to the destination unchanged, start and end sequences included, instead of failing with
// KeyNotFound. False by default.
func (r *ConfigurationItemResolver) IgnoreUnresolvablePlaceholders() bool {
	return r.ignoreUnresolvablePlaceholders
}

// WithIgnoreUnresolvablePlaceholders returns a copy of r with IgnoreUnresolvablePlaceholders set
// to ignore. A key that is not allowed still fails with KeyNotAllowed, and an error a value
// provider returns, such as KeyValueUnstable, is still returned.
func (r *ConfigurationItemResolver) WithIgnoreUnresolvablePlaceholders(ignore bool) *ConfigurationItemResolver {
	copied := *r
	copied.ignoreUnresolvablePlaceholders = ignore
	return &copied
}

// MaxResolutionDepth is the number of levels of configuration items that are resolved; 1 by
// default.
func (r *ConfigurationItemResolver) MaxResolutionDepth() int {
	return r.maxResolutionDepth
}

// WithMaxResolutionDepth returns a copy of r that resolves depth levels of items. It fails when
// depth is less than 1.
//
// At 1, values are inserted exactly as they are, even if they contain items. At 2, the items in
// each value are resolved too, and their values are inserted as they are; each further level
// resolves one more level of values. Items in values follow the same rules as items in the
// source: their keys must be allowed by the reader, and escape sequences in values are applied.
// Values at the last level are inserted unchanged, escape sequences included. A key whose value
// leads back to itself fails with KeyCycle. An error in a value reports the position of the item
// in the source that led to it. A value that is resolved is held in a buffer that is wiped
// afterwards, and is never read as a string.
func (r *ConfigurationItemResolver) WithMaxResolutionDepth(depth int) (*ConfigurationItemResolver, error) {
	if depth < 1 {
		return nil, fmt.Errorf("configurationresolver: the maximum resolution depth must be at least 1, not %d", depth)
	}
	copied := *r
	copied.maxResolutionDepth = depth
	return &copied, nil
}

// Resolve copies the UTF-8 source to destination, replacing each configuration item with its
// value, and returns the number of bytes written. See ConfigurationResolver.Resolve.
func (r *ConfigurationItemResolver) Resolve(ctx context.Context, source, destination []byte) (int, error) {
	run := resolution{
		resolver:    r,
		ctx:         ctx,
		destination: destination,
		allowedKeys: map[string]struct{}{},
	}
	for _, key := range r.reader.Keys() {
		run.allowedKeys[key] = struct{}{}
	}

	if err := run.write(source, 1, -1); err != nil {
		hkdfguard.Wipe(destination)
		return 0, err
	}
	return run.written, nil
}

// resolution is one Resolve call's state.
type resolution struct {
	resolver    *ConfigurationItemResolver
	ctx         context.Context
	destination []byte
	written     int
	allowedKeys map[string]struct{}

	// resolving holds the keys whose values are being resolved, outermost first.
	resolving []string
}

// write copies text to the destination, replacing each configuration item with its value. depth
// is 1 for the source, 2 for a value in it, and so on. itemIndex is the index of the item in the
// source that led to this text, or -1 for the source itself.
func (run *resolution) write(text []byte, depth, itemIndex int) error {
	start, end, escape := run.resolver.start, run.resolver.end, run.resolver.escape
	offset := 0

	for {
		startIndex := bytes.Index(text, start)
		if startIndex < 0 {
			return run.copy(text)
		}

		keyStart := startIndex + len(start)
		var consumed int
		if len(escape) > 0 && bytes.HasSuffix(text[:startIndex], escape) {
			if err := run.copy(text[:startIndex-len(escape)]); err != nil {
				return err
			}
			if err := run.copy(start); err != nil {
				return err
			}
			consumed = keyStart
		} else {
			endIndex := bytes.Index(text[keyStart:], end)
			if endIndex < 0 {
				return run.copy(text)
			}

			consumed = keyStart + endIndex + len(end)
			key := itemKey(text[keyStart : keyStart+endIndex])
			if key == "" {
				if err := run.copy(text[:consumed]); err != nil {
					return err
				}
			} else {
				if err := run.copy(text[:startIndex]); err != nil {
					return err
				}
				sourceIndex := itemIndex
				if sourceIndex < 0 {
					sourceIndex = offset + startIndex
				}
				wrote, err := run.tryWriteValue(key, sourceIndex, depth)
				if err != nil {
					return err
				}
				if !wrote {
					if err := run.copy(text[startIndex:consumed]); err != nil {
						return err
					}
				}
			}
		}

		text = text[consumed:]
		offset += consumed
	}
}

// tryWriteValue writes key's value to the destination, resolving the items in it if the depth
// allows. It returns false when no provider has the key and IgnoreUnresolvablePlaceholders is
// set, so the item is to be copied unchanged.
func (run *resolution) tryWriteValue(key string, sourceIndex, depth int) (bool, error) {
	if _, ok := run.allowedKeys[key]; !ok {
		return false, keyError(key, KeyNotAllowed, sourceIndex)
	}
	if slices.Contains(run.resolving, key) {
		return false, keyError(key, KeyCycle, sourceIndex)
	}

	room := run.destination[run.written:]
	valueLength, status, err := run.resolver.valueProvider.TryGetBytes(run.ctx, key, room)
	if err != nil {
		var keyErr *ConfigurationKeyError
		if errors.As(err, &keyErr) && !keyErr.HasSourceIndex {
			return false, &ConfigurationKeyError{Key: keyErr.Key, Code: keyErr.Code, SourceIndex: sourceIndex, HasSourceIndex: true, Err: err}
		}
		return false, err
	}

	if status == NotFound && run.resolver.ignoreUnresolvablePlaceholders {
		return false, nil
	}
	switch status {
	case Found:
	case DestinationTooSmall:
		return false, ErrDestinationTooSmall
	default:
		return false, keyError(key, KeyNotFound, sourceIndex)
	}
	if valueLength < 0 || valueLength > len(room) {
		return false, fmt.Errorf("configurationresolver: a value provider reported writing %d bytes into %d", valueLength, len(room))
	}

	value := room[:valueLength]
	if depth >= run.resolver.maxResolutionDepth || !bytes.Contains(value, run.resolver.start) {
		run.written += valueLength
		return true, nil
	}

	// Move the value to a copy, wipe it from the destination, and write it back resolved.
	copied := bytes.Clone(value)
	defer hkdfguard.Wipe(copied)
	hkdfguard.Wipe(value)

	run.resolving = append(run.resolving, key)
	if err := run.write(copied, depth+1, sourceIndex); err != nil {
		return false, err
	}
	run.resolving = run.resolving[:len(run.resolving)-1]
	return true, nil
}

func (run *resolution) copy(text []byte) error {
	if len(text) > len(run.destination)-run.written {
		return ErrDestinationTooSmall
	}
	run.written += copy(run.destination[run.written:], text)
	return nil
}
