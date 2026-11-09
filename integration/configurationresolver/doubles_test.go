package configurationresolver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// The test doubles and helpers of the ports of .NET's ConfigurationResolver tests (TestDoubles.cs
// and TestSupport.cs).

// mapProvider is a ByteValueProvider over a map, standing in for .NET's DictionaryValueProvider
// where a test needs only a convenient source of values. newMapValueProvider wraps it in a
// ValueProviderBase.
type mapProvider map[string]string

var _ ByteValueProvider = mapProvider(nil)

func newMapValueProvider(values map[string]string) ValueProvider {
	return ValueProviderBase{ByteValueProvider: mapProvider(values)}
}

func (m mapProvider) TryGetBytes(_ context.Context, key string, destination []byte) (int, ValueStatus, error) {
	value, ok := m[key]
	if !ok {
		return 0, NotFound, nil
	}
	if len(value) > len(destination) {
		return 0, DestinationTooSmall, nil
	}
	return copy(destination, value), Found, nil
}

func (m mapProvider) TryGetByteCount(_ context.Context, key string) (int, bool, error) {
	value, ok := m[key]
	if !ok {
		return 0, false, nil
	}
	return len(value), true, nil
}

// spyValueProvider is a ValueProvider that records how it is called: the port of SpyValueProvider.
// When err is set, TryGetBytes records the call and returns it.
type spyValueProvider struct {
	values           map[string]string
	err              error
	tryGetValueCalls []string
	tryGetBytesCalls []string
	bufferLengths    []int
}

var _ ValueProvider = (*spyValueProvider)(nil)

func newSpyValueProvider(values map[string]string) *spyValueProvider {
	return &spyValueProvider{values: values}
}

func (s *spyValueProvider) TryGetValue(_ context.Context, key string) (string, ValueStatus, error) {
	s.tryGetValueCalls = append(s.tryGetValueCalls, key)
	value, ok := s.values[key]
	if !ok {
		return "", NotFound, nil
	}
	return value, Found, nil
}

func (s *spyValueProvider) TryGetBytes(_ context.Context, key string, destination []byte) (int, ValueStatus, error) {
	s.tryGetBytesCalls = append(s.tryGetBytesCalls, key)
	s.bufferLengths = append(s.bufferLengths, len(destination))
	if s.err != nil {
		return 0, NotFound, s.err
	}
	value, ok := s.values[key]
	if !ok {
		return 0, NotFound, nil
	}
	if len(value) > len(destination) {
		return 0, DestinationTooSmall, nil
	}
	return copy(destination, value), Found, nil
}

// fakeThrowingProvider returns the same error for every lookup: the port of
// ValueProviderBaseScenarioTests' ThrowingProvider.
type fakeThrowingProvider struct {
	err *ConfigurationKeyError
}

var _ ValueProvider = (*fakeThrowingProvider)(nil)

func (f *fakeThrowingProvider) TryGetValue(context.Context, string) (string, ValueStatus, error) {
	return "", NotFound, f.err
}

func (f *fakeThrowingProvider) TryGetBytes(context.Context, string, []byte) (int, ValueStatus, error) {
	return 0, NotFound, f.err
}

// readingResolver reads the keys of each source before resolving it, so every key in the source
// is allowed: the port of ReadingResolver. Set its options before the first Resolve; the resolver
// is created then, once.
type readingResolver struct {
	token                          *ConfigurationItemToken
	providers                      []ValueProvider
	reader                         *ConfigurationItemReader
	ignoreUnresolvablePlaceholders bool
	maxResolutionDepth             int

	// alsoAllowed holds texts whose keys are allowed as well as the source's, such as the keys
	// of items inside values.
	alsoAllowed []string

	resolver *ConfigurationItemResolver
}

var _ ConfigurationResolver = (*readingResolver)(nil)

func newReadingResolver(t testing.TB, token *ConfigurationItemToken, providers ...ValueProvider) *readingResolver {
	t.Helper()
	reader, err := NewConfigurationItemReader(token)
	if err != nil {
		t.Fatalf("NewConfigurationItemReader: %v", err)
	}
	return &readingResolver{token: token, providers: providers, reader: reader, maxResolutionDepth: 1}
}

func (r *readingResolver) Resolve(ctx context.Context, source, destination []byte) (int, error) {
	r.reader.ReadKeysAll(append([]string{string(source)}, r.alsoAllowed...))
	if r.resolver == nil {
		resolver, err := NewConfigurationItemResolver(r.token, r.reader, r.providers...)
		if err != nil {
			return 0, err
		}
		resolver, err = resolver.WithIgnoreUnresolvablePlaceholders(r.ignoreUnresolvablePlaceholders).WithMaxResolutionDepth(r.maxResolutionDepth)
		if err != nil {
			return 0, err
		}
		r.resolver = resolver
	}
	return r.resolver.Resolve(ctx, source, destination)
}

// newTemplateResolver reads the keys of a trusted template and returns a resolver that allows only
// those keys: the port of TemplateFile.CreateResolver.
func newTemplateResolver(t testing.TB, token *ConfigurationItemToken, provider ValueProvider, template string) *ConfigurationItemResolver {
	t.Helper()
	reader, err := NewConfigurationItemReader(token)
	if err != nil {
		t.Fatalf("NewConfigurationItemReader: %v", err)
	}
	reader.ReadKeysString(template)
	resolver, err := NewConfigurationItemResolver(token, reader, provider)
	if err != nil {
		t.Fatalf("NewConfigurationItemResolver: %v", err)
	}
	return resolver
}

// mustCustomToken returns a token with the given sequences: the port of CustomToken.
func mustCustomToken(t testing.TB, start, end, escape string) *ConfigurationItemToken {
	t.Helper()
	token, err := NewConfigurationItemToken(start, end, escape)
	if err != nil {
		t.Fatalf("NewConfigurationItemToken(%q, %q, %q): %v", start, end, escape, err)
	}
	return token
}

// resolveToString resolves source into a destination of destinationLength bytes and returns what
// was written.
func resolveToString(resolver ConfigurationResolver, source string, destinationLength int) (string, error) {
	destination := make([]byte, destinationLength)
	written, err := resolver.Resolve(context.Background(), []byte(source), destination)
	if err != nil {
		return "", err
	}
	return string(destination[:written]), nil
}

// mustResolveToString resolves source into a 1024-byte destination, failing the test on an error.
func mustResolveToString(t testing.TB, resolver ConfigurationResolver, source string) string {
	t.Helper()
	resolved, err := resolveToString(resolver, source, 1024)
	if err != nil {
		t.Fatalf("Resolve(%q): %v", source, err)
	}
	return resolved
}

// filledWith returns length bytes of value.
func filledWith(value byte, length int) []byte {
	b := make([]byte, length)
	for i := range b {
		b[i] = value
	}
	return b
}

// requireWiped fails the test unless every byte of destination is zero.
func requireWiped(t testing.TB, destination []byte) {
	t.Helper()
	for i, b := range destination {
		if b != 0 {
			t.Fatalf("destination[%d] = %#x, want the whole destination wiped: %q", i, b, destination)
		}
	}
}

// requireDestinationTooSmall fails the test unless err is ErrDestinationTooSmall.
func requireDestinationTooSmall(t testing.TB, err error) {
	t.Helper()
	if !errors.Is(err, ErrDestinationTooSmall) {
		t.Fatalf("err = %v, want ErrDestinationTooSmall", err)
	}
}

// requireKeyErrorAt is the port of AssertKeyException: err is a *ConfigurationKeyError for key,
// with code, at sourceIndex, and its message holds the index and the code but not the key.
func requireKeyErrorAt(t testing.TB, err error, key string, code ConfigurationKeyErrorCode, sourceIndex int) *ConfigurationKeyError {
	t.Helper()
	var keyErr *ConfigurationKeyError
	if !errors.As(err, &keyErr) {
		t.Fatalf("err = %v (%T), want a *ConfigurationKeyError", err, err)
	}
	if keyErr.Key != key {
		t.Errorf("Key = %q, want %q", keyErr.Key, key)
	}
	if keyErr.Code != code {
		t.Errorf("Code = %v, want %v", keyErr.Code, code)
	}
	if !keyErr.HasSourceIndex || keyErr.SourceIndex != sourceIndex {
		t.Errorf("SourceIndex = %d (HasSourceIndex %v), want %d", keyErr.SourceIndex, keyErr.HasSourceIndex, sourceIndex)
	}
	want := fmt.Sprintf("configurationresolver: the configuration item at index %d could not be resolved (%s)", sourceIndex, code)
	if keyErr.Error() != want {
		t.Errorf("Error() = %q, want %q", keyErr.Error(), want)
	}
	if strings.Contains(keyErr.Error(), key) {
		t.Errorf("Error() = %q holds the key %q", keyErr.Error(), key)
	}
	return keyErr
}
