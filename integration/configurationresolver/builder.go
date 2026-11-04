package configurationresolver

import (
	"errors"
	"fmt"

	"github.com/runsecure/hkdfguard-go"
)

// ConfigurationResolverBuilder builds a ConfigurationItemResolver from a token, a reader, and one
// or more value providers: the port of ConfigurationResolverBuilder, with .NET's AddProtectedCache
// extension method as a method of its own.
//
// The token defaults to NewDefaultToken. A reader and at least one value provider are required.
// The reader is not created for you, because only you can read the keys of your trusted template
// into it; create it with the same token. Each Build returns a new resolver that shares the reader
// and the value providers. An invalid argument to any method is reported by Build.
//
//	token := configurationresolver.NewDefaultToken()
//	reader, _ := configurationresolver.NewConfigurationItemReader(token)
//	reader.ReadKeysString(template)
//
//	resolver, err := configurationresolver.NewConfigurationResolverBuilder().
//		WithToken(token).
//		WithReader(reader).
//		AddProtectedCache(secrets).
//		Build()
type ConfigurationResolverBuilder struct {
	token                          *ConfigurationItemToken
	reader                         KeyReader
	valueProviders                 []ValueProvider
	ignoreUnresolvablePlaceholders bool
	maxResolutionDepth             int
	err                            error
}

// NewConfigurationResolverBuilder returns a builder with the default token and a maximum
// resolution depth of 1.
func NewConfigurationResolverBuilder() *ConfigurationResolverBuilder {
	return &ConfigurationResolverBuilder{token: NewDefaultToken(), maxResolutionDepth: 1}
}

func (b *ConfigurationResolverBuilder) fail(err error) *ConfigurationResolverBuilder {
	if b.err == nil {
		b.err = err
	}
	return b
}

// WithToken sets the token that defines the start, end, and escape sequences of a configuration
// item. Use the same token as the reader.
func (b *ConfigurationResolverBuilder) WithToken(token *ConfigurationItemToken) *ConfigurationResolverBuilder {
	if token == nil {
		return b.fail(errors.New("configurationresolver: WithToken was given no token"))
	}
	b.token = token
	return b
}

// WithReader sets the reader whose keys are the only keys the resolver may resolve.
func (b *ConfigurationResolverBuilder) WithReader(reader KeyReader) *ConfigurationResolverBuilder {
	if reader == nil {
		return b.fail(errors.New("configurationresolver: WithReader was given no reader"))
	}
	b.reader = reader
	return b
}

// AddValueProvider adds a value provider, after any added already. Providers added earlier have
// higher priority.
func (b *ConfigurationResolverBuilder) AddValueProvider(valueProvider ValueProvider) *ConfigurationResolverBuilder {
	if valueProvider == nil {
		return b.fail(errors.New("configurationresolver: AddValueProvider was given no value provider"))
	}
	b.valueProviders = append(b.valueProviders, valueProvider)
	return b
}

// AddProtectedCache adds a ProtectedCacheValueProvider over cache, after any value provider added
// already.
func (b *ConfigurationResolverBuilder) AddProtectedCache(cache hkdfguard.ProtectedReadOnlyCache) *ConfigurationResolverBuilder {
	provider, err := NewProtectedCacheValueProvider(cache)
	if err != nil {
		return b.fail(err)
	}
	return b.AddValueProvider(provider)
}

// IgnoreUnresolvablePlaceholders sets whether an allowed key that no value provider has is copied
// unchanged instead of failing.
func (b *ConfigurationResolverBuilder) IgnoreUnresolvablePlaceholders(ignore bool) *ConfigurationResolverBuilder {
	b.ignoreUnresolvablePlaceholders = ignore
	return b
}

// WithMaxResolutionDepth sets the number of levels of configuration items that are resolved; 1
// inserts values as they are.
func (b *ConfigurationResolverBuilder) WithMaxResolutionDepth(maxResolutionDepth int) *ConfigurationResolverBuilder {
	if maxResolutionDepth < 1 {
		return b.fail(fmt.Errorf("configurationresolver: the maximum resolution depth must be at least 1, not %d", maxResolutionDepth))
	}
	b.maxResolutionDepth = maxResolutionDepth
	return b
}

// Build returns a new resolver from the builder's settings. It fails if a method was given an
// invalid argument, no reader has been set, or no value provider has been added.
func (b *ConfigurationResolverBuilder) Build() (*ConfigurationItemResolver, error) {
	if b.err != nil {
		return nil, b.err
	}
	if b.reader == nil {
		return nil, errors.New("configurationresolver: a reader is required; call WithReader before Build")
	}
	if len(b.valueProviders) == 0 {
		return nil, errors.New("configurationresolver: at least one value provider is required; call AddValueProvider before Build")
	}

	resolver, err := NewConfigurationItemResolver(b.token, b.reader, b.valueProviders...)
	if err != nil {
		return nil, err
	}
	resolver.ignoreUnresolvablePlaceholders = b.ignoreUnresolvablePlaceholders
	resolver.maxResolutionDepth = b.maxResolutionDepth
	return resolver, nil
}
