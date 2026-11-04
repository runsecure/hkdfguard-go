package configurationresolver

import (
	"testing"
)

// The port of .NET's ConfigurationResolverBuilderTests. An invalid argument, which .NET throws
// from the builder's method, is reported by Build.

var (
	builderTestHigh = map[string]string{"Name": "Grace"}
	builderTestLow  = map[string]string{"Name": "Ada", "Lang": "${Name}"}
)

func TestBuild_UsesTheReaderAndProvidersInTheOrderAdded(t *testing.T) {
	reader := mustDefaultTokenReader(t)
	reader.ReadKeysString("${Name} ${Lang}")

	resolver, err := NewConfigurationResolverBuilder().
		WithReader(reader).
		AddValueProvider(newMapValueProvider(builderTestHigh)).
		AddValueProvider(newMapValueProvider(builderTestLow)).
		Build()

	if err != nil {
		t.Fatal(err)
	}
	if got, want := mustResolveToString(t, resolver, "${Name} ${Lang} $$${Name}"), "Grace ${Name} $${Name}"; got != want {
		t.Errorf("Resolve = %q, want %q", got, want)
	}
}

func TestBuild_DefaultsToTheDefaultTokenAndOptions(t *testing.T) {
	resolver, err := NewConfigurationResolverBuilder().
		WithReader(mustDefaultTokenReader(t)).
		AddValueProvider(newMapValueProvider(builderTestLow)).
		Build()

	if err != nil {
		t.Fatal(err)
	}
	if resolver.IgnoreUnresolvablePlaceholders() {
		t.Error("IgnoreUnresolvablePlaceholders() = true, want false")
	}
	if got := resolver.MaxResolutionDepth(); got != 1 {
		t.Errorf("MaxResolutionDepth() = %d, want 1", got)
	}
	if got := mustResolveToString(t, resolver, "$${Name}"); got != "${Name}" {
		t.Errorf("Resolve = %q, want %q", got, "${Name}")
	}
}

func TestBuild_AppliesTheTokenAndOptions(t *testing.T) {
	token := mustCustomToken(t, "{{", "}}", "")
	reader, err := NewConfigurationItemReader(token)
	if err != nil {
		t.Fatal(err)
	}
	reader.ReadKeysString("{{Lang}} {{Name}} {{Missing}}")

	resolver, err := NewConfigurationResolverBuilder().
		WithToken(token).
		WithReader(reader).
		AddValueProvider(newMapValueProvider(map[string]string{"Lang": "{{Name}}", "Name": "Ada"})).
		IgnoreUnresolvablePlaceholders(true).
		WithMaxResolutionDepth(2).
		Build()

	if err != nil {
		t.Fatal(err)
	}
	if !resolver.IgnoreUnresolvablePlaceholders() {
		t.Error("IgnoreUnresolvablePlaceholders() = false, want true")
	}
	if got := resolver.MaxResolutionDepth(); got != 2 {
		t.Errorf("MaxResolutionDepth() = %d, want 2", got)
	}
	if got, want := mustResolveToString(t, resolver, "{{Lang}} {{Missing}} ${Lang}"), "Ada {{Missing}} ${Lang}"; got != want {
		t.Errorf("Resolve = %q, want %q", got, want)
	}
}

func TestBuild_EachCallReturnsANewResolver(t *testing.T) {
	builder := NewConfigurationResolverBuilder().
		WithReader(mustDefaultTokenReader(t)).
		AddValueProvider(newMapValueProvider(builderTestLow))

	first, err1 := builder.Build()
	second, err2 := builder.Build()

	if err1 != nil || err2 != nil {
		t.Fatalf("Build = %v, %v", err1, err2)
	}
	if first == second {
		t.Error("Build returned the same resolver twice")
	}
}

func TestBuild_WithoutAReaderOrAProvider_Fails(t *testing.T) {
	if resolver, err := NewConfigurationResolverBuilder().AddValueProvider(newMapValueProvider(builderTestLow)).Build(); err == nil || resolver != nil {
		t.Errorf("Build without a reader = %v, %v; want an error", resolver, err)
	}
	if resolver, err := NewConfigurationResolverBuilder().WithReader(mustDefaultTokenReader(t)).Build(); err == nil || resolver != nil {
		t.Errorf("Build without a provider = %v, %v; want an error", resolver, err)
	}
}

func TestBuilder_InvalidArguments_Fail(t *testing.T) {
	tests := map[string]func(*ConfigurationResolverBuilder) *ConfigurationResolverBuilder{
		"WithToken(nil)":        func(b *ConfigurationResolverBuilder) *ConfigurationResolverBuilder { return b.WithToken(nil) },
		"WithReader(nil)":       func(b *ConfigurationResolverBuilder) *ConfigurationResolverBuilder { return b.WithReader(nil) },
		"AddValueProvider(nil)": func(b *ConfigurationResolverBuilder) *ConfigurationResolverBuilder { return b.AddValueProvider(nil) },
		"WithMaxResolutionDepth0": func(b *ConfigurationResolverBuilder) *ConfigurationResolverBuilder {
			return b.WithMaxResolutionDepth(0)
		},
	}
	for name, invalid := range tests {
		t.Run(name, func(t *testing.T) {
			// Otherwise complete, so only the invalid argument can fail Build.
			builder := NewConfigurationResolverBuilder().
				WithReader(mustDefaultTokenReader(t)).
				AddValueProvider(newMapValueProvider(builderTestLow))

			// The invalid argument is reported even after a valid call follows it.
			resolver, err := invalid(builder).WithMaxResolutionDepth(1).Build()

			if err == nil || resolver != nil {
				t.Errorf("Build = %v, %v; want an error", resolver, err)
			}
		})
	}
}
