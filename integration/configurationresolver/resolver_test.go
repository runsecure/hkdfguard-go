package configurationresolver

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

// The port of .NET's ConfigurationItemResolverTests. Each pair of char and byte tests is one test
// here, and an item's index is a byte index.

var resolverTestValues = map[string]string{
	"Name":        "Ada",
	"value 1":     "ONE",
	"value2":      "TWO",
	"value3":      "THREE",
	"Db:Password": "p@ss",
	"Empty":       "",
	"Unicode":     "café",
}

var nestedTestValues = map[string]string{
	"Url":     "https://${Host}:${Port}/",
	"Host":    "${Region}.db.internal",
	"Region":  "eu",
	"Port":    "5432",
	"Self":    "a${Self}",
	"Ping":    "${Pong}",
	"Pong":    "${Ping}",
	"Escaped": "$${Region}",
	"Missing": "[${ Nope }]",
	"Shrinks": "${Region}!",
}

// nestedTestKeys returns the values of nestedTestValues, whose keys a nested resolver allows.
func nestedTestKeys() []string {
	keys := make([]string, 0, len(nestedTestValues))
	for _, value := range nestedTestValues {
		keys = append(keys, value)
	}
	return keys
}

func newValuesResolver(t testing.TB) *readingResolver {
	return newReadingResolver(t, NewDefaultToken(), newMapValueProvider(resolverTestValues))
}

func newNestedResolver(t testing.TB, depth int) *readingResolver {
	resolver := newReadingResolver(t, NewDefaultToken(), newMapValueProvider(nestedTestValues))
	resolver.maxResolutionDepth = depth
	resolver.alsoAllowed = nestedTestKeys()
	return resolver
}

// newAllowListed is the port of CreateAllowListed: a resolver over a spy that allows only the keys
// its reader reads.
func newAllowListed(t testing.TB) (*ConfigurationItemReader, *ConfigurationItemResolver, *spyValueProvider) {
	t.Helper()
	reader, err := NewConfigurationItemReader(NewDefaultToken())
	if err != nil {
		t.Fatal(err)
	}
	spy := newSpyValueProvider(resolverTestValues)
	resolver, err := NewConfigurationItemResolver(NewDefaultToken(), reader, spy)
	if err != nil {
		t.Fatal(err)
	}
	return reader, resolver, spy
}

func TestResolve_ReplacesItems(t *testing.T) {
	tests := []struct{ source, expected string }{
		// ResolvedText
		{"", ""},
		{"plain text", "plain text"},
		{"${Name}", "Ada"},
		{"Hello ${Name}!", "Hello Ada!"},
		{"${ Name }", "Ada"},
		{"${\tName\n}", "Ada"},
		{"${Name}${Name}", "AdaAda"},
		{"${Db:Password}", "p@ss"},
		{"[${Empty}]", "[]"},
		{"ünï ${Unicode} ✓", "ünï café ✓"},
		{
			"this is my ${ value 1 }, and this is ${value2} and lastly this is ${value3}",
			"this is my ONE, and this is TWO and lastly this is THREE",
		},
		// PartiallyResolvedText
		{"${Name}} extra", "Ada} extra"},
		{"${Name} then ${unterminated", "Ada then ${unterminated"},
		{"${} then ${Name}", "${} then Ada"},
	}
	resolver := newValuesResolver(t)
	for _, tc := range tests {
		t.Run(tc.source, func(t *testing.T) {
			if got := mustResolveToString(t, resolver, tc.source); got != tc.expected {
				t.Errorf("Resolve(%q) = %q, want %q", tc.source, got, tc.expected)
			}
		})
	}
}

func TestResolve_CopiesTextWithoutCompleteItemsUnchanged(t *testing.T) {
	resolver := newValuesResolver(t)
	for _, source := range []string{"${}", "${ }", "start ${Name", "} stray end }", "$ {Name} $Name {Name}"} {
		t.Run(source, func(t *testing.T) {
			if got := mustResolveToString(t, resolver, source); got != source {
				t.Errorf("Resolve(%q) = %q, want it unchanged", source, got)
			}
		})
	}
}

func TestResolve_ReturnsCountAndLeavesRestOfDestinationUntouched(t *testing.T) {
	tests := []struct {
		source            string
		destinationLength int
		written           int
		expected          string
	}{
		{"x=${Name}", 16, 5, "x=Ada###########"},
		// "café" is 5 UTF-8 bytes.
		{"${Unicode}", 8, 5, "café###"},
	}
	resolver := newValuesResolver(t)
	for _, tc := range tests {
		t.Run(tc.source, func(t *testing.T) {
			destination := filledWith('#', tc.destinationLength)

			written, err := resolver.Resolve(context.Background(), []byte(tc.source), destination)

			if err != nil {
				t.Fatal(err)
			}
			if written != tc.written {
				t.Errorf("written = %d, want %d", written, tc.written)
			}
			if string(destination) != tc.expected {
				t.Errorf("destination = %q, want %q", destination, tc.expected)
			}
		})
	}
}

func TestResolve_SucceedsWhenDestinationIsExactlyTheResolvedLength(t *testing.T) {
	tests := []struct {
		source            string
		destinationLength int
		expected          string
	}{
		{"x=${Name}", 5, "x=Ada"},
		// "café" is 4 characters but 5 UTF-8 bytes.
		{"x=${Unicode}", 7, "x=café"},
	}
	resolver := newValuesResolver(t)
	for _, tc := range tests {
		got, err := resolveToString(resolver, tc.source, tc.destinationLength)
		if err != nil || got != tc.expected {
			t.Errorf("Resolve(%q) into %d bytes = %q, %v; want %q", tc.source, tc.destinationLength, got, err, tc.expected)
		}
	}
}

func TestResolve_EmptySourceIntoEmptyDestination_WritesNothing(t *testing.T) {
	resolver := newValuesResolver(t)

	for _, destination := range [][]byte{nil, {}} {
		written, err := resolver.Resolve(context.Background(), nil, destination)
		if written != 0 || err != nil {
			t.Errorf("Resolve(nil, %v) = %d, %v; want 0, nil", destination, written, err)
		}
	}
}

func TestResolve_UsesTheTokensStartAndEndSequences(t *testing.T) {
	tests := []struct{ start, end, source, expected string }{
		{"{{", "}}", "{{Name}} and ${Name}", "Ada and ${Name}"},
		{"{{", "}}", "{{ Name }}{{Name}", "Ada{{Name}"},
		{"<%", "%>", "<%Db:Password%>", "p@ss"},
		{"«", "»", "« Unicode » and «Name»", "café and Ada"},
	}
	for _, tc := range tests {
		t.Run(tc.source, func(t *testing.T) {
			resolver := newReadingResolver(t, mustCustomToken(t, tc.start, tc.end, ""), newMapValueProvider(resolverTestValues))

			if got := mustResolveToString(t, resolver, tc.source); got != tc.expected {
				t.Errorf("Resolve(%q) = %q, want %q", tc.source, got, tc.expected)
			}
		})
	}
}

func TestResolve_WritesValuesDirectlyIntoTheDestination(t *testing.T) {
	tests := []struct {
		source, expected string
		calls            []string
		bufferLengths    []int
	}{
		{"ab-${Name}-${value2}", "ab-Ada-TWO", []string{"Name", "value2"}, []int{32 - 3, 32 - 7}},
		// "ü-" is 3 bytes.
		{"ü-${Unicode}", "ü-café", []string{"Unicode"}, []int{32 - 3}},
	}
	for _, tc := range tests {
		t.Run(tc.source, func(t *testing.T) {
			spy := newSpyValueProvider(resolverTestValues)
			resolver := newReadingResolver(t, NewDefaultToken(), spy)

			got, err := resolveToString(resolver, tc.source, 32)

			if err != nil || got != tc.expected {
				t.Fatalf("Resolve(%q) = %q, %v; want %q", tc.source, got, err, tc.expected)
			}
			if !slices.Equal(spy.tryGetBytesCalls, tc.calls) {
				t.Errorf("TryGetBytes calls = %q, want %q", spy.tryGetBytesCalls, tc.calls)
			}
			if !slices.Equal(spy.bufferLengths, tc.bufferLengths) {
				t.Errorf("buffer lengths = %v, want %v", spy.bufferLengths, tc.bufferLengths)
			}
			if len(spy.tryGetValueCalls) != 0 {
				t.Errorf("TryGetValue calls = %q, want none", spy.tryGetValueCalls)
			}
		})
	}
}

func TestResolve_NeverReadsValuesAsStrings_EvenWhenItFails(t *testing.T) {
	tests := []struct {
		source, failingKey string
		destinationLength  int
	}{
		{"${Name} ${missing}", "missing", 64},
		{"${Name} ${value2}", "value2", 5},
	}
	for _, tc := range tests {
		t.Run(tc.source, func(t *testing.T) {
			spy := newSpyValueProvider(resolverTestValues)
			resolver := newReadingResolver(t, NewDefaultToken(), spy)

			if _, err := resolveToString(resolver, tc.source, tc.destinationLength); err == nil {
				t.Fatal("Resolve succeeded, want an error")
			}

			if want := []string{"Name", tc.failingKey}; !slices.Equal(spy.tryGetBytesCalls, want) {
				t.Errorf("TryGetBytes calls = %q, want %q", spy.tryGetBytesCalls, want)
			}
			if len(spy.tryGetValueCalls) != 0 {
				t.Errorf("TryGetValue calls = %q, want none", spy.tryGetValueCalls)
			}
		})
	}
}

func TestConstructor_NullToken_Fails(t *testing.T) {
	reader, _ := NewConfigurationItemReader(NewDefaultToken())

	if resolver, err := NewConfigurationItemResolver(nil, reader, newMapValueProvider(resolverTestValues)); err == nil || resolver != nil {
		t.Errorf("NewConfigurationItemResolver(nil token) = %v, %v; want an error", resolver, err)
	}
}

func TestConstructor_NullReader_Fails(t *testing.T) {
	if resolver, err := NewConfigurationItemResolver(NewDefaultToken(), nil, newMapValueProvider(resolverTestValues)); err == nil || resolver != nil {
		t.Errorf("NewConfigurationItemResolver(nil reader) = %v, %v; want an error", resolver, err)
	}
}

func TestConstructor_NullValueProviders_Fails(t *testing.T) {
	// .NET's null params array: in Go a nil slice, which is the same as no providers.
	reader, _ := NewConfigurationItemReader(NewDefaultToken())

	if resolver, err := NewConfigurationItemResolver(NewDefaultToken(), reader, []ValueProvider(nil)...); err == nil || resolver != nil {
		t.Errorf("NewConfigurationItemResolver(nil providers) = %v, %v; want an error", resolver, err)
	}
}

func TestConstructor_NoValueProviders_Fails(t *testing.T) {
	reader, _ := NewConfigurationItemReader(NewDefaultToken())

	if resolver, err := NewConfigurationItemResolver(NewDefaultToken(), reader); err == nil || resolver != nil {
		t.Errorf("NewConfigurationItemResolver() = %v, %v; want an error", resolver, err)
	}
}

func TestConstructor_NullAmongValueProviders_Fails(t *testing.T) {
	reader, _ := NewConfigurationItemReader(NewDefaultToken())

	if resolver, err := NewConfigurationItemResolver(NewDefaultToken(), reader, newMapValueProvider(resolverTestValues), nil); err == nil || resolver != nil {
		t.Errorf("NewConfigurationItemResolver(provider, nil) = %v, %v; want an error", resolver, err)
	}
}

func TestResolve_MultipleProviders_UsesTheFirstProviderThatHasTheKey(t *testing.T) {
	high := newSpyValueProvider(map[string]string{"Name": "Grace"})
	low := newSpyValueProvider(resolverTestValues)
	resolver := newReadingResolver(t, NewDefaultToken(), high, low)

	if got := mustResolveToString(t, resolver, "${Name} ${Db:Password}"); got != "Grace p@ss" {
		t.Errorf("Resolve = %q, want %q", got, "Grace p@ss")
	}

	if want := []string{"Name", "Db:Password"}; !slices.Equal(high.tryGetBytesCalls, want) {
		t.Errorf("high calls = %q, want %q", high.tryGetBytesCalls, want)
	}
	if want := []string{"Db:Password"}; !slices.Equal(low.tryGetBytesCalls, want) {
		t.Errorf("low calls = %q, want %q", low.tryGetBytesCalls, want)
	}
}

func TestResolve_MultipleProviders_NoneHasTheKey_FailsNotFound(t *testing.T) {
	resolver := newReadingResolver(t, NewDefaultToken(),
		newMapValueProvider(map[string]string{"Name": "Grace"}),
		newMapValueProvider(resolverTestValues))

	_, err := resolveToString(resolver, "${Name} ${missing}", 1024)

	requireKeyErrorAt(t, err, "missing", KeyNotFound, 8)
}

func TestResolve_MultipleProviders_ValueTooLargeInTheFirstProvider_DoesNotFallThrough(t *testing.T) {
	high := newMapValueProvider(map[string]string{"Name": "Grace Hopper"})
	low := newSpyValueProvider(resolverTestValues)
	resolver := newReadingResolver(t, NewDefaultToken(), high, low)

	_, err := resolveToString(resolver, "${Name}", 5)

	requireDestinationTooSmall(t, err)
	if len(low.tryGetBytesCalls) != 0 {
		t.Errorf("low calls = %q, want none", low.tryGetBytesCalls)
	}
}

func TestResolve_IgnoreUnresolvablePlaceholders_CopiesMissingItemsUnchanged(t *testing.T) {
	tests := []struct{ source, expected string }{
		{"${missing}", "${missing}"},
		{"a ${ missing } b ${Name}", "a ${ missing } b Ada"},
		{"${Name}${missing}${Name}", "Ada${missing}Ada"},
		{"é ${missing} ${Unicode}", "é ${missing} café"},
	}
	for _, tc := range tests {
		t.Run(tc.source, func(t *testing.T) {
			resolver := newValuesResolver(t)
			resolver.ignoreUnresolvablePlaceholders = true

			if got := mustResolveToString(t, resolver, tc.source); got != tc.expected {
				t.Errorf("Resolve(%q) = %q, want %q", tc.source, got, tc.expected)
			}
		})
	}
}

func TestResolve_IgnoreUnresolvablePlaceholders_CopiesTheTokensOwnSequences(t *testing.T) {
	resolver := newReadingResolver(t, mustCustomToken(t, "{{", "}}", ""), newMapValueProvider(resolverTestValues))
	resolver.ignoreUnresolvablePlaceholders = true

	if got := mustResolveToString(t, resolver, "{{Name}} {{ missing }}"); got != "Ada {{ missing }}" {
		t.Errorf("Resolve = %q, want %q", got, "Ada {{ missing }}")
	}
}

func TestResolve_IgnoreUnresolvablePlaceholders_KeyNotReadByTheReader_StillFails(t *testing.T) {
	reader, _ := NewConfigurationItemReader(NewDefaultToken())
	spy := newSpyValueProvider(resolverTestValues)
	resolver, err := NewConfigurationItemResolver(NewDefaultToken(), reader, spy)
	if err != nil {
		t.Fatal(err)
	}
	resolver = resolver.WithIgnoreUnresolvablePlaceholders(true)
	reader.ReadKeysString("${Name}")

	_, err = resolveToString(resolver, "${Name} ${Db:Password}", 1024)

	requireKeyErrorAt(t, err, "Db:Password", KeyNotAllowed, 8)
	if want := []string{"Name"}; !slices.Equal(spy.tryGetBytesCalls, want) {
		t.Errorf("calls = %q, want %q", spy.tryGetBytesCalls, want)
	}
}

func TestResolve_IgnoreUnresolvablePlaceholders_ProviderErrorStillPropagates(t *testing.T) {
	spy := newSpyValueProvider(resolverTestValues)
	spy.err = &ConfigurationKeyError{Key: "Name", Code: KeyValueUnstable}
	resolver := newReadingResolver(t, NewDefaultToken(), spy)
	resolver.ignoreUnresolvablePlaceholders = true

	_, err := resolveToString(resolver, "${Name}", 1024)

	var keyErr *ConfigurationKeyError
	if !errors.As(err, &keyErr) || keyErr.Code != KeyValueUnstable {
		t.Errorf("err = %v, want a ValueUnstable *ConfigurationKeyError", err)
	}
}

func TestResolve_IgnoreUnresolvablePlaceholders_DestinationTooSmallForTheItem_FailsAndClearsDestination(t *testing.T) {
	for _, destinationLength := range []int{9, 13} {
		resolver := newValuesResolver(t)
		resolver.ignoreUnresolvablePlaceholders = true
		destination := filledWith('#', destinationLength)

		_, err := resolver.Resolve(context.Background(), []byte("Ada ${missing}"), destination)

		requireDestinationTooSmall(t, err)
		requireWiped(t, destination)
	}
}

func TestResolve_IgnoreUnresolvablePlaceholders_IsOffByDefault(t *testing.T) {
	_, resolver, _ := newAllowListed(t)

	if resolver.IgnoreUnresolvablePlaceholders() {
		t.Error("IgnoreUnresolvablePlaceholders() = true, want false")
	}
}

func TestResolve_KeysReadFromATrustedTemplate_AreResolvedInAnotherSource(t *testing.T) {
	reader, resolver, _ := newAllowListed(t)
	reader.ReadKeysString("${Name} ${ Db:Password }")

	if got := mustResolveToString(t, resolver, "${Db:Password} for ${Name}"); got != "p@ss for Ada" {
		t.Errorf("Resolve = %q, want %q", got, "p@ss for Ada")
	}
}

func TestResolve_KeyNotReadByTheReader_FailsWithoutAskingTheProvider(t *testing.T) {
	tests := []struct {
		source, rejectedKey string
		byteIndex           int
	}{
		{"${Db:Password}", "Db:Password", 0},
		{"${Name} then ${Db:Password}", "Db:Password", 13},
		{"${name}", "name", 0},
		{"ü ${ Db:Password }", "Db:Password", 3},
	}
	for _, tc := range tests {
		t.Run(tc.source, func(t *testing.T) {
			reader, resolver, spy := newAllowListed(t)
			reader.ReadKeysString("${Name}")
			destination := filledWith('#', 64)

			_, err := resolver.Resolve(context.Background(), []byte(tc.source), destination)

			requireKeyErrorAt(t, err, tc.rejectedKey, KeyNotAllowed, tc.byteIndex)
			if slices.Contains(spy.tryGetBytesCalls, tc.rejectedKey) {
				t.Errorf("the provider was asked for %q", tc.rejectedKey)
			}
			requireWiped(t, destination)
		})
	}
}

func TestResolve_BeforeAnyKeysAreRead_ResolvesOnlyTextWithoutItems(t *testing.T) {
	_, resolver, spy := newAllowListed(t)

	if got := mustResolveToString(t, resolver, "plain ${} text"); got != "plain ${} text" {
		t.Errorf("Resolve = %q, want it unchanged", got)
	}
	_, err := resolveToString(resolver, "${Name}", 1024)
	var keyErr *ConfigurationKeyError
	if !errors.As(err, &keyErr) {
		t.Errorf("err = %v, want a *ConfigurationKeyError", err)
	}
	if len(spy.tryGetBytesCalls) != 0 {
		t.Errorf("calls = %q, want none", spy.tryGetBytesCalls)
	}
}

func TestResolve_UsesTheReadersMostRecentKeys(t *testing.T) {
	reader, resolver, _ := newAllowListed(t)
	reader.ReadKeysString("${Name}")
	if got := mustResolveToString(t, resolver, "${Name}"); got != "Ada" {
		t.Fatalf("Resolve = %q, want Ada", got)
	}

	reader.ReadKeysString("${value2}")

	if got := mustResolveToString(t, resolver, "${value2}"); got != "TWO" {
		t.Errorf("Resolve = %q, want TWO", got)
	}
	_, err := resolveToString(resolver, "${Name}", 1024)
	var keyErr *ConfigurationKeyError
	if !errors.As(err, &keyErr) {
		t.Errorf("err = %v, want a *ConfigurationKeyError", err)
	}
}

func TestResolve_MissingKey_FailsAndClearsDestination(t *testing.T) {
	tests := []struct {
		source, missingKey string
		sourceIndex        int
	}{
		{"${missing}", "missing", 0},
		{"${Name} then ${ missing }", "missing", 13},
		{"${name}", "name", 0},
		{"${a${Name}}", "a${Name", 0},
		{"é ${missing}", "missing", 3},
	}
	resolver := newValuesResolver(t)
	for _, tc := range tests {
		t.Run(tc.source, func(t *testing.T) {
			destination := filledWith('#', 64)

			_, err := resolver.Resolve(context.Background(), []byte(tc.source), destination)

			requireKeyErrorAt(t, err, tc.missingKey, KeyNotFound, tc.sourceIndex)
			requireWiped(t, destination)
		})
	}
}

func TestResolve_DestinationTooSmall_FailsAndClearsDestination(t *testing.T) {
	tests := []struct {
		source            string
		destinationLength int
	}{
		{"literal too long", 4},
		{"ab ${Name}", 2},
		{"ab ${Name}", 5},
		{"${Name} trailing text", 6},
		{"${Unicode}", 4},
		{"${Db:Password} ${Name}", 6},
		{"x", 0},
	}
	resolver := newValuesResolver(t)
	for _, tc := range tests {
		destination := filledWith('#', tc.destinationLength)

		_, err := resolver.Resolve(context.Background(), []byte(tc.source), destination)

		requireDestinationTooSmall(t, err)
		requireWiped(t, destination)
	}
}

func TestResolve_ProviderFails_PropagatesAndClearsDestination(t *testing.T) {
	providerErr := errors.New("provider failed")
	spy := newSpyValueProvider(resolverTestValues)
	spy.err = providerErr
	resolver := newReadingResolver(t, NewDefaultToken(), spy)
	destination := filledWith('#', 16)

	_, err := resolver.Resolve(context.Background(), []byte("ab ${Name}"), destination)

	if !errors.Is(err, providerErr) {
		t.Errorf("err = %v, want the provider's error", err)
	}
	requireWiped(t, destination)
}

func TestResolve_EscapedStartSequence_IsCopiedWithoutTheEscape(t *testing.T) {
	tests := []struct{ source, expected string }{
		{"$${Name}", "${Name}"},
		{"$${", "${"},
		{"$${Name} is ${Name}", "${Name} is Ada"},
		{"$$${Name}", "$${Name}"},
		{"$${a ${Name}}", "${a Ada}"},
		{"$ ${Name} $$", "$ Ada $$"},
		{"é $${Unicode}", "é ${Unicode}"},
	}
	resolver := newValuesResolver(t)
	for _, tc := range tests {
		t.Run(tc.source, func(t *testing.T) {
			if got := mustResolveToString(t, resolver, tc.source); got != tc.expected {
				t.Errorf("Resolve(%q) = %q, want %q", tc.source, got, tc.expected)
			}
		})
	}
}

func TestResolve_EscapedItem_IsNotAKeySoItNeedsNoPermission(t *testing.T) {
	reader, resolver, spy := newAllowListed(t)
	reader.ReadKeysString("${Name}")

	if got := mustResolveToString(t, resolver, "${Name} $${Db:Password}"); got != "Ada ${Db:Password}" {
		t.Errorf("Resolve = %q, want %q", got, "Ada ${Db:Password}")
	}
	if want := []string{"Name"}; !slices.Equal(spy.tryGetBytesCalls, want) {
		t.Errorf("calls = %q, want %q", spy.tryGetBytesCalls, want)
	}
}

func TestResolve_UsesTheTokensEscapeSequence(t *testing.T) {
	tests := []struct{ escape, source, expected string }{
		// .NET's null escape: "" is none.
		{"", `${{Name}} \{{Name}}`, `$Ada \Ada`},
		{`\`, `${{Name}} \{{Name}}`, `$Ada {{Name}}`},
	}
	for _, tc := range tests {
		t.Run(tc.escape, func(t *testing.T) {
			resolver := newReadingResolver(t, mustCustomToken(t, "{{", "}}", tc.escape), newMapValueProvider(resolverTestValues))

			if got := mustResolveToString(t, resolver, tc.source); got != tc.expected {
				t.Errorf("Resolve(%q) = %q, want %q", tc.source, got, tc.expected)
			}
		})
	}
}

func TestMaxResolutionDepth_DefaultsToOne_AndMustBePositive(t *testing.T) {
	_, resolver, _ := newAllowListed(t)

	if got := resolver.MaxResolutionDepth(); got != 1 {
		t.Errorf("MaxResolutionDepth() = %d, want 1", got)
	}
	for _, depth := range []int{0, -1} {
		if copied, err := resolver.WithMaxResolutionDepth(depth); err == nil || copied != nil {
			t.Errorf("WithMaxResolutionDepth(%d) = %v, %v; want an error", depth, copied, err)
		}
	}
	if resolver.MaxResolutionDepth() != 1 {
		t.Error("WithMaxResolutionDepth changed the resolver it was called on")
	}
}

func TestResolve_ItemsInValues_AreResolvedUpToTheMaximumDepth(t *testing.T) {
	tests := []struct {
		depth            int
		source, expected string
	}{
		{1, "${Url}", "https://${Host}:${Port}/"},
		{2, "${Url}", "https://${Region}.db.internal:5432/"},
		{3, "${Url}", "https://eu.db.internal:5432/"},
		{10, "go ${Url} now", "go https://eu.db.internal:5432/ now"},
		{1, "${Escaped}", "$${Region}"},
		{2, "${Escaped}", "${Region}"},
		{2, "${Ping}", "${Ping}"},
		{2, "${Port}${Host}", "5432eu.db.internal"},
	}
	for _, tc := range tests {
		resolver := newNestedResolver(t, tc.depth)

		if got := mustResolveToString(t, resolver, tc.source); got != tc.expected {
			t.Errorf("depth %d: Resolve(%q) = %q, want %q", tc.depth, tc.source, got, tc.expected)
		}
	}
}

func TestResolve_ValueThatLeadsBackToItsKey_FailsCycleAndClearsDestination(t *testing.T) {
	tests := []struct {
		depth       int
		source, key string
		sourceIndex int
	}{
		{2, "${Self}", "Self", 0},
		{5, "x ${Self}", "Self", 2},
		{3, "${Ping}", "Ping", 0},
		{10, "ab ${Pong}", "Pong", 3},
	}
	for _, tc := range tests {
		t.Run(tc.source, func(t *testing.T) {
			resolver := newNestedResolver(t, tc.depth)
			destination := filledWith('#', 256)

			_, err := resolver.Resolve(context.Background(), []byte(tc.source), destination)

			requireKeyErrorAt(t, err, tc.key, KeyCycle, tc.sourceIndex)
			requireWiped(t, destination)
		})
	}
}

func TestResolve_KeyInAValue_MustBeAllowed(t *testing.T) {
	spy := newSpyValueProvider(nestedTestValues)
	resolver := newReadingResolver(t, NewDefaultToken(), spy)
	resolver.maxResolutionDepth = 3

	_, err := resolveToString(resolver, "go ${Host}", 1024)

	requireKeyErrorAt(t, err, "Region", KeyNotAllowed, 3)
	if want := []string{"Host"}; !slices.Equal(spy.tryGetBytesCalls, want) {
		t.Errorf("calls = %q, want %q", spy.tryGetBytesCalls, want)
	}
}

func TestResolve_MissingKeyInAValue_FailsWithTheSourceItemsIndex_OrIsKeptWhenIgnored(t *testing.T) {
	strict := newNestedResolver(t, 2)
	lenient := newNestedResolver(t, 2)
	lenient.ignoreUnresolvablePlaceholders = true

	_, err := resolveToString(strict, "é ${Missing}", 1024)

	requireKeyErrorAt(t, err, "Nope", KeyNotFound, 3)
	if got := mustResolveToString(t, lenient, "é ${Missing}"); got != "é [${ Nope }]" {
		t.Errorf("lenient Resolve = %q, want %q", got, "é [${ Nope }]")
	}
}

func TestResolve_ValueThatShrinksWhenResolved_LeavesNoTraceOfTheRawValue(t *testing.T) {
	resolver := newNestedResolver(t, 2)
	destination := filledWith('#', 64)

	written, err := resolver.Resolve(context.Background(), []byte("${Shrinks}"), destination)

	if err != nil {
		t.Fatal(err)
	}
	if got := string(destination[:written]); got != "eu!" {
		t.Errorf("resolved = %q, want eu!", got)
	}
	if bytes.Contains(destination, []byte("Region")) {
		t.Errorf("destination %q still holds the raw value", destination)
	}
	raw := len("${Region}!")
	if got, want := string(destination[raw:]), strings.Repeat("#", 64-raw); got != want {
		t.Errorf("destination after the raw value = %q, want it untouched", got)
	}
}

func TestResolve_ItemsInValues_AreWrittenWithoutReadingValuesAsStrings(t *testing.T) {
	spy := newSpyValueProvider(nestedTestValues)
	resolver := newReadingResolver(t, NewDefaultToken(), spy)
	resolver.maxResolutionDepth = 3
	resolver.alsoAllowed = nestedTestKeys()

	if got := mustResolveToString(t, resolver, "${Url}"); got != "https://eu.db.internal:5432/" {
		t.Errorf("Resolve = %q, want %q", got, "https://eu.db.internal:5432/")
	}

	if want := []string{"Url", "Host", "Region", "Port"}; !slices.Equal(spy.tryGetBytesCalls, want) {
		t.Errorf("calls = %q, want %q", spy.tryGetBytesCalls, want)
	}
	if len(spy.tryGetValueCalls) != 0 {
		t.Errorf("TryGetValue calls = %q, want none", spy.tryGetValueCalls)
	}
}
