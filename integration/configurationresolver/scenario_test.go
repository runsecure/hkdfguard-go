package configurationresolver

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

// The port of the parts of .NET's JsonConfigurationScenarioTests that need only ported code: the
// "dictionary" provider is a map-backed ValueProviderBase, the template is held in memory instead
// of on disk, and the resolved JSON is loaded with encoding/json instead of
// Microsoft.Extensions.Configuration.

const scenarioTemplate = `{
  "ConnectionStrings": {
    "Default": "Host=${Database:Host};Port=${ Database:Port };Password=${Database:Password}"
  },
  "Greeting": "${Greeting} wörld",
  "Literal": "${} and $ {not an item}"
}`

var scenarioValues = map[string]string{
	"Database:Host":     "db.internal",
	"Database:Port":     "5432",
	"Database:Password": `s3cr\"t!`,
	"Greeting":          "héllo",
}

var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

func newScenarioResolver(t testing.TB, token *ConfigurationItemToken, template string) *ConfigurationItemResolver {
	return newTemplateResolver(t, token, newMapValueProvider(scenarioValues), template)
}

// loadScenarioJSON is the port of TemplateFile.LoadJson, for a JSON object of strings and objects.
func loadScenarioJSON(t testing.TB, resolved string) map[string]any {
	t.Helper()
	var configuration map[string]any
	if err := json.Unmarshal([]byte(resolved), &configuration); err != nil {
		t.Fatalf("the resolved template %q is not JSON: %v", resolved, err)
	}
	return configuration
}

func TestResolvedTemplate_LoadsAsConfiguration(t *testing.T) {
	resolver := newScenarioResolver(t, NewDefaultToken(), scenarioTemplate)

	configuration := loadScenarioJSON(t, mustResolveToString(t, resolver, scenarioTemplate))

	connectionStrings, _ := configuration["ConnectionStrings"].(map[string]any)
	if got, want := connectionStrings["Default"], `Host=db.internal;Port=5432;Password=s3cr"t!`; got != want {
		t.Errorf("ConnectionStrings:Default = %v, want %q", got, want)
	}
	if got, want := configuration["Greeting"], "héllo wörld"; got != want {
		t.Errorf("Greeting = %v, want %q", got, want)
	}
	if got, want := configuration["Literal"], "${} and $ {not an item}"; got != want {
		t.Errorf("Literal = %v, want %q", got, want)
	}
}

func TestReaderListsTheKeysInTheTemplateFile(t *testing.T) {
	reader := mustDefaultTokenReader(t)
	expected := []string{"Database:Host", "Database:Port", "Database:Password", "Greeting"}

	keys, err := reader.ReadKeysFrom(strings.NewReader(scenarioTemplate))
	if err != nil {
		t.Fatal(err)
	}

	requireKeys(t, keys, expected...)
	requireKeys(t, reader.Keys(), expected...)
	requireKeys(t, reader.ReadKeys([]byte(scenarioTemplate)), expected...)
}

func TestCustomToken_ResolvesOnlyItsOwnItems(t *testing.T) {
	template := `{ "Host": "{{Database:Host}}", "Kept": "${Database:Host}" }`
	resolver := newScenarioResolver(t, mustCustomToken(t, "{{", "}}", ""), template)

	configuration := loadScenarioJSON(t, mustResolveToString(t, resolver, template))

	if configuration["Host"] != "db.internal" || configuration["Kept"] != "${Database:Host}" {
		t.Errorf("configuration = %v, want Host db.internal and Kept ${Database:Host}", configuration)
	}
}

func TestTemplateWithByteOrderMark_ResolvesAndLoads(t *testing.T) {
	template := append(slices.Clone(utf8BOM), `{ "Host": "${Database:Host}" }`...)
	reader := mustDefaultTokenReader(t)
	keys, err := reader.ReadKeysFrom(bytes.NewReader(template))
	if err != nil {
		t.Fatal(err)
	}
	requireKeys(t, keys, "Database:Host")
	resolver, err := NewConfigurationItemResolver(NewDefaultToken(), reader, newMapValueProvider(scenarioValues))
	if err != nil {
		t.Fatal(err)
	}
	destination := make([]byte, 4096)

	written, err := resolver.Resolve(context.Background(), template, destination)

	if err != nil {
		t.Fatal(err)
	}
	// The byte order mark is copied like any other text, as .NET does; its JSON loader skips it.
	resolved := destination[:written]
	if !bytes.HasPrefix(resolved, utf8BOM) {
		t.Fatalf("resolved = %q, want it to keep the byte order mark", resolved)
	}
	if got := loadScenarioJSON(t, string(resolved[len(utf8BOM):]))["Host"]; got != "db.internal" {
		t.Errorf("Host = %v, want db.internal", got)
	}
}

func TestTemplateWithMissingValue_Fails(t *testing.T) {
	template := `{ "Value": "${Database:Missing}" }`
	resolver := newScenarioResolver(t, NewDefaultToken(), template)

	_, err := resolveToString(resolver, template, 4096)

	requireKeyErrorAt(t, err, "Database:Missing", KeyNotFound, strings.Index(template, "${"))
}

func TestDestinationTooSmallForAValue_FailsAndClearsTheSecret(t *testing.T) {
	template := "${Database:Password}${Database:Password}"
	resolver := newScenarioResolver(t, NewDefaultToken(), template)
	destination := make([]byte, len(`s3cr"t!`)+3)

	_, err := resolver.Resolve(context.Background(), []byte(template), destination)

	requireDestinationTooSmall(t, err)
	requireWiped(t, destination)
}

func TestDestinationTooSmallForTheTemplateText_FailsAndClearsTheDestination(t *testing.T) {
	resolver := newScenarioResolver(t, NewDefaultToken(), scenarioTemplate)
	destination := filledWith('#', strings.Index(scenarioTemplate, "${")-1)

	_, err := resolver.Resolve(context.Background(), []byte(scenarioTemplate), destination)

	requireDestinationTooSmall(t, err)
	requireWiped(t, destination)
}

func TestTemplateUsingAKeyOutsideTheTrustedTemplate_IsRejected(t *testing.T) {
	// The trusted template only asks for the host; a substituted template also asks for the password.
	trusted := `{ "Host": "${Database:Host}" }`
	injected := `{ "Host": "${Database:Host}", "Leak": "${Database:Password}" }`
	resolver := newScenarioResolver(t, NewDefaultToken(), trusted)

	if got := loadScenarioJSON(t, mustResolveToString(t, resolver, trusted))["Host"]; got != "db.internal" {
		t.Errorf("Host = %v, want db.internal", got)
	}

	destination := filledWith('#', 4096)
	_, err := resolver.Resolve(context.Background(), []byte(injected), destination)

	requireKeyErrorAt(t, err, "Database:Password", KeyNotAllowed, strings.Index(injected, "${Database:Password}"))
	requireWiped(t, destination)
}

func TestIgnoreUnresolvablePlaceholders_LeavesMissingItemsInTheLoadedConfiguration(t *testing.T) {
	template := `{ "Host": "${Database:Host}", "Optional": "${ Feature:Flag }" }`
	resolver := newScenarioResolver(t, NewDefaultToken(), template).WithIgnoreUnresolvablePlaceholders(true)

	configuration := loadScenarioJSON(t, mustResolveToString(t, resolver, template))

	if configuration["Host"] != "db.internal" || configuration["Optional"] != "${ Feature:Flag }" {
		t.Errorf("configuration = %v, want Host db.internal and Optional ${ Feature:Flag }", configuration)
	}
}

func TestUnterminatedItemInJson_RunsToTheNextClosingBrace(t *testing.T) {
	// JSON's own closing brace ends the item, so the key includes the JSON that follows it.
	template := `{ "Value": "${unterminated" }`
	resolver := newScenarioResolver(t, NewDefaultToken(), template)

	_, err := resolveToString(resolver, template, 4096)

	requireKeyErrorAt(t, err, `unterminated"`, KeyNotFound, strings.Index(template, "${"))
}

func TestValueThatBreaksJson_ProducesInvalidConfiguration(t *testing.T) {
	// Values are inserted as they are; the resolver does not escape them for JSON.
	template := `{ "Value": "${Quote}" }`
	resolver := newTemplateResolver(t, NewDefaultToken(), newMapValueProvider(map[string]string{"Quote": `a"b`}), template)

	resolved := mustResolveToString(t, resolver, template)

	if resolved != `{ "Value": "a"b" }` {
		t.Errorf("resolved = %q, want the value inserted unescaped", resolved)
	}
	if json.Valid([]byte(resolved)) {
		t.Errorf("resolved = %q is valid JSON, want it broken", resolved)
	}
}
