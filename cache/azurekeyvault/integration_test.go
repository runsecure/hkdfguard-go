package azurekeyvault

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	"github.com/runsecure/hkdfguard-go/cache"
	"github.com/runsecure/hkdfguard-go/internal/kmstest"
)

// Real calls against a secret the caller provides, named in azure.test.properties at the repository
// root (or the environment; see configuredSecret). Credentials come from DefaultAzureCredential
// (environment, workload or managed identity, Azure CLI, ...):
//
//	az login
//	HKDFGUARD_TEST_AZURE_SECRET_ID=https://{vault}.vault.azure.net/secrets/{name} \
//	go test -run TestAzureKeyVaultSecretCacheIntegration -v ./...
//
// Without the variable every test here is reported as skipped - never as passed - the same variable
// the .NET integration tests read. The principal needs only get on secrets (the Key Vault Secrets
// User role); the tests never list, create, alter or delete a secret.
//
// To check what the secret holds, not just that it holds something, set
// HKDFGUARD_TEST_AZURE_SECRET_JSON to the JSON object it is expected to hold: the whole value and
// each member, read as "name#key", are then compared with it. Set
// HKDFGUARD_TEST_AZURE_SEPARATE_SECRETS=true as well when the vault also holds each member as a
// secret of its own, named by its key; those are then read and compared too.

const (
	secretIDVariable        = "HKDFGUARD_TEST_AZURE_SECRET_ID"
	expectedJSONVariable    = "HKDFGUARD_TEST_AZURE_SECRET_JSON"
	separateSecretsVariable = "HKDFGUARD_TEST_AZURE_SEPARATE_SECRETS"
	settingsFile            = "azure.test.properties"
)

// setting is the named setting from the environment, else from the settings file at the repository
// root - the counterpart of hkdfguard-dotnet's azure.runsettings, shared with the key wrapper's
// integration tests; "" if neither has it.
func setting(t *testing.T, name string) string {
	t.Helper()
	if value := os.Getenv(name); value != "" {
		return value
	}
	return kmstest.Settings(t, settingsFile)[name]
}

// configuredSecret is the vault URL and secret name of the configured secret identifier; it skips
// the test unless one is given, and fails it when the value isn't a secret identifier.
func configuredSecret(t *testing.T) (string, string) {
	t.Helper()
	id := setting(t, secretIDVariable)
	if id == "" {
		t.Skipf("Set %s to a secret's identifier, in %s at the repository root or the environment, to run the Azure Key Vault secret cache integration tests.",
			secretIDVariable, settingsFile)
	}
	u, err := url.Parse(id)
	if err != nil {
		u = &url.URL{}
	}
	segments := strings.Split(strings.Trim(u.Path, "/"), "/")
	if u.Scheme != "https" || u.Host == "" || len(segments) < 2 || len(segments) > 3 || segments[0] != "secrets" ||
		!IsValidSecretName(segments[1]) {
		t.Fatalf("%s is %q, which isn't a secret identifier: https://{vault}.vault.azure.net/secrets/{name}", secretIDVariable, id)
	}
	return "https://" + u.Host + "/", segments[1]
}

// expected is the JSON object the secret is expected to hold; it skips the test unless one is given.
func expected(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	text := setting(t, expectedJSONVariable)
	if text == "" {
		t.Skipf("Set %s and %s to check a secret's contents.", secretIDVariable, expectedJSONVariable)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal([]byte(text), &members); err != nil || members == nil {
		t.Fatalf("%s isn't a JSON object.", expectedJSONVariable)
	}
	return members
}

// expectedKeys is each member of the expected object as the cache reveals it under "name#key": a
// string as its text, a number, true or false as its JSON text; null, objects and arrays aren't keys.
func expectedKeys(t *testing.T, members map[string]json.RawMessage) map[string]string {
	t.Helper()
	keys := map[string]string{}
	for key, raw := range members {
		switch raw[0] {
		case '"':
			var s string
			if err := json.Unmarshal(raw, &s); err != nil {
				t.Fatal(err)
			}
			keys[key] = s
		case '{', '[', 'n':
		default:
			keys[key] = string(raw)
		}
	}
	return keys
}

// requireWholeValue checks whole is the expected object, compared as JSON, so whitespace the
// vault's copy has or lacks doesn't matter.
func requireWholeValue(t *testing.T, members map[string]json.RawMessage, whole string) {
	t.Helper()
	var want, got any
	text, _ := json.Marshal(members)
	if json.Unmarshal(text, &want) != nil || json.Unmarshal([]byte(whole), &got) != nil || !reflect.DeepEqual(want, got) {
		t.Fatal("The secret's whole value isn't the expected JSON object.")
	}
}

// integrationCache is a cache over the configured secret's vault, with a credential the test
// creates as an application would, and the secret's name; it skips the test when none is configured.
func integrationCache(t *testing.T) (*cache.RemoteCache, string) {
	t.Helper()
	vault, name := configuredSecret(t)
	credential, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(vault, credential, newRing(t), Options{})
	if err != nil {
		t.Fatal(err)
	}
	return c, name
}

func TestAzureKeyVaultSecretCacheIntegration_RevealsTheSecret(t *testing.T) {
	c, name := integrationCache(t)

	n, ok, err := c.MaxDecryptedLength(t.Context(), name)
	if err != nil || !ok {
		t.Fatalf("%v, %v; want the secret", ok, err)
	}
	result := make([]byte, n)
	if written, err := c.Decrypt(t.Context(), name, result); err != nil || written == 0 {
		t.Fatalf("%d, %v; want the secret", written, err)
	}
}

func TestAzureKeyVaultSecretCacheIntegration_RevealsTheExpectedWholeValue(t *testing.T) {
	c, name := integrationCache(t)
	members := expected(t)

	whole, ok := get(t, c, name)
	if !ok {
		t.Fatalf("Nothing is stored under '%s'.", name)
	}
	requireWholeValue(t, members, whole)
}

func TestAzureKeyVaultSecretCacheIntegration_RevealsEveryKeyTheSecretHolds(t *testing.T) {
	c, name := integrationCache(t)

	for key, value := range expectedKeys(t, expected(t)) {
		mustGet(t, c, name+"#"+key, value)
	}
	requireMissing(t, c, name+"#no-such-key")
}

func TestAzureKeyVaultSecretCacheIntegration_EachKeyIsAlsoASecretOfItsOwn_HoldingTheSameValue(t *testing.T) {
	c, _ := integrationCache(t)
	keys := expectedKeys(t, expected(t))
	if !strings.EqualFold(setting(t, separateSecretsVariable), "true") {
		t.Skipf("Set %s=true when the vault holds each expected key as a secret of its own.", separateSecretsVariable)
	}

	for key, value := range keys {
		if !IsValidSecretName(key) {
			t.Fatalf("'%s' can't be a Key Vault secret name.", key)
		}
		mustGet(t, c, key, value)
		// Key Vault matches secret names ignoring case, so the cache does too.
		mustGet(t, c, strings.ToUpper(key), value)
	}
}

func TestAzureKeyVaultSecretCacheIntegration_ASecretThatDoesNotExist_IsMissing(t *testing.T) {
	c, _ := integrationCache(t)
	random := make([]byte, 16)
	_, _ = rand.Read(random)

	requireMissing(t, c, "hkdfguard-missing-"+hex.EncodeToString(random))
}
