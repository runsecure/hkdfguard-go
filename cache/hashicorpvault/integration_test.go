package hashicorpvault

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/vault/api"

	"github.com/runsecure/hkdfguard-go/cache"
)

// Real reads of a secret the caller provides, in a KV version 2 engine mounted at "secret" (a dev
// server's default), with a token the caller provides:
//
//	vault kv put secret/hkdfguard/test value=s3cret
//	HKDFGUARD_TEST_VAULT_ADDR=https://127.0.0.1:8200 HKDFGUARD_TEST_VAULT_TOKEN=... \
//	HKDFGUARD_TEST_VAULT_CACERT=/path/to/vault-ca.pem HKDFGUARD_TEST_VAULT_SECRET_NAME=hkdfguard/test#value \
//	go test -run TestVaultIntegration -v ./...
//
// Without HKDFGUARD_TEST_VAULT_SECRET_NAME every test here is reported as skipped - never as passed
// - the same variables the .NET integration tests read (hkdfguard-dotnet's vault.runsettings).
// HKDFGUARD_TEST_VAULT_CACERT is needed only for a server certificate the operating system doesn't
// trust. The token needs only read on that secret's path; the tests never list, write or delete.
//
// To check what the secret holds, not just that it holds something, set
// HKDFGUARD_TEST_VAULT_SECRET_JSON to the JSON object of keys it is expected to hold: each is then
// read as "path#key", the path being HKDFGUARD_TEST_VAULT_SECRET_NAME's, and compared with it.
// VAULT_* variables are ignored (see TestMain): the client is configured from these alone.

const (
	addressVariable      = "HKDFGUARD_TEST_VAULT_ADDR"
	tokenVariable        = "HKDFGUARD_TEST_VAULT_TOKEN"
	caCertVariable       = "HKDFGUARD_TEST_VAULT_CACERT"
	secretNameVariable   = "HKDFGUARD_TEST_VAULT_SECRET_NAME"
	expectedJSONVariable = "HKDFGUARD_TEST_VAULT_SECRET_JSON"
)

// configuredSecretName is the secret to read, skipping the test unless one is named.
func configuredSecretName(t *testing.T) string {
	t.Helper()
	name := os.Getenv(secretNameVariable)
	if name == "" {
		t.Skipf("Set %s (with %s and %s) to a secret's path#key to run the Vault cache integration tests.",
			secretNameVariable, addressVariable, tokenVariable)
	}
	return name
}

// integrationCache is a cache over the configured Vault's KV engine at "secret", through a client
// made as an application would make one.
func integrationCache(t *testing.T) *cache.RemoteCache {
	t.Helper()
	config := api.DefaultConfig()
	if config.Error != nil {
		t.Fatal(config.Error)
	}
	config.Address = "https://127.0.0.1:8200"
	if address := os.Getenv(addressVariable); address != "" {
		config.Address = address
	}
	config.DisableRedirects = true
	if path := os.Getenv(caCertVariable); path != "" {
		if err := config.ConfigureTLS(&api.TLSConfig{CACert: path}); err != nil {
			t.Fatalf("%s: %v", caCertVariable, err)
		}
	}
	client, err := api.NewClient(config)
	if err != nil {
		t.Fatal(err)
	}
	token := os.Getenv(tokenVariable)
	if token == "" {
		t.Fatalf("%s is set, but %s isn't: set it to a token that may read the secret.", secretNameVariable, tokenVariable)
	}
	client.SetToken(token)

	c, err := New(client, newTestRing(t), Options{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// expectedKeys is the JSON object HKDFGUARD_TEST_VAULT_SECRET_JSON names, as each key's expected
// value: a string as itself, a number, true or false as its JSON text. It skips the test when unset.
func expectedKeys(t *testing.T) map[string]string {
	t.Helper()
	document := os.Getenv(expectedJSONVariable)
	if document == "" {
		t.Skipf("Set %s and %s to check a secret's keys.", secretNameVariable, expectedJSONVariable)
	}
	decoder := json.NewDecoder(strings.NewReader(document))
	decoder.UseNumber()
	var members map[string]any
	if err := decoder.Decode(&members); err != nil {
		t.Fatalf("%s isn't a JSON object: %v", expectedJSONVariable, err)
	}
	expected := map[string]string{}
	for key, value := range members {
		switch v := value.(type) {
		case string:
			expected[key] = v
		case json.Number:
			expected[key] = v.String()
		case bool:
			expected[key] = strconv.FormatBool(v)
		}
	}
	return expected
}

func TestVaultIntegration_Decrypt_RevealsTheSecret(t *testing.T) {
	name := configuredSecretName(t)
	c := integrationCache(t)

	max, ok, err := c.MaxDecryptedLength(t.Context(), name)
	if err != nil || !ok || max <= 0 {
		t.Fatalf("MaxDecryptedLength: %d, %v, %v", max, ok, err)
	}
	if n, err := c.Decrypt(t.Context(), name, make([]byte, max)); err != nil || n <= 0 {
		t.Fatalf("Decrypt: %d, %v", n, err)
	}
}

func TestVaultIntegration_Decrypt_RevealsEveryKeyTheSecretHolds(t *testing.T) {
	path, _, _ := strings.Cut(configuredSecretName(t), "#")
	expected := expectedKeys(t)
	c := integrationCache(t)

	for key, want := range expected {
		result := make([]byte, len(want)+64)
		n, err := c.Decrypt(t.Context(), path+"#"+key, result)
		if err != nil || !bytes.Equal(result[:n], []byte(want)) {
			t.Errorf("%s#%s: got %d bytes, %v", path, key, n, err)
		}
	}
	if n, err := c.Decrypt(t.Context(), path+"#no-such-key", make([]byte, 16)); n != 0 || err != nil {
		t.Fatalf("no-such-key: %d, %v", n, err)
	}
}

func TestVaultIntegration_Decrypt_OfASecretThatDoesNotExist_ReturnsZero(t *testing.T) {
	configuredSecretName(t)
	c := integrationCache(t)
	random := make([]byte, 16)
	_, _ = rand.Read(random)

	n, err := c.Decrypt(context.Background(), "hkdfguard/missing-"+hex.EncodeToString(random), make([]byte, 16))
	if n != 0 || err != nil {
		t.Fatalf("got %d, %v", n, err)
	}
}
