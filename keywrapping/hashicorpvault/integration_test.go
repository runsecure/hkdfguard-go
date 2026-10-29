package hashicorpvault

import (
	"bytes"
	"errors"
	"net/http"
	"os"
	"testing"

	"github.com/hashicorp/vault/api"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/internal/kmstest"
)

// Real calls against a transit key the caller provides, with a token the caller provides - on a
// dev server, the ones scripts/provision-vault-transit-test-key.sh creates and prints:
//
//	HKDFGUARD_TEST_VAULT_ADDR=http://127.0.0.1:8200 HKDFGUARD_TEST_VAULT_TOKEN=... \
//	HKDFGUARD_TEST_VAULT_TRANSIT_KEY=hkdfguard-test HKDFGUARD_TEST_VAULT_TRANSIT_OTHER_KEY=hkdfguard-test-other \
//	go test -run TestVaultTransitIntegration -v ./...
//
// Without HKDFGUARD_TEST_VAULT_TRANSIT_KEY every test here is reported as skipped - never as
// passed - the same variables the .NET integration tests read. Once it is set, a failing call, or
// a missing token, is a test failure. HKDFGUARD_TEST_VAULT_TRANSIT_MOUNT names a mount other than
// "transit", and HKDFGUARD_TEST_VAULT_CACERT a CA for a server certificate the operating system
// doesn't trust. The token needs only update on encrypt, decrypt and datakey/wrapped for the keys;
// the tests never create, rotate, read or delete a key. See
// docs/how-to/run-hashicorp-vault-transit-integration-tests.md.

const (
	transitKeyVariable      = "HKDFGUARD_TEST_VAULT_TRANSIT_KEY"
	transitOtherKeyVariable = "HKDFGUARD_TEST_VAULT_TRANSIT_OTHER_KEY"
	transitMountVariable    = "HKDFGUARD_TEST_VAULT_TRANSIT_MOUNT"
	vaultAddressVariable    = "HKDFGUARD_TEST_VAULT_ADDR"
	vaultTokenVariable      = "HKDFGUARD_TEST_VAULT_TOKEN"
	vaultCACertVariable     = "HKDFGUARD_TEST_VAULT_CACERT"
	vaultSettingsFile       = "vault.test.properties"
	integrationContext      = "hkdfguard.integrationtest"
)

// setting is a variable from the environment, else from vault.test.properties at the repository
// root - this repository's counterpart of hkdfguard-dotnet's vault.runsettings, ignored by git. The
// token is read from the environment only: the file names the server and keys, never a credential.
func setting(t *testing.T, name string) string {
	t.Helper()
	if value := os.Getenv(name); value != "" || name == vaultTokenVariable {
		return value
	}
	return kmstest.Settings(t, vaultSettingsFile)[name]
}

// configuredKey is the real transit key; it skips the test unless one is named.
func configuredKey(t *testing.T) string {
	t.Helper()
	key := setting(t, transitKeyVariable)
	if key == "" {
		t.Skipf("Set %s (with %s and %s) to a transit key, in the environment or %s at the repository root, to run the Vault transit integration tests.",
			transitKeyVariable, vaultAddressVariable, vaultTokenVariable, vaultSettingsFile)
	}
	return key
}

// integrationClient is a client for the configured Vault, made as an application would make one,
// with token; it fails the test when the address can't be used.
func integrationClient(t *testing.T, token string) *api.Client {
	t.Helper()
	config := api.DefaultConfig()
	if config.Error != nil {
		t.Fatal(config.Error)
	}
	config.Address = setting(t, vaultAddressVariable)
	if config.Address == "" {
		config.Address = "http://127.0.0.1:8200"
	}
	// Trusts HKDFGUARD_TEST_VAULT_CACERT, and only it, when set.
	if ca := setting(t, vaultCACertVariable); ca != "" {
		if err := config.ConfigureTLS(&api.TLSConfig{CACert: ca}); err != nil {
			t.Fatal(err)
		}
	}
	client, err := api.NewClient(config)
	if err != nil {
		t.Fatal(err)
	}
	client.SetToken(token)
	return client
}

// integrationWrapper is a wrapper over key (the configured key when "") with context, through a
// client with the configured token; it skips the test when no key is configured.
func integrationWrapper(t *testing.T, key, context string) *KeyWrapper {
	t.Helper()
	configured := configuredKey(t)
	if key == "" {
		key = configured
	}
	token := setting(t, vaultTokenVariable)
	if token == "" {
		t.Fatalf("%s is set, but %s isn't: set it to the token scripts/provision-vault-transit-test-key.sh printed.", transitKeyVariable, vaultTokenVariable)
	}
	wrapper, err := New(integrationClient(t, token), key, Options{MountPath: setting(t, transitMountVariable), Context: context})
	if err != nil {
		t.Fatal(err)
	}
	return wrapper
}

func TestVaultTransitIntegration_RoundTripsA32ByteDEKThroughWrapAndUnwrap(t *testing.T) {
	wrapper := integrationWrapper(t, "", integrationContext)
	dek := random(32)
	revealed := make([]byte, 32)
	if n, err := wrapper.Unwrap(t.Context(), wrapWith(t, wrapper, dek), revealed); err != nil || n != 32 || !bytes.Equal(revealed, dek) {
		t.Fatalf("%d, %v; want the DEK", n, err)
	}
}

func TestVaultTransitIntegration_GeneratesInVaultAWrappedDEKThatReveals(t *testing.T) {
	// No context: Vault generates the DEK with datakey/wrapped.
	wrapper := integrationWrapper(t, "", "")
	revealed := make([]byte, 32)
	if n, err := wrapper.Unwrap(t.Context(), generate(t, wrapper), revealed); err != nil || n != 32 || hkdfguard.IsZero(revealed) {
		t.Fatalf("%d, %v; want 32 non-zero bytes", n, err)
	}
}

func TestVaultTransitIntegration_GeneratesWithAContextAWrappedDEKThatReveals(t *testing.T) {
	wrapper := integrationWrapper(t, "", integrationContext)
	revealed := make([]byte, 32)
	if n, err := wrapper.Unwrap(t.Context(), generate(t, wrapper), revealed); err != nil || n != 32 || hkdfguard.IsZero(revealed) {
		t.Fatalf("%d, %v; want 32 non-zero bytes", n, err)
	}
}

func TestVaultTransitIntegration_RefusesToUnwrapUnderAnotherContextOrNone(t *testing.T) {
	wrapped := generate(t, integrationWrapper(t, "", integrationContext))
	for _, context := range []string{integrationContext + ".other", ""} {
		_, err := integrationWrapper(t, "", context).Unwrap(t.Context(), wrapped, make([]byte, 32))
		requireVaultError(t, err, "...Vault answered 400 Bad Request...")
	}
}

func TestVaultTransitIntegration_RefusesToUnwrapATamperedDEK(t *testing.T) {
	wrapper := integrationWrapper(t, "", integrationContext)
	wrapped := generate(t, wrapper)
	// Another base64 character, so it reaches Vault and fails there.
	if wrapped[12] == 'A' {
		wrapped[12] = 'B'
	} else {
		wrapped[12] = 'A'
	}
	_, err := wrapper.Unwrap(t.Context(), wrapped, make([]byte, 32))
	requireVaultError(t, err, "Vault transit unwrap failed for key '"+wrapper.KeyName()+"': Vault answered 400 Bad Request...")
}

func TestVaultTransitIntegration_RefusesToUnwrapUnderAnotherKey(t *testing.T) {
	configuredKey(t)
	other := setting(t, transitOtherKeyVariable)
	if other == "" {
		t.Skipf("Set %s to a second transit key to check one refuses the other's DEKs.", transitOtherKeyVariable)
	}
	wrapped := generate(t, integrationWrapper(t, "", integrationContext))
	_, err := integrationWrapper(t, other, integrationContext).Unwrap(t.Context(), wrapped, make([]byte, 32))
	requireVaultError(t, err, "...Vault answered 400 Bad Request...")
}

func TestVaultTransitIntegration_RefusesAnInvalidTokenWith403(t *testing.T) {
	key := configuredKey(t)
	wrapper, err := New(integrationClient(t, "hvs.not-a-real-token"), key, Options{MountPath: setting(t, transitMountVariable)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = wrapper.GenerateAndWrap(t.Context(), make([]byte, hkdfguard.MaxWrappedKeyBytes))
	requireVaultError(t, err, "...Vault answered 403 Forbidden...")
	var refusal *api.ResponseError
	if !errors.As(err, &refusal) || refusal.StatusCode != http.StatusForbidden {
		t.Errorf("got %v; want Vault's 403 as the cause", err)
	}
}
