package azurekeyvault

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	"github.com/runsecure/hkdfguard-go"
)

// Real calls against an RSA wrapping key and an EC P-256 signing key the caller provides, named in
// azure.test.properties at the repository root (or the environment; see configuredKeys).
// Credentials come from DefaultAzureCredential (environment, workload or managed identity, Azure
// CLI, ...):
//
//	az login
//	go test -run TestAzureKeyVaultIntegration -v ./...
//
// Without both keys every test here is reported as skipped - never as passed - the same variables
// the .NET, Java, Python and Node integration tests read. Once they are named, a failing call - or a
// value that isn't a key identifier - is a test failure. The identity needs wrapKey, unwrapKey, sign
// and verify on the keys; the tests never create, change or delete a key. See
// docs/how-to/run-azure-key-vault-integration-tests.md.

const (
	wrappingKeyVariable = "HKDFGUARD_TEST_AZURE_WRAP_KEY_ID"
	signingKeyVariable  = "HKDFGUARD_TEST_AZURE_SIGN_KEY_ID"
	settingsFile        = "azure.test.properties"
	integrationContext  = "hkdfguard.integrationtest"
)

// settings is the settings file at the repository root - the root module's directory, two above
// this package's, where go test runs - as NAME=value lines, '#' and '!' starting a comment; empty
// if there is none. This repository's counterpart of hkdfguard-dotnet's azure.runsettings, and the
// same file as hkdfguard-java's, hkdfguard-python's and hkdfguard-node's: a local file, ignored by
// git, naming keys only - DefaultAzureCredential signs in with az login, so no credential ever goes
// in it.
func settings(t *testing.T) map[string]string {
	t.Helper()
	values := map[string]string{}
	file, err := os.Open(filepath.Join("..", "..", settingsFile))
	if errors.Is(err, os.ErrNotExist) {
		return values
	}
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		name, value, found := strings.Cut(line, "=")
		if line != "" && !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "!") && found && strings.TrimSpace(name) != "" {
			values[strings.TrimSpace(name)] = strings.TrimSpace(value)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return values
}

// configuredKeys is the real wrapping and signing keys, each from the environment, else from the
// settings file; it skips the test unless both are given. A value that isn't a key identifier (a
// placeholder left in place, say) fails the test, naming the variable.
func configuredKeys(t *testing.T) (string, string) {
	t.Helper()
	file := settings(t)
	var keys []string
	for _, name := range []string{wrappingKeyVariable, signingKeyVariable} {
		value := os.Getenv(name)
		if value == "" {
			value = file[name]
		}
		if value == "" {
			t.Skipf("Set %s and %s, in %s at the repository root or the environment, to run the Azure Key Vault integration tests.",
				wrappingKeyVariable, signingKeyVariable, settingsFile)
		}
		if _, err := parseKeyID(value); err != nil {
			t.Fatalf("%s is %q, which isn't a key identifier. See docs/how-to/run-azure-key-vault-integration-tests.md.", name, value)
		}
		keys = append(keys, value)
	}
	return keys[0], keys[1]
}

// integrationWrapper is a wrapper over the configured keys, with a credential the test creates as an
// application would; it skips the test when no keys are configured.
func integrationWrapper(t *testing.T, context string) *KeyWrapper {
	t.Helper()
	wrapping, signing := configuredKeys(t)
	credential, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		t.Fatal(err)
	}
	wrapper, err := New(wrapping, signing, credential, Options{Context: context})
	if err != nil {
		t.Fatal(err)
	}
	return wrapper
}

func generate(t *testing.T, wrapper *KeyWrapper) []byte {
	t.Helper()
	wrapped := make([]byte, hkdfguard.MaxWrappedKeyBytes)
	n, err := wrapper.GenerateAndWrap(t.Context(), wrapped)
	if err != nil {
		t.Fatal(err)
	}
	return wrapped[:n]
}

func TestAzureKeyVaultIntegration_RoundTripsA32ByteDEKThroughWrapAndUnwrap(t *testing.T) {
	wrapper := integrationWrapper(t, integrationContext)
	dek := random(32)
	revealed := make([]byte, 32)
	if n, err := wrapper.Unwrap(t.Context(), wrapWith(t, wrapper, dek), revealed); err != nil || n != 32 || !bytes.Equal(revealed, dek) {
		t.Fatalf("%d, %v; want the DEK", n, err)
	}
}

func TestAzureKeyVaultIntegration_GeneratesAWrappedDEKThatReveals(t *testing.T) {
	wrapper := integrationWrapper(t, integrationContext)
	revealed := make([]byte, 32)
	if n, err := wrapper.Unwrap(t.Context(), generate(t, wrapper), revealed); err != nil || n != 32 || hkdfguard.IsZero(revealed) {
		t.Fatalf("%d, %v; want 32 non-zero bytes", n, err)
	}
}

func TestAzureKeyVaultIntegration_RefusesToUnwrapUnderAnotherContext(t *testing.T) {
	wrapper := integrationWrapper(t, integrationContext)
	other := integrationWrapper(t, integrationContext+".other")
	_, err := other.Unwrap(t.Context(), generate(t, wrapper), make([]byte, 32))
	requireKeyVaultError(t, err, "...signature doesn't verify")
}

func TestAzureKeyVaultIntegration_RefusesToUnwrapATamperedDEK(t *testing.T) {
	wrapper := integrationWrapper(t, integrationContext)
	wrapped := generate(t, wrapper)
	wrapped[headerLength] ^= 1 // the first byte of the RSA ciphertext
	_, err := wrapper.Unwrap(t.Context(), wrapped, make([]byte, 32))
	requireKeyVaultError(t, err, "...signature doesn't verify")
}
