package googlekms

import (
	"bytes"
	"os"
	"testing"

	kms "cloud.google.com/go/kms/apiv1"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/internal/kmstest"
)

// Real calls against a symmetric Cloud KMS key the caller provides, named in google.test.properties
// at the repository root (or the environment; see configuredKey). Credentials come from Application
// Default Credentials (an attached service account, workload identity federation, or gcloud):
//
//	gcloud auth application-default login
//	go test -run TestGoogleKMSIntegration -v ./...
//
// Without the key every test here is reported as skipped - never as passed - the same variable the
// .NET, Java, Python and Node integration tests read. Once it is named, a failing call - or a value
// that isn't a key's resource name - is a test failure. The identity needs
// roles/cloudkms.cryptoKeyEncrypterDecrypter on the key; the tests never create, change or destroy a
// key. See docs/how-to/run-google-kms-integration-tests.md.

const (
	keyNameVariable    = "HKDFGUARD_TEST_GOOGLE_KMS_KEY_NAME"
	settingsFile       = "google.test.properties"
	integrationContext = "hkdfguard.integrationtest"
)

// settings is the settings file at the repository root - the root module's directory, two above
// this package's, where go test runs - as NAME=value lines, '#' and '!' starting a comment; empty
// if there is none. This repository's counterpart of hkdfguard-dotnet's google.runsettings, and the
// same file as hkdfguard-java's, hkdfguard-python's and hkdfguard-node's: a local file, ignored by
// git, naming the key only - Application Default Credentials sign in with gcloud, so no credential
// ever goes in it.
func settings(t *testing.T) map[string]string {
	t.Helper()
	return kmstest.Settings(t, settingsFile)
}

// configuredKey is the real key, from the environment, else from the settings file; it skips the
// test unless one names it. A value that isn't a key's resource name (a placeholder left in place,
// say) fails the test, naming the variable.
func configuredKey(t *testing.T) string {
	t.Helper()
	value := os.Getenv(keyNameVariable)
	if value == "" {
		value = settings(t)[keyNameVariable]
	}
	if value == "" {
		t.Skipf("Set %s to a symmetric Cloud KMS key, in %s at the repository root or the environment, to run the Google Cloud KMS integration tests.",
			keyNameVariable, settingsFile)
	}
	if !isKeyName(value) {
		t.Fatalf("%s is %q, which isn't a key's resource name. Replace the placeholders in %s with your project, key ring and key. "+
			"See docs/how-to/run-google-kms-integration-tests.md.", keyNameVariable, value, settingsFile)
	}
	return value
}

// integrationWrappers is a wrapper over the configured key for each context, sharing one client the
// test creates as an application would and closes when it ends; it skips the test when no key is
// configured.
func integrationWrappers(t *testing.T, contexts ...string) []*KeyWrapper {
	t.Helper()
	name := configuredKey(t)
	client, err := kms.NewKeyManagementClient(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	var wrappers []*KeyWrapper
	for _, context := range contexts {
		wrappers = append(wrappers, newWrapperOver(t, client, name, Options{Context: context}))
	}
	return wrappers
}

func TestGoogleKMSIntegration_RoundTripsA32ByteDEKThroughWrapAndUnwrap(t *testing.T) {
	wrapper := integrationWrappers(t, integrationContext)[0]
	dek := random(32)
	revealed := make([]byte, 32)
	if n, err := wrapper.Unwrap(t.Context(), wrapWith(t, wrapper, dek), revealed); err != nil || n != 32 || !bytes.Equal(revealed, dek) {
		t.Fatalf("%d, %v; want the DEK", n, err)
	}
}

func TestGoogleKMSIntegration_GeneratesAWrappedDEKThatReveals(t *testing.T) {
	wrapper := integrationWrappers(t, integrationContext)[0]
	revealed := make([]byte, 32)
	if n, err := wrapper.Unwrap(t.Context(), generate(t, wrapper), revealed); err != nil || n != 32 || hkdfguard.IsZero(revealed) {
		t.Fatalf("%d, %v; want 32 non-zero bytes", n, err)
	}
}

func TestGoogleKMSIntegration_RefusesToUnwrapUnderAnotherContext(t *testing.T) {
	wrappers := integrationWrappers(t, integrationContext, integrationContext+".other")
	_, err := wrappers[1].Unwrap(t.Context(), generate(t, wrappers[0]), make([]byte, 32))
	requireCloudKMSError(t, err, "...INVALID_ARGUMENT")
}

func TestGoogleKMSIntegration_RefusesToUnwrapATamperedDEK(t *testing.T) {
	wrapper := integrationWrappers(t, integrationContext)[0]
	wrapped := generate(t, wrapper)
	wrapped[len(wrapped)-1] ^= 1
	_, err := wrapper.Unwrap(t.Context(), wrapped, make([]byte, 32))
	requireCloudKMSError(t, err, "Cloud KMS unwrap failed for key '"+wrapper.KeyName()+"'...")
}
