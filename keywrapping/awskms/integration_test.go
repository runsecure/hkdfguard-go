package awskms

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"

	"github.com/runsecure/hkdfguard-go"
)

// Real calls against a symmetric AWS KMS key the caller provides. The SDK resolves credentials and
// region the usual way (environment, shared config and credentials files, container or instance
// role):
//
//	HKDFGUARD_TEST_AWS_KMS_KEY_ID=arn:aws:kms:... go test -run TestAwsKmsIntegration -v ./...
//
// Without HKDFGUARD_TEST_AWS_KMS_KEY_ID every test here is reported as skipped - never as passed -
// the same variable the .NET, Java, Python and Node integration tests read. Once it names a key, a
// failing call is a test failure. The principal needs kms:Encrypt, kms:Decrypt and
// kms:GenerateDataKeyWithoutPlaintext on the key; the tests never create, alter or schedule
// deletion of a key. See docs/how-to/run-aws-kms-integration-tests.md.

const keyIDVariable = "HKDFGUARD_TEST_AWS_KMS_KEY_ID"

var integrationContext = map[string]string{"purpose": "hkdfguard.integrationtest"}

// integrationWrapper is a wrapper over the configured key, through a client the test creates as an
// application would; it skips the test when no key is configured.
func integrationWrapper(t *testing.T, encryptionContext map[string]string) *KeyWrapper {
	t.Helper()
	keyID := os.Getenv(keyIDVariable)
	if keyID == "" {
		t.Skipf("Set %s to a symmetric KMS key to run the AWS KMS integration tests.", keyIDVariable)
	}
	cfg, err := config.LoadDefaultConfig(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	wrapper, err := New(kms.NewFromConfig(cfg), keyID, Options{EncryptionContext: encryptionContext})
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

func TestAwsKmsIntegration_RoundTripsA32ByteDEKThroughWrapAndUnwrap(t *testing.T) {
	wrapper := integrationWrapper(t, integrationContext)
	dek := random(32)
	wrapped := wrapWith(t, wrapper, dek)
	revealed := make([]byte, 32)
	if n, err := wrapper.Unwrap(t.Context(), wrapped, revealed); err != nil || n != 32 || !bytes.Equal(revealed, dek) {
		t.Fatalf("%d, %v; want the DEK", n, err)
	}
}

func TestAwsKmsIntegration_GeneratesAWrappedDEKThatReveals(t *testing.T) {
	wrapper := integrationWrapper(t, integrationContext)
	revealed := make([]byte, 32)
	if n, err := wrapper.Unwrap(t.Context(), generate(t, wrapper), revealed); err != nil || n != 32 || hkdfguard.IsZero(revealed) {
		t.Fatalf("%d, %v; want 32 non-zero bytes", n, err)
	}
}

func TestAwsKmsIntegration_RefusesToUnwrapUnderAnotherEncryptionContext(t *testing.T) {
	wrapper := integrationWrapper(t, integrationContext)
	other := integrationWrapper(t, map[string]string{"purpose": "hkdfguard.integrationtest.other"})
	_, err := other.Unwrap(t.Context(), generate(t, wrapper), make([]byte, 32))
	if !errors.Is(err, ErrKMS) {
		t.Fatalf("got %v; want an *awskms.Error", err)
	}
}

func TestAwsKmsIntegration_RefusesToUnwrapATamperedDEK(t *testing.T) {
	wrapper := integrationWrapper(t, integrationContext)
	wrapped := generate(t, wrapper)
	wrapped[len(wrapped)-1] ^= 1
	_, err := wrapper.Unwrap(t.Context(), wrapped, make([]byte, 32))
	if !errors.Is(err, ErrKMS) {
		t.Fatalf("got %v; want an *awskms.Error", err)
	}
}
