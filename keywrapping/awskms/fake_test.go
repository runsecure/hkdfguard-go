package awskms

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"github.com/runsecure/hkdfguard-go"
)

const keyARN = "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"

var testContext = map[string]string{"purpose": "hkdfguard.test"}

// fakeKMS is an in-process stand-in for KMS, implementing only the three calls KeyWrapper makes,
// through Client as the SDK's client takes them. By default it behaves like a symmetric KMS key:
// ciphertext is AES-GCM under a local key, binding the key ID and encryption context, so Decrypt
// fails unless both match. Each call can be answered by a handler instead, which returns what a
// test needs. Every input is recorded as received; Encrypt's plaintext is also copied when it
// arrives, since the wrapper zeroes the slice it sent once the call returns.
type fakeKMS struct {
	key cipher.AEAD

	onEncrypt  func(*kms.EncryptInput) (*kms.EncryptOutput, error)
	onDecrypt  func(*kms.DecryptInput) (*kms.DecryptOutput, error)
	onGenerate func(*kms.GenerateDataKeyWithoutPlaintextInput) (*kms.GenerateDataKeyWithoutPlaintextOutput, error)

	mu                sync.Mutex
	encryptRequests   []*kms.EncryptInput
	encryptPlaintexts [][]byte
	decryptRequests   []*kms.DecryptInput
	generateRequests  []*kms.GenerateDataKeyWithoutPlaintextInput
	contexts          []context.Context
}

func newFakeKMS(t *testing.T) *fakeKMS {
	t.Helper()
	block, err := aes.NewCipher(random(32))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeKMS{key: aead}
}

func (f *fakeKMS) Encrypt(ctx context.Context, input *kms.EncryptInput, _ ...func(*kms.Options)) (*kms.EncryptOutput, error) {
	f.mu.Lock()
	f.contexts = append(f.contexts, ctx)
	f.encryptRequests = append(f.encryptRequests, input)
	f.encryptPlaintexts = append(f.encryptPlaintexts, bytes.Clone(input.Plaintext))
	f.mu.Unlock()
	if f.onEncrypt != nil {
		return f.onEncrypt(input)
	}
	return &kms.EncryptOutput{KeyId: input.KeyId, CiphertextBlob: f.seal(input.Plaintext, aws.ToString(input.KeyId), input.EncryptionContext)}, nil
}

func (f *fakeKMS) Decrypt(ctx context.Context, input *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	f.mu.Lock()
	f.contexts = append(f.contexts, ctx)
	f.decryptRequests = append(f.decryptRequests, input)
	f.mu.Unlock()
	if f.onDecrypt != nil {
		return f.onDecrypt(input)
	}
	plaintext, err := f.open(input.CiphertextBlob, aws.ToString(input.KeyId), input.EncryptionContext)
	if err != nil {
		return nil, err
	}
	return &kms.DecryptOutput{KeyId: input.KeyId, Plaintext: plaintext}, nil
}

func (f *fakeKMS) GenerateDataKeyWithoutPlaintext(ctx context.Context, input *kms.GenerateDataKeyWithoutPlaintextInput,
	_ ...func(*kms.Options)) (*kms.GenerateDataKeyWithoutPlaintextOutput, error) {
	f.mu.Lock()
	f.contexts = append(f.contexts, ctx)
	f.generateRequests = append(f.generateRequests, input)
	f.mu.Unlock()
	if f.onGenerate != nil {
		return f.onGenerate(input)
	}
	return &kms.GenerateDataKeyWithoutPlaintextOutput{
		KeyId: input.KeyId, CiphertextBlob: f.seal(random(32), aws.ToString(input.KeyId), input.EncryptionContext),
	}, nil
}

func (f *fakeKMS) seal(plaintext []byte, keyID string, encryptionContext map[string]string) []byte {
	nonce := random(f.key.NonceSize())
	return f.key.Seal(nonce, nonce, plaintext, aad(keyID, encryptionContext))
}

func (f *fakeKMS) open(sealed []byte, keyID string, encryptionContext map[string]string) ([]byte, error) {
	if len(sealed) < f.key.NonceSize()+f.key.Overhead() {
		return nil, serviceError("Decrypt", &types.InvalidCiphertextException{Message: aws.String("from fakeKMS")}, 400)
	}
	plaintext, err := f.key.Open(nil, sealed[:f.key.NonceSize()], sealed[f.key.NonceSize():], aad(keyID, encryptionContext))
	if err != nil {
		// Real KMS reports a key mismatch as IncorrectKeyException and a context mismatch or
		// tampering as InvalidCiphertextException; one is enough for a fake.
		return nil, serviceError("Decrypt", &types.InvalidCiphertextException{Message: aws.String("from fakeKMS")}, 400)
	}
	return plaintext, nil
}

func aad(keyID string, encryptionContext map[string]string) []byte {
	var b strings.Builder
	b.WriteString(keyID)
	for _, key := range slices.Sorted(maps.Keys(encryptionContext)) {
		b.WriteString("\x00" + key + "=" + encryptionContext[key])
	}
	return []byte(b.String())
}

// serviceError is what the SDK returns for a KMS error response: the modeled error, inside the
// response error that carries the HTTP status, inside the operation error.
func serviceError(operation string, apiErr smithy.APIError, status int) error {
	var response *smithyhttp.Response
	if status != 0 {
		response = &smithyhttp.Response{Response: &http.Response{StatusCode: status}}
	} else {
		response = &smithyhttp.Response{}
	}
	return &smithy.OperationError{ServiceID: "KMS", OperationName: operation, Err: &awshttp.ResponseError{
		ResponseError: &smithyhttp.ResponseError{Response: response, Err: apiErr},
		RequestID:     "fake-request-id",
	}}
}

func random(length int) []byte {
	b := make([]byte, length)
	_, _ = rand.Read(b)
	return b
}

func filled(length int) []byte { return bytes.Repeat([]byte{0xaa}, length) }

func newWrapper(t *testing.T, client Client, options ...Options) *KeyWrapper {
	t.Helper()
	var o Options
	if len(options) > 0 {
		o = options[0]
	}
	wrapper, err := New(client, keyARN, o)
	if err != nil {
		t.Fatal(err)
	}
	return wrapper
}

func withContext() Options { return Options{EncryptionContext: testContext} }

func wrapWith(t *testing.T, wrapper *KeyWrapper, dek []byte) []byte {
	t.Helper()
	result := make([]byte, hkdfguard.MaxWrappedKeyBytes)
	n, err := wrapper.Wrap(t.Context(), dek, result)
	if err != nil {
		t.Fatal(err)
	}
	return result[:n]
}

// requireKMSError fails the test unless err is an *Error whose message is exactly message, or -
// with a trailing "..." - starts with it.
func requireKMSError(t *testing.T, err error, message string) *Error {
	t.Helper()
	var kmsErr *Error
	if !errors.As(err, &kmsErr) || !errors.Is(err, ErrKMS) {
		t.Fatalf("got %v (%T); want an *awskms.Error", err, err)
	}
	if prefix, ok := strings.CutSuffix(message, "..."); ok {
		if !strings.HasPrefix(kmsErr.Message, prefix) {
			t.Errorf("message %q; want it to start %q", kmsErr.Message, prefix)
		}
	} else if kmsErr.Message != message {
		t.Errorf("message %q; want %q", kmsErr.Message, message)
	}
	return kmsErr
}
