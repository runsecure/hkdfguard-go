package awssecretsmanager

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/dek"
)

// fakeSecretsManager is Secrets Manager's JSON 1.1 endpoint as an HTTPClient behind a real
// *secretsmanager.Client, so the SDK's whole pipeline - signing, retries, logging, the capture
// middleware and unmarshalling - runs as it does against AWS. A signed GetSecretValue is answered
// with the secret (names matched exactly, as AWS matches them) or ResourceNotFoundException. Any
// other operation - ListSecrets and BatchGetSecretValue among them - is recorded in unexpected and
// refused.
type fakeSecretsManager struct {
	t *testing.T

	mu         sync.Mutex
	secrets    map[string]map[string]string
	gets       []string
	unexpected []string

	// failWith, when set, is the AWS error type and HTTP status GetSecretValue fails with.
	failWith *awsError
	// failures is how many GetSecretValue calls fail with failWith before it is cleared; 0 for all.
	failures int
	// rawBody, when set, is the body GetSecretValue answers 200 with, as it is.
	rawBody *string
	// onGet runs inside every GetSecretValue before it answers, e.g. to hold it open.
	onGet func()
}

type awsError struct {
	Type   string
	Status int
}

func newFakeSecretsManager(t *testing.T) *fakeSecretsManager {
	return &fakeSecretsManager{t: t, secrets: map[string]map[string]string{}}
}

func (f *fakeSecretsManager) setString(name, value string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.secrets[name] = map[string]string{"SecretString": value}
}

func (f *fakeSecretsManager) setBinary(name string, value []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.secrets[name] = map[string]string{"SecretBinary": base64.StdEncoding.EncodeToString(value)}
}

func (f *fakeSecretsManager) setEmpty(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.secrets[name] = map[string]string{}
}

func (f *fakeSecretsManager) fail(err *awsError, times int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failWith, f.failures = err, times
}

func (f *fakeSecretsManager) getNames() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.gets...)
}

// Do is the HTTPClient the SDK sends every request through.
func (f *fakeSecretsManager) Do(request *http.Request) (*http.Response, error) {
	operation := request.Header.Get("X-Amz-Target")
	if operation != "secretsmanager.GetSecretValue" {
		f.mu.Lock()
		f.unexpected = append(f.unexpected, operation)
		f.mu.Unlock()
		return errorResponse(awsError{"AccessDeniedException", 400}), nil
	}
	if auth := request.Header.Get("Authorization"); !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 ") {
		f.t.Errorf("the request isn't signed with SigV4: %q", auth)
	}
	var body map[string]any
	if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
		f.t.Errorf("the request body isn't JSON: %v", err)
	}
	name, _ := body["SecretId"].(string)
	if _, ok := body["VersionId"]; ok {
		f.t.Error("the request names a VersionId")
	}
	if _, ok := body["VersionStage"]; ok {
		f.t.Error("the request names a VersionStage")
	}

	f.mu.Lock()
	f.gets = append(f.gets, name)
	onGet, failWith, rawBody := f.onGet, f.failWith, f.rawBody
	if failWith != nil && f.failures > 0 {
		if f.failures--; f.failures == 0 {
			f.failWith = nil
		}
	}
	value, found := f.secrets[name]
	f.mu.Unlock()

	if onGet != nil {
		onGet()
	}
	if failWith != nil {
		return errorResponse(*failWith), nil
	}
	if rawBody != nil {
		return jsonResponse(200, *rawBody), nil
	}
	if !found {
		return errorResponse(awsError{"ResourceNotFoundException", 400}), nil
	}
	answer := map[string]any{
		"ARN":           fmt.Sprintf("arn:aws:secretsmanager:us-east-1:123456789012:secret:%s-AbCdEf", name),
		"Name":          name,
		"VersionId":     "a1b2c3d4-5678-90ab-cdef-EXAMPLE11111",
		"VersionStages": []string{"AWSCURRENT"},
		"CreatedDate":   1700000000.0,
	}
	for property, v := range value {
		answer[property] = v
	}
	encoded, _ := json.Marshal(answer)
	return jsonResponse(200, string(encoded)), nil
}

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode:    status,
		Status:        fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": {"application/x-amz-json-1.1"}, "X-Amzn-Requestid": {"request-1"}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
}

func errorResponse(e awsError) *http.Response {
	body, _ := json.Marshal(map[string]string{"__type": e.Type, "message": e.Type + " in a test."})
	response := jsonResponse(e.Status, string(body))
	response.Header.Set("X-Amzn-Errortype", e.Type)
	return response
}

// client is a real *secretsmanager.Client sending every request to f, without retries unless
// configure sets them.
func (f *fakeSecretsManager) client(configure ...func(*secretsmanager.Options)) *secretsmanager.Client {
	return secretsmanager.New(secretsmanager.Options{
		Region:           "us-east-1",
		HTTPClient:       f,
		RetryMaxAttempts: 1,
		Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}, nil
		}),
	}, configure...)
}

// recordingClient is a Client that hands every call on to a real client - optFns included - and
// records each output as the SDK returned it.
type recordingClient struct {
	*secretsmanager.Client

	mu      sync.Mutex
	outputs []*secretsmanager.GetSecretValueOutput
}

func (r *recordingClient) GetSecretValue(ctx context.Context, params *secretsmanager.GetSecretValueInput,
	optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	out, err := r.Client.GetSecretValue(ctx, params, optFns...)
	if out != nil {
		r.mu.Lock()
		r.outputs = append(r.outputs, out)
		r.mu.Unlock()
	}
	return out, err
}

// testKey is a real AES-256-GCM hkdfguard.DataEncryptionKey.
type testKey struct{ aead cipher.AEAD }

func newTestKey(t *testing.T) *testKey {
	t.Helper()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	block, _ := aes.NewCipher(key)
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		t.Fatal(err)
	}
	return &testKey{aead: aead}
}

func (k *testKey) Encrypt(_ context.Context, plaintext, aad []byte) ([]byte, error) {
	defer hkdfguard.Wipe(plaintext)
	return k.aead.Seal(nil, nil, plaintext, aad), nil
}

func (k *testKey) Decrypt(_ context.Context, ciphertext, aad, result []byte) (int, error) {
	if len(ciphertext) < k.aead.Overhead() || len(result) < len(ciphertext)-k.aead.Overhead() {
		return 0, hkdfguard.ErrAuthenticationFailed
	}
	out, err := k.aead.Open(result[:0], nil, ciphertext, aad)
	if err != nil {
		return 0, hkdfguard.ErrAuthenticationFailed
	}
	return len(out), nil
}

// newRing returns a ring holding one fresh key as version 1, its current version.
func newRing(t *testing.T) *dek.KeyRing {
	t.Helper()
	ring := dek.NewKeyRing(nil)
	if err := ring.Add(t.Context(), 1, newTestKey(t)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ring.Close() })
	return ring
}

// get decrypts name's value, sized by MaxDecryptedLength; "" and false when nothing is stored.
func get(t *testing.T, c hkdfguard.ProtectedReadOnlyCache, name string) (string, bool) {
	t.Helper()
	n, ok, err := c.MaxDecryptedLength(t.Context(), name)
	if err != nil {
		t.Fatalf("MaxDecryptedLength(%q): %v", name, err)
	}
	if !ok {
		return "", false
	}
	result := make([]byte, n)
	written, err := c.Decrypt(t.Context(), name, result)
	if err != nil {
		t.Fatalf("Decrypt(%q): %v", name, err)
	}
	return string(result[:written]), true
}

// mustGet is get, failing the test when nothing is stored.
func mustGet(t *testing.T, c hkdfguard.ProtectedReadOnlyCache, name string) string {
	t.Helper()
	value, ok := get(t, c, name)
	if !ok {
		t.Fatalf("nothing is stored under %q", name)
	}
	return value
}

// logBuffer collects what a logger writes, safely from any goroutine.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
