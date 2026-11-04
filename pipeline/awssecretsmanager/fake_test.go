package awssecretsmanager

import (
	"context"
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
