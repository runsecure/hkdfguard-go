package awskms

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/runsecure/hkdfguard-go"
)

// Through a real *kms.Client whose HTTP client answers in-process: every request is built, signed
// and serialized by the SDK exactly as it would be sent, and every answer deserialized as it would
// be received - so the requests are checked against the KMS model and its wire format.

// exchange is what the fake HTTP client received: a request's target, and its JSON body.
type exchange struct {
	target string
	body   map[string]any
}

type answer struct {
	status  int
	headers map[string]string
	body    any
}

type fakeHTTP struct {
	mu        sync.Mutex
	exchanges []exchange
	answer    func(exchange) answer
}

func (f *fakeHTTP) Do(request *http.Request) (*http.Response, error) {
	raw, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, fmt.Errorf("the request body is not JSON: %w", err)
	}
	ex := exchange{target: request.Header.Get("X-Amz-Target"), body: body}
	f.mu.Lock()
	f.exchanges = append(f.exchanges, ex)
	f.mu.Unlock()

	a := f.answer(ex)
	encoded, err := json.Marshal(a.body)
	if err != nil {
		return nil, err
	}
	header := http.Header{}
	header.Set("Content-Type", "application/x-amz-json-1.1")
	header.Set("X-Amzn-Requestid", "fake-request-id")
	for k, v := range a.headers {
		header.Set(k, v)
	}
	return &http.Response{
		StatusCode: a.status, Status: http.StatusText(a.status), Header: header, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Body: io.NopCloser(bytes.NewReader(encoded)), ContentLength: int64(len(encoded)), Request: request,
	}, nil
}

var staticCredentials = aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
	return aws.Credentials{AccessKeyID: "testing", SecretAccessKey: "testing", Source: "test"}, nil
})

// clientAnswering is a real *kms.Client whose HTTP client is fake, making one attempt per call.
func clientAnswering(answer func(exchange) answer) (*kms.Client, *fakeHTTP) {
	fake := &fakeHTTP{answer: answer}
	client := kms.New(kms.Options{Region: "us-east-1", Credentials: staticCredentials, HTTPClient: fake, RetryMaxAttempts: 1})
	return client, fake
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func TestRealClient_SendsEveryRequestAsTheKmsModelAndWireFormatDefineIt(t *testing.T) {
	key := random(32)
	ciphertext := bytes.Repeat([]byte{0x63}, 184)
	generated := bytes.Repeat([]byte{0x67}, 184)
	client, fake := clientAnswering(func(ex exchange) answer {
		switch ex.target {
		case "TrentService.Decrypt":
			return answer{status: 200, body: map[string]any{"KeyId": keyARN, "Plaintext": b64(key), "EncryptionAlgorithm": "SYMMETRIC_DEFAULT"}}
		case "TrentService.Encrypt":
			return answer{status: 200, body: map[string]any{"KeyId": keyARN, "CiphertextBlob": b64(ciphertext)}}
		default:
			return answer{status: 200, body: map[string]any{"KeyId": keyARN, "CiphertextBlob": b64(generated)}}
		}
	})
	wrapper := newWrapper(t, client, withContext())

	wrapped := make([]byte, hkdfguard.MaxWrappedKeyBytes)
	if n, err := wrapper.Wrap(t.Context(), key, wrapped); err != nil || n != 184 {
		t.Fatalf("wrap: %d, %v", n, err)
	}
	revealed := make([]byte, 32)
	if n, err := wrapper.Unwrap(t.Context(), wrapped[:184], revealed); err != nil || n != 32 {
		t.Fatalf("unwrap: %d, %v", n, err)
	}
	if n, err := wrapper.GenerateAndWrap(t.Context(), wrapped); err != nil || n != 184 {
		t.Fatalf("generate-and-wrap: %d, %v", n, err)
	}

	if !bytes.Equal(revealed, key) || !bytes.Equal(wrapped[:184], generated) {
		t.Error("the answers were not decoded into the results")
	}
	bound := map[string]any{"purpose": "hkdfguard.test"}
	want := []exchange{
		{"TrentService.Encrypt", map[string]any{"KeyId": keyARN, "Plaintext": b64(key), "EncryptionContext": bound, "EncryptionAlgorithm": "SYMMETRIC_DEFAULT"}},
		{"TrentService.Decrypt", map[string]any{"KeyId": keyARN, "CiphertextBlob": b64(ciphertext), "EncryptionContext": bound, "EncryptionAlgorithm": "SYMMETRIC_DEFAULT"}},
		{"TrentService.GenerateDataKeyWithoutPlaintext", map[string]any{"KeyId": keyARN, "KeySpec": "AES_256", "EncryptionContext": bound}},
	}
	if !reflect.DeepEqual(fake.exchanges, want) {
		t.Errorf("sent %+v\nwant %+v", fake.exchanges, want)
	}
}

func TestRealClient_SendsNoEncryptionContextWhenThereIsNone(t *testing.T) {
	client, fake := clientAnswering(func(exchange) answer {
		return answer{status: 200, body: map[string]any{"KeyId": keyARN, "CiphertextBlob": b64(random(184))}}
	})
	if _, err := newWrapper(t, client).GenerateAndWrap(t.Context(), make([]byte, hkdfguard.MaxWrappedKeyBytes)); err != nil {
		t.Fatal(err)
	}
	if _, ok := fake.exchanges[0].body["EncryptionContext"]; ok {
		t.Errorf("sent %v", fake.exchanges[0].body)
	}
}

func TestRealClient_NamesAModeledKmsErrorByItsName(t *testing.T) {
	client, _ := clientAnswering(func(exchange) answer {
		return answer{status: 400, headers: map[string]string{"X-Amzn-Errortype": "IncorrectKeyException"}, body: map[string]any{
			"__type": "IncorrectKeyException", "message": "The key ID in the request does not identify a CMK that can perform this operation.",
		}}
	})
	result := filled(32)

	_, err := newWrapper(t, client).Unwrap(t.Context(), bytes.Repeat([]byte{0x63}, 184), result)
	requireKMSError(t, err, fmt.Sprintf("AWS KMS unwrap failed for key '%s': IncorrectKeyException (HTTP 400).", keyARN))
	var incorrect *types.IncorrectKeyException
	if !errors.As(err, &incorrect) {
		t.Errorf("%v does not reach an *types.IncorrectKeyException", err)
	}
	if !hkdfguard.IsZero(result) {
		t.Error("the result was not zeroed")
	}
}

func TestRealClient_NamesAnUnmodeledKmsErrorByItsCode(t *testing.T) {
	client, _ := clientAnswering(func(exchange) answer {
		return answer{status: 400, headers: map[string]string{"X-Amzn-Errortype": "AccessDeniedException"}, body: map[string]any{
			"__type": "AccessDeniedException", "message": "User is not authorized to perform: kms:Encrypt",
		}}
	})
	_, err := newWrapper(t, client).Wrap(t.Context(), random(32), make([]byte, hkdfguard.MaxWrappedKeyBytes))
	requireKMSError(t, err, fmt.Sprintf("AWS KMS wrap failed for key '%s': AccessDeniedException (HTTP 400).", keyARN))
}

func TestRealClient_ReportsARefusedConnectionAsAnError(t *testing.T) {
	// A client-side failure end to end: a port this machine just stopped listening on, so the
	// connection is refused locally and no request leaves it.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := "http://" + listener.Addr().String()
	_ = listener.Close()
	client := kms.New(kms.Options{Region: "us-east-1", Credentials: staticCredentials, BaseEndpoint: aws.String(endpoint), RetryMaxAttempts: 1})

	_, err = newWrapper(t, client).GenerateAndWrap(t.Context(), make([]byte, hkdfguard.MaxWrappedKeyBytes))
	requireKMSError(t, err, fmt.Sprintf("AWS KMS generate-and-wrap failed for key '%s': ...", keyARN))
	var opErr *net.OpError
	if !errors.As(err, &opErr) || opErr.Op != "dial" {
		t.Errorf("%v does not reach the refused dial", err)
	}
	if !strings.Contains(err.Error(), "refused") {
		t.Errorf("%q does not say the connection was refused", err)
	}
}
