package googlekms

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/runsecure/hkdfguard-go"
)

const (
	testKeyName  = "projects/test-project/locations/us-east1/keyRings/hkdfguard/cryptoKeys/wrap"
	otherKeyName = "projects/test-project/locations/us-east1/keyRings/hkdfguard/cryptoKeys/other"
	testContext  = "hkdfguard.test"
)

// fakeKMS stands in for Cloud KMS: Encrypt and Decrypt over one symmetric key per key name, served
// over gRPC (the kmspb service, on the loopback address) and over REST, so the tests run through
// the real client either way. It seals as [version][nonce][ciphertext][tag] with AES-GCM, binding
// the key name, the version and the AAD, so - as Cloud KMS does - it refuses a ciphertext under
// another key, other AAD, or tampered with, saying only "Decryption failed.". It verifies request
// checksums as Cloud KMS does, and records every request it receives.
type fakeKMS struct {
	kmspb.UnimplementedKeyManagementServiceServer
	aead cipher.AEAD

	mu        sync.Mutex
	version   int
	encrypts  []*kmspb.EncryptRequest
	decrypts  []*kmspb.DecryptRequest
	onEncrypt func(*kmspb.EncryptRequest) (*kmspb.EncryptResponse, error)
	onDecrypt func(*kmspb.DecryptRequest) (*kmspb.DecryptResponse, error)
	hang      bool

	grpcAddress string
	restURL     string
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
	f := &fakeKMS{aead: aead, version: 1}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	kmspb.RegisterKeyManagementServiceServer(server, f)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	f.grpcAddress = listener.Addr().String()

	rest := httptest.NewServer(f)
	t.Cleanup(rest.Close)
	f.restURL = rest.URL
	return f
}

// client is a real Cloud KMS client over gRPC, reaching only the fake.
func (f *fakeKMS) client(t *testing.T) *kms.KeyManagementClient {
	t.Helper()
	client, err := kms.NewKeyManagementClient(context.Background(), option.WithEndpoint(f.grpcAddress), option.WithoutAuthentication(),
		option.WithGRPCDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// restClient is a real Cloud KMS client over REST (HTTP/JSON), reaching only the fake.
func (f *fakeKMS) restClient(t *testing.T, options ...option.ClientOption) *kms.KeyManagementClient {
	t.Helper()
	options = append([]option.ClientOption{option.WithEndpoint(f.restURL)}, options...)
	if len(options) == 1 {
		options = append(options, option.WithoutAuthentication())
	}
	client, err := kms.NewKeyManagementRESTClient(context.Background(), options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// rotate makes a new primary version, as rotating the key does; ciphertexts made under earlier ones
// still decrypt.
func (f *fakeKMS) rotate() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.version++
}

func (f *fakeKMS) primary() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.version
}

// answerEncrypt and answerDecrypt replace what the fake answers; nil restores its normal answers.
func (f *fakeKMS) answerEncrypt(answer func(*kmspb.EncryptRequest) (*kmspb.EncryptResponse, error)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.onEncrypt = answer
}

func (f *fakeKMS) answerDecrypt(answer func(*kmspb.DecryptRequest) (*kmspb.DecryptResponse, error)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.onDecrypt = answer
}

// hangCalls makes every call wait until its caller gives up.
func (f *fakeKMS) hangCalls() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hang = true
}

func (f *fakeKMS) encryptRequests() []*kmspb.EncryptRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*kmspb.EncryptRequest(nil), f.encrypts...)
}

func (f *fakeKMS) decryptRequests() []*kmspb.DecryptRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*kmspb.DecryptRequest(nil), f.decrypts...)
}

func (f *fakeKMS) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.encrypts) + len(f.decrypts)
}

// Encrypt and Decrypt are the gRPC service's methods.

func (f *fakeKMS) Encrypt(ctx context.Context, request *kmspb.EncryptRequest) (*kmspb.EncryptResponse, error) {
	f.mu.Lock()
	f.encrypts = append(f.encrypts, proto.Clone(request).(*kmspb.EncryptRequest))
	answer, hang := f.onEncrypt, f.hang
	f.mu.Unlock()
	if hang {
		<-ctx.Done()
		return nil, status.FromContextError(ctx.Err()).Err()
	}
	if answer != nil {
		return answer(request)
	}
	return f.encryptNormally(request)
}

func (f *fakeKMS) Decrypt(ctx context.Context, request *kmspb.DecryptRequest) (*kmspb.DecryptResponse, error) {
	f.mu.Lock()
	f.decrypts = append(f.decrypts, proto.Clone(request).(*kmspb.DecryptRequest))
	answer, hang := f.onDecrypt, f.hang
	f.mu.Unlock()
	if hang {
		<-ctx.Done()
		return nil, status.FromContextError(ctx.Err()).Err()
	}
	if answer != nil {
		return answer(request)
	}
	return f.decryptNormally(request)
}

// encryptNormally is what Encrypt answers by default.
func (f *fakeKMS) encryptNormally(request *kmspb.EncryptRequest) (*kmspb.EncryptResponse, error) {
	if err := verifyChecksum(request.Plaintext, request.PlaintextCrc32C, "plaintext"); err != nil {
		return nil, err
	}
	if err := verifyChecksum(request.AdditionalAuthenticatedData, request.AdditionalAuthenticatedDataCrc32C, "additional_authenticated_data"); err != nil {
		return nil, err
	}
	if !isKeyName(request.Name) {
		return nil, status.Error(codes.InvalidArgument, "Encrypt takes a key's resource name.")
	}
	version := f.primary()
	ciphertext := f.seal(request.Plaintext, request.Name, version, request.AdditionalAuthenticatedData)
	return &kmspb.EncryptResponse{
		Name:                    fmt.Sprintf("%s/cryptoKeyVersions/%d", request.Name, version),
		Ciphertext:              ciphertext,
		CiphertextCrc32C:        wrapperspb.Int64(crc32c(ciphertext)),
		VerifiedPlaintextCrc32C: request.PlaintextCrc32C != nil,
		VerifiedAdditionalAuthenticatedDataCrc32C: request.AdditionalAuthenticatedDataCrc32C != nil,
		ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE,
	}, nil
}

// decryptNormally is what Decrypt answers by default.
func (f *fakeKMS) decryptNormally(request *kmspb.DecryptRequest) (*kmspb.DecryptResponse, error) {
	if err := verifyChecksum(request.Ciphertext, request.CiphertextCrc32C, "ciphertext"); err != nil {
		return nil, err
	}
	if err := verifyChecksum(request.AdditionalAuthenticatedData, request.AdditionalAuthenticatedDataCrc32C, "additional_authenticated_data"); err != nil {
		return nil, err
	}
	plaintext, err := f.open(request.Ciphertext, request.Name, request.AdditionalAuthenticatedData)
	if err != nil {
		return nil, err
	}
	return &kmspb.DecryptResponse{
		Plaintext:       plaintext,
		PlaintextCrc32C: wrapperspb.Int64(crc32c(plaintext)),
		UsedPrimary:     int(request.Ciphertext[0]) == f.primary(),
		ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE,
	}, nil
}

// sealDirectly encrypts as Cloud KMS would for any caller, not through the wrapper: under this key,
// with exactly this AAD.
func (f *fakeKMS) sealDirectly(plaintext []byte, keyName string, aad []byte) []byte {
	return f.seal(plaintext, keyName, f.primary(), aad)
}

func (f *fakeKMS) seal(plaintext []byte, keyName string, version int, aad []byte) []byte {
	nonce := random(12)
	sealed := append([]byte{byte(version)}, nonce...)
	return f.aead.Seal(sealed, nonce, plaintext, binding(keyName, version, aad))
}

func (f *fakeKMS) open(sealed []byte, keyName string, aad []byte) ([]byte, error) {
	// Cloud KMS says no more than this whatever is wrong: another key, other AAD, or tampering.
	refused := status.Error(codes.InvalidArgument, "Decryption failed.")
	if len(sealed) < 1+12+16 {
		return nil, refused
	}
	plaintext, err := f.aead.Open(nil, sealed[1:13], sealed[13:], binding(keyName, int(sealed[0]), aad))
	if err != nil {
		return nil, refused
	}
	return plaintext, nil
}

func binding(keyName string, version int, aad []byte) []byte {
	return append(append([]byte(keyName+"\x00"), byte(version)), aad...)
}

func verifyChecksum(data []byte, checksum *wrapperspb.Int64Value, field string) error {
	if checksum != nil && checksum.GetValue() != crc32c(data) {
		return status.Errorf(codes.InvalidArgument, "The checksum in field %s_crc32c did not match the data in field %s.", field, field)
	}
	return nil
}

// ServeHTTP is the REST service: POST /v1/{name}:encrypt and :decrypt, protobuf messages as JSON,
// a failure as Google's JSON error with the HTTP status its gRPC status maps to.
func (f *fakeKMS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	name, method, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/v1/"), ":")
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var response proto.Message
	switch method {
	case "encrypt":
		request := &kmspb.EncryptRequest{}
		if err = protojson.Unmarshal(body, request); err == nil {
			request.Name = name
			response, err = f.Encrypt(r.Context(), request)
		}
	case "decrypt":
		request := &kmspb.DecryptRequest{}
		if err = protojson.Unmarshal(body, request); err == nil {
			request.Name = name
			response, err = f.Decrypt(r.Context(), request)
		}
	default:
		err = status.Errorf(codes.Unimplemented, "%s isn't implemented.", r.URL.Path)
	}
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		s := status.Convert(err)
		code := map[codes.Code]int{
			codes.InvalidArgument: 400, codes.FailedPrecondition: 400, codes.Unauthenticated: 401, codes.PermissionDenied: 403,
			codes.NotFound: 404, codes.Unimplemented: 501, codes.Unavailable: 503, codes.DeadlineExceeded: 504,
		}[s.Code()]
		if code == 0 {
			code = 500
		}
		w.WriteHeader(code)
		_, _ = fmt.Fprintf(w, `{"error": {"code": %d, "message": %q, "status": %q}}`, code, s.Message(), statusNames[s.Code()])
		return
	}
	encoded, _ := protojson.Marshal(response)
	_, _ = w.Write(encoded)
}

// stubClient is a Client test double that answers in the process, keeping the requests exactly as
// the wrapper made them - not copies - so a test can see what the wrapper did to them afterwards.
type stubClient struct {
	mu       sync.Mutex
	encrypts []*kmspb.EncryptRequest
	decrypts []*kmspb.DecryptRequest
	encrypt  func(*kmspb.EncryptRequest) (*kmspb.EncryptResponse, error)
	decrypt  func(*kmspb.DecryptRequest) (*kmspb.DecryptResponse, error)
}

// newStub is a stub answering as fake does, unless told otherwise.
func newStub(fake *fakeKMS) *stubClient {
	return &stubClient{encrypt: fake.encryptNormally, decrypt: fake.decryptNormally}
}

func (s *stubClient) Encrypt(_ context.Context, request *kmspb.EncryptRequest, _ ...gax.CallOption) (*kmspb.EncryptResponse, error) {
	s.mu.Lock()
	s.encrypts = append(s.encrypts, request)
	s.mu.Unlock()
	return s.encrypt(request)
}

func (s *stubClient) Decrypt(_ context.Context, request *kmspb.DecryptRequest, _ ...gax.CallOption) (*kmspb.DecryptResponse, error) {
	s.mu.Lock()
	s.decrypts = append(s.decrypts, request)
	s.mu.Unlock()
	return s.decrypt(request)
}

func random(length int) []byte {
	b := make([]byte, length)
	_, _ = rand.Read(b)
	return b
}

func filled(length int) []byte { return bytes.Repeat([]byte{0xaa}, length) }

// newWrapper is a wrapper over testKeyName through client, with options' context and key file trust.
func newWrapper(t *testing.T, client Client, options ...Options) *KeyWrapper {
	t.Helper()
	return newWrapperOver(t, client, testKeyName, options...)
}

func newWrapperOver(t *testing.T, client Client, name string, options ...Options) *KeyWrapper {
	t.Helper()
	var o Options
	if len(options) > 0 {
		o = options[0]
	}
	wrapper, err := New(client, name, o)
	if err != nil {
		t.Fatal(err)
	}
	return wrapper
}

func withContext() Options { return Options{Context: testContext} }

func wrapWith(t *testing.T, wrapper *KeyWrapper, dek []byte) []byte {
	t.Helper()
	result := make([]byte, hkdfguard.MaxWrappedKeyBytes)
	n, err := wrapper.Wrap(t.Context(), dek, result)
	if err != nil {
		t.Fatal(err)
	}
	return result[:n]
}

func generate(t *testing.T, wrapper *KeyWrapper) []byte {
	t.Helper()
	result := make([]byte, hkdfguard.MaxWrappedKeyBytes)
	n, err := wrapper.GenerateAndWrap(t.Context(), result)
	if err != nil {
		t.Fatal(err)
	}
	return result[:n]
}

// requireCloudKMSError fails the test unless err is an *Error whose message is exactly message, or
// - with a trailing "..." - starts with it, or - with a leading "..." - contains it.
func requireCloudKMSError(t *testing.T, err error, message string) *Error {
	t.Helper()
	var kmsErr *Error
	if !errors.As(err, &kmsErr) || !errors.Is(err, ErrCloudKMS) {
		t.Fatalf("got %v (%T); want a *googlekms.Error", err, err)
	}
	if text, ok := strings.CutPrefix(message, "..."); ok {
		if !strings.Contains(kmsErr.Message, text) {
			t.Errorf("message %q; want it to contain %q", kmsErr.Message, text)
		}
	} else if prefix, ok := strings.CutSuffix(message, "..."); ok {
		if !strings.HasPrefix(kmsErr.Message, prefix) {
			t.Errorf("message %q; want it to start %q", kmsErr.Message, prefix)
		}
	} else if kmsErr.Message != message {
		t.Errorf("message %q; want %q", kmsErr.Message, message)
	}
	return kmsErr
}
