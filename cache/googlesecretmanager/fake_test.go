package googlesecretmanager

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/cache"
	"github.com/runsecure/hkdfguard-go/dek"
)

const (
	testProjectID = "hkdfguard-test"

	// Google answers with the project's number, not the ID it was asked with.
	testProjectNumber = "123456789012"
)

// fakeSecretManager stands in for Secret Manager's AccessSecretVersion, served over gRPC (the
// secretmanagerpb service, on the loopback address) and over REST, so tests can run through the
// real client either way; answer gives the same responses in the process, for a stub. Secret IDs
// are matched exactly, as Google matches them; a secret it doesn't hold is NOT_FOUND. Responses
// carry a CRC32C, as Google's do for payloads added with one. Any other call is unimplemented.
type fakeSecretManager struct {
	secretmanagerpb.UnimplementedSecretManagerServiceServer

	mu       sync.Mutex
	secrets  map[string][]byte
	accesses []string
	// contentTypes is the content type of every gRPC call.
	contentTypes []string
	failure      error
	tamper       func(*secretmanagerpb.AccessSecretVersionResponse)
	onGet        func()
	hang         bool

	grpcAddress string
	restURL     string
}

func newFakeSecretManager() *fakeSecretManager {
	return &fakeSecretManager{secrets: map[string][]byte{}}
}

// serve starts the gRPC and REST servers, stopped when the test ends.
func (f *fakeSecretManager) serve(t *testing.T) *fakeSecretManager {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	secretmanagerpb.RegisterSecretManagerServiceServer(server, f)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	f.grpcAddress = listener.Addr().String()

	rest := httptest.NewServer(f)
	t.Cleanup(rest.Close)
	f.restURL = rest.URL
	return f
}

// client is a real Secret Manager client over gRPC, reaching only the fake.
func (f *fakeSecretManager) client(t *testing.T, options ...option.ClientOption) *secretmanager.Client {
	t.Helper()
	options = append([]option.ClientOption{option.WithEndpoint(f.grpcAddress), option.WithoutAuthentication(),
		option.WithGRPCDialOption(grpc.WithTransportCredentials(insecure.NewCredentials()))}, options...)
	client, err := secretmanager.NewClient(context.Background(), options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// restClient is a real Secret Manager client over REST (HTTP/JSON), reaching only the fake.
func (f *fakeSecretManager) restClient(t *testing.T) *secretmanager.Client {
	t.Helper()
	client, err := secretmanager.NewRESTClient(context.Background(), option.WithEndpoint(f.restURL), option.WithoutAuthentication())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func (f *fakeSecretManager) set(secretID string, value []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.secrets[secretID] = bytes.Clone(value)
}

func (f *fakeSecretManager) setString(secretID, value string) { f.set(secretID, []byte(value)) }

// fail makes every access fail with err; nil restores normal answers.
func (f *fakeSecretManager) fail(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failure = err
}

// rewrite changes every response before it is sent.
func (f *fakeSecretManager) rewrite(tamper func(*secretmanagerpb.AccessSecretVersionResponse)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tamper = tamper
}

// whileGetting runs inside every access before it answers, e.g. to hold it open.
func (f *fakeSecretManager) whileGetting(onGet func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.onGet = onGet
}

// hangCalls makes every call wait until its caller gives up.
func (f *fakeSecretManager) hangCalls() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hang = true
}

// accessed is every resource name AccessSecretVersion was called with, in order.
func (f *fakeSecretManager) accessed() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.accesses...)
}

// gets is the secret ID of every access, in order.
func (f *fakeSecretManager) gets() []string {
	var ids []string
	for _, name := range f.accessed() {
		id, _ := strings.CutSuffix(strings.TrimPrefix(name, "projects/"+testProjectID+"/secrets/"), "/versions/latest")
		ids = append(ids, id)
	}
	return ids
}

// AccessSecretVersion is the gRPC service's method.
func (f *fakeSecretManager) AccessSecretVersion(ctx context.Context, request *secretmanagerpb.AccessSecretVersionRequest) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	f.mu.Lock()
	hang := f.hang
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		f.contentTypes = append(f.contentTypes, md.Get("content-type")...)
	}
	f.mu.Unlock()
	if hang {
		<-ctx.Done()
		return nil, status.FromContextError(ctx.Err()).Err()
	}
	return f.answer(request)
}

// answer is what AccessSecretVersion answers, in the process.
func (f *fakeSecretManager) answer(request *secretmanagerpb.AccessSecretVersionRequest) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	f.mu.Lock()
	f.accesses = append(f.accesses, request.GetName())
	onGet, failure, tamper := f.onGet, f.failure, f.tamper
	f.mu.Unlock()
	if onGet != nil {
		onGet()
	}
	if failure != nil {
		return nil, failure
	}

	prefix := "projects/" + testProjectID + "/secrets/"
	secretID, found := strings.CutSuffix(strings.TrimPrefix(request.GetName(), prefix), "/versions/latest")
	if !strings.HasPrefix(request.GetName(), prefix) || !found {
		return nil, status.Errorf(codes.InvalidArgument, "unexpected resource name %q", request.GetName())
	}
	f.mu.Lock()
	value, ok := f.secrets[secretID]
	f.mu.Unlock()
	if !ok {
		return nil, status.Errorf(codes.NotFound, "Secret [projects/%s/secrets/%s] not found or has no versions.", testProjectNumber, secretID)
	}

	checksum := crc32c(value)
	response := &secretmanagerpb.AccessSecretVersionResponse{
		Name:    fmt.Sprintf("projects/%s/secrets/%s/versions/1", testProjectNumber, secretID),
		Payload: &secretmanagerpb.SecretPayload{Data: bytes.Clone(value), DataCrc32C: &checksum},
	}
	if tamper != nil {
		tamper(response)
	}
	return response, nil
}

// ServeHTTP is the REST service: GET /v1/{name}:access, the response as JSON, a failure as
// Google's JSON error with the HTTP status its gRPC status maps to.
func (f *fakeSecretManager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	name, method, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/v1/"), ":")
	var response proto.Message
	var err error
	if method == "access" && r.Method == http.MethodGet {
		response, err = f.AccessSecretVersion(r.Context(), &secretmanagerpb.AccessSecretVersionRequest{Name: name})
	} else {
		err = status.Errorf(codes.Unimplemented, "%s %s isn't implemented.", r.Method, r.URL.Path)
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
		_, _ = fmt.Fprintf(w, `{"error": {"code": %d, "message": %q, "status": %q}}`, code, s.Message(), s.Code().String())
		return
	}
	encoded, _ := protojson.Marshal(response)
	_, _ = w.Write(encoded)
}

// stubClient is a Client test double that answers in the process, as fake does, keeping every
// response exactly as the cache received it - not a copy - so a test can see what the cache did to
// its payload afterwards, and the call options it was given.
type stubClient struct {
	fake *fakeSecretManager

	mu        sync.Mutex
	responses []*secretmanagerpb.AccessSecretVersionResponse
	options   [][]gax.CallOption
}

func (s *stubClient) AccessSecretVersion(ctx context.Context, request *secretmanagerpb.AccessSecretVersionRequest,
	options ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, status.FromContextError(err).Err()
	}
	response, err := s.fake.answer(request)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.options = append(s.options, options)
	if response != nil {
		s.responses = append(s.responses, response)
	}
	return response, err
}

// payloads is every payload the stub handed the cache.
func (s *stubClient) payloads() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	var payloads [][]byte
	for _, response := range s.responses {
		if data := response.GetPayload().GetData(); data != nil {
			payloads = append(payloads, data)
		}
	}
	return payloads
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
	if len(ciphertext) < k.aead.Overhead() {
		return 0, hkdfguard.ErrAuthenticationFailed
	}
	if len(result) < len(ciphertext)-k.aead.Overhead() {
		return 0, hkdfguard.ErrInvalidConfigurationKey
	}
	out, err := k.aead.Open(result[:0], nil, ciphertext, aad)
	if err != nil {
		return 0, hkdfguard.ErrAuthenticationFailed
	}
	return len(out), nil
}

// newRing is a ring holding one fresh key, version 1.
func newRing(t *testing.T) *dek.KeyRing {
	t.Helper()
	ring := dek.NewKeyRing(nil)
	if err := ring.Add(t.Context(), 1, newTestKey(t)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ring.Close() })
	return ring
}

// newCache is a cache over a fresh fake, through a stub client.
func newCache(t *testing.T) (*cache.RemoteCache, *fakeSecretManager, *stubClient) {
	t.Helper()
	fake := newFakeSecretManager()
	stub := &stubClient{fake: fake}
	return newCacheOver(t, stub, Options{}), fake, stub
}

func newCacheOver(t *testing.T, client Client, options Options) *cache.RemoteCache {
	t.Helper()
	c, err := New(client, testProjectID, newRing(t), options)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// decryptString is the value for name as a string, "" for none; it fails the test on an error.
func decryptString(t *testing.T, c hkdfguard.ProtectedReadOnlyCache, name string) string {
	t.Helper()
	result := make([]byte, 64*1024)
	n, err := c.Decrypt(t.Context(), name, result)
	if err != nil {
		t.Fatalf("decrypting %q: %v", name, err)
	}
	return string(result[:n])
}
