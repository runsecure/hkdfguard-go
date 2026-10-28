package azurekeyvault

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"

	"github.com/runsecure/hkdfguard-go"
)

// Through real *azkeys.Client instances whose transport answers in-process: every request is built,
// authenticated (Key Vault's challenge included) and serialized by the SDK exactly as it would be
// sent, and every answer deserialized as it would be received.

const (
	vaultURL  = "https://myvault.vault.azure.net"
	wrapName  = "hkdfguard-wrap"
	signName  = "hkdfguard-sign"
	tenantID  = "00000000-0000-0000-0000-000000000000"
	fakeToken = "fake-token"
)

var (
	wrapKeyID = vaultURL + "/keys/" + wrapName
	signKeyID = vaultURL + "/keys/" + signName
)

// RSA keys are slow to generate, so every fake vault draws from a few made once.
var (
	rsaOnce sync.Once
	rsa2048 []*rsa.PrivateKey
	rsa3072 *rsa.PrivateKey
	rsaNext atomic.Uint32
)

func rsaKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	rsaOnce.Do(func() {
		for range 3 {
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				panic(err)
			}
			rsa2048 = append(rsa2048, key)
		}
		key, err := rsa.GenerateKey(rand.Reader, 3072)
		if err != nil {
			panic(err)
		}
		rsa3072 = key
	})
	if bits == 3072 {
		return rsa3072
	}
	return rsa2048[rsaNext.Add(1)%uint32(len(rsa2048))]
}

// fakeKey is a key in the fake vault: its versions, oldest first, the last current.
type fakeKey struct {
	versions []string
	rsa      map[string]*rsa.PrivateKey
	ec       map[string]*ecdsa.PrivateKey
}

func (k *fakeKey) current() string { return k.versions[len(k.versions)-1] }

// fakeRequest is a request the fake vault answered, after the challenge.
type fakeRequest struct {
	name, version, op string
	apiVersion        string
	header            http.Header
	body              map[string]any
	value             []byte // the decoded "value", if any
}

// fakeAnswer is what a test's hook answers instead of the vault: a status and a JSON body.
type fakeAnswer struct {
	status int
	body   any
}

// fakeVault is an in-process stand-in for one or more Key Vaults, answering wrapkey, unwrapkey,
// sign and verify as Key Vault does: on the key version in the path, or the current one when the
// path names none, reporting the versioned key identifier it used. Keys are RSA (wrap and unwrap,
// RSA-OAEP-256) or EC P-256 (sign and verify, ES256). Requests with no bearer token get Key Vault's
// 401 challenge.
type fakeVault struct {
	mu         sync.Mutex
	keys       map[string]*fakeKey // by host and lower-case name
	requests   []fakeRequest
	challenges map[string]int // by host
	plaintexts [][]byte       // what each wrapkey was sent

	// onRequest, if set, may answer a request instead of the vault.
	onRequest func(fakeRequest) *fakeAnswer
	// hang, if set, holds every request until its context ends.
	hang bool
	// failure, if set, is returned in place of every response: a request that never got one.
	failure error
}

func newFakeVault(t *testing.T) *fakeVault {
	t.Helper()
	f := &fakeVault{keys: map[string]*fakeKey{}, challenges: map[string]int{}}
	f.addRSA(t, vaultURL, wrapName, 2048)
	f.addEC(t, vaultURL, signName)
	return f
}

func keyIndex(vault, name string) string {
	return strings.TrimPrefix(vault, "https://") + "/" + strings.ToLower(name)
}

func newVersion() string { return hex.EncodeToString(random(16)) }

func (f *fakeVault) addRSA(t *testing.T, vault, name string, bits int) {
	t.Helper()
	version := newVersion()
	f.mu.Lock()
	defer f.mu.Unlock()
	key := f.keys[keyIndex(vault, name)]
	if key == nil {
		key = &fakeKey{rsa: map[string]*rsa.PrivateKey{}, ec: map[string]*ecdsa.PrivateKey{}}
		f.keys[keyIndex(vault, name)] = key
	}
	key.versions = append(key.versions, version)
	key.rsa[version] = rsaKey(t, bits)
}

func (f *fakeVault) addEC(t *testing.T, vault, name string) {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	version := newVersion()
	f.mu.Lock()
	defer f.mu.Unlock()
	key := f.keys[keyIndex(vault, name)]
	if key == nil {
		key = &fakeKey{rsa: map[string]*rsa.PrivateKey{}, ec: map[string]*ecdsa.PrivateKey{}}
		f.keys[keyIndex(vault, name)] = key
	}
	key.versions = append(key.versions, version)
	key.ec[version] = private
}

// rotate gives a key a new current version, of the same kind.
func (f *fakeVault) rotate(t *testing.T, name string) string {
	t.Helper()
	f.mu.Lock()
	key := f.keys[keyIndex(vaultURL, name)]
	isRSA := key.rsa[key.current()] != nil
	f.mu.Unlock()
	if isRSA {
		f.addRSA(t, vaultURL, name, 2048)
	} else {
		f.addEC(t, vaultURL, name)
	}
	return f.current(name)
}

func (f *fakeVault) current(name string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.keys[keyIndex(vaultURL, name)].current()
}

// purge removes a key version.
func (f *fakeVault) purge(name, version string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := f.keys[keyIndex(vaultURL, name)]
	delete(key.rsa, version)
	delete(key.ec, version)
}

func (f *fakeVault) publicRSA(name string) *rsa.PublicKey {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := f.keys[keyIndex(vaultURL, name)]
	return &key.rsa[key.current()].PublicKey
}

func (f *fakeVault) recorded() []fakeRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fakeRequest(nil), f.requests...)
}

// ops is the operation of every request answered, in order.
func (f *fakeVault) ops() []string {
	var ops []string
	for _, r := range f.recorded() {
		ops = append(ops, r.op)
	}
	return ops
}

// Do answers a request as Key Vault would.
func (f *fakeVault) Do(request *http.Request) (*http.Response, error) {
	if f.failure != nil {
		return nil, f.failure
	}
	if f.hang {
		<-request.Context().Done()
		return nil, request.Context().Err()
	}
	host := request.URL.Host
	if request.Header.Get("Authorization") == "" {
		f.mu.Lock()
		f.challenges[host]++
		f.mu.Unlock()
		return response(request, http.StatusUnauthorized, map[string]any{"error": map[string]any{"code": "Unauthorized", "message": "AKV10000"}},
			"WWW-Authenticate", fmt.Sprintf(`Bearer authorization="https://login.microsoftonline.com/%s", resource="https://vault.azure.net"`, tenantID)), nil
	}
	if request.Header.Get("Authorization") != "Bearer "+fakeToken {
		return errorResponse(request, http.StatusUnauthorized, "Unauthorized", "bad token"), nil
	}

	// /keys/{name}/{version}/{op}, or /keys/{name}/{op} for the current version: the SDK joins an
	// empty version out of the path.
	segments := strings.Split(strings.TrimPrefix(request.URL.Path, "/keys/"), "/")
	if len(segments) == 2 {
		segments = []string{segments[0], "", segments[1]}
	}
	if request.Method != http.MethodPost || len(segments) != 3 {
		return errorResponse(request, http.StatusBadRequest, "BadParameter", "unexpected "+request.Method+" "+request.URL.Path), nil
	}
	raw, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		return errorResponse(request, http.StatusBadRequest, "BadParameter", "the body is not JSON"), nil
	}
	r := fakeRequest{name: segments[0], version: segments[1], op: segments[2], apiVersion: request.URL.Query().Get("api-version"),
		header: request.Header.Clone(), body: body}
	if value, ok := body["value"].(string); ok {
		r.value = decode(value)
	}
	f.mu.Lock()
	f.requests = append(f.requests, r)
	if r.op == "wrapkey" {
		f.plaintexts = append(f.plaintexts, bytes.Clone(r.value))
	}
	f.mu.Unlock()

	if f.onRequest != nil {
		if a := f.onRequest(r); a != nil {
			return response(request, a.status, a.body), nil
		}
	}
	status, answer := f.answer(host, r)
	return response(request, status, answer), nil
}

func (f *fakeVault) answer(host string, r fakeRequest) (int, any) {
	f.mu.Lock()
	key := f.keys[host+"/"+strings.ToLower(r.name)]
	version := r.version
	if key != nil && version == "" {
		version = key.current()
	}
	var rsaKey *rsa.PrivateKey
	var ecKey *ecdsa.PrivateKey
	if key != nil {
		rsaKey, ecKey = key.rsa[version], key.ec[version]
	}
	f.mu.Unlock()
	if rsaKey == nil && ecKey == nil {
		return errorBody(http.StatusNotFound, "KeyNotFound", fmt.Sprintf("A key with (name/id) %s/%s was not found in this key vault.", r.name, version))
	}
	kid := "https://" + host + "/keys/" + r.name + "/" + version
	alg, _ := r.body["alg"].(string)

	switch {
	case (r.op == "wrapkey" || r.op == "unwrapkey") && rsaKey != nil:
		if alg != "RSA-OAEP-256" {
			return errorBody(http.StatusBadRequest, "BadParameter", "unexpected algorithm "+alg)
		}
		var result []byte
		var err error
		if r.op == "wrapkey" {
			result, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, &rsaKey.PublicKey, r.value, nil)
		} else {
			result, err = rsa.DecryptOAEP(sha256.New(), nil, rsaKey, r.value, nil)
		}
		if err != nil {
			return errorBody(http.StatusBadRequest, "BadParameter", err.Error())
		}
		return http.StatusOK, map[string]any{"kid": kid, "value": encode(result)}

	case r.op == "sign" && ecKey != nil:
		if alg != "ES256" || len(r.value) != sha256.Size {
			return errorBody(http.StatusBadRequest, "BadParameter", "unexpected algorithm or digest")
		}
		rr, s, err := ecdsa.Sign(rand.Reader, ecKey, r.value)
		if err != nil {
			return errorBody(http.StatusInternalServerError, "InternalError", err.Error())
		}
		return http.StatusOK, map[string]any{"kid": kid, "value": encode(append(rr.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...))}

	case r.op == "verify" && ecKey != nil:
		digest, _ := r.body["digest"].(string)
		if alg != "ES256" {
			return errorBody(http.StatusBadRequest, "BadParameter", "unexpected algorithm "+alg)
		}
		signature := r.value
		valid := len(signature) == 64 && ecdsa.Verify(&ecKey.PublicKey, decode(digest),
			new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:]))
		return http.StatusOK, map[string]any{"value": valid}
	}
	// As Key Vault refuses an operation the key's type or permitted operations don't allow.
	return http.StatusForbidden, map[string]any{"error": map[string]any{"code": "Forbidden",
		"message": fmt.Sprintf("Operation %s is not permitted on this key.", r.op), "innererror": map[string]any{"code": "KeyOperationForbidden"}}}
}

func errorBody(status int, code, message string) (int, any) {
	return status, map[string]any{"error": map[string]any{"code": code, "message": message}}
}

func errorResponse(request *http.Request, status int, code, message string) *http.Response {
	_, body := errorBody(status, code, message)
	return response(request, status, body)
}

func response(request *http.Request, status int, body any, headers ...string) *http.Response {
	encoded, err := json.Marshal(body)
	if err != nil {
		panic(err)
	}
	header := http.Header{"Content-Type": {"application/json; charset=utf-8"}}
	for i := 0; i+1 < len(headers); i += 2 {
		header.Set(headers[i], headers[i+1])
	}
	return &http.Response{
		StatusCode: status, Status: http.StatusText(status), Header: header, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Body: io.NopCloser(bytes.NewReader(encoded)), ContentLength: int64(len(encoded)), Request: request,
	}
}

// Key Vault encodes bytes as base64url, without padding.
func encode(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func decode(s string) []byte {
	b, _ := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	return b
}

// fakeCredential hands out a token, or fails.
type fakeCredential struct {
	err      error
	mu       sync.Mutex
	requests []policy.TokenRequestOptions
}

func (c *fakeCredential) GetToken(_ context.Context, options policy.TokenRequestOptions) (azcore.AccessToken, error) {
	c.mu.Lock()
	c.requests = append(c.requests, options)
	c.mu.Unlock()
	if c.err != nil {
		return azcore.AccessToken{}, c.err
	}
	return azcore.AccessToken{Token: fakeToken, ExpiresOn: time.Now().Add(time.Hour)}, nil
}

// clientOptions send every request to vault, with no retries.
func clientOptions(vault *fakeVault) *azkeys.ClientOptions {
	return &azkeys.ClientOptions{ClientOptions: azcore.ClientOptions{
		Transport: vault,
		Retry:     policy.RetryOptions{MaxRetries: -1},
	}}
}

func random(length int) []byte {
	b := make([]byte, length)
	_, _ = rand.Read(b)
	return b
}

func filled(length int) []byte { return bytes.Repeat([]byte{0xaa}, length) }

// newWrapper is a wrapper over the fake vault's two keys, with options' context and key file
// trust.
func newWrapper(t *testing.T, vault *fakeVault, options ...Options) *KeyWrapper {
	t.Helper()
	return newWrapperOver(t, vault, wrapKeyID, signKeyID, options...)
}

func newWrapperOver(t *testing.T, vault *fakeVault, wrapping, signing string, options ...Options) *KeyWrapper {
	t.Helper()
	var o Options
	if len(options) > 0 {
		o = options[0]
	}
	if o.ClientOptions == nil {
		o.ClientOptions = clientOptions(vault)
	}
	wrapper, err := New(wrapping, signing, &fakeCredential{}, o)
	if err != nil {
		t.Fatal(err)
	}
	return wrapper
}

func withContext() Options { return Options{Context: "hkdfguard.test"} }

func wrapWith(t *testing.T, wrapper *KeyWrapper, dek []byte) []byte {
	t.Helper()
	result := make([]byte, hkdfguard.MaxWrappedKeyBytes)
	n, err := wrapper.Wrap(t.Context(), dek, result)
	if err != nil {
		t.Fatal(err)
	}
	return result[:n]
}

// requireKeyVaultError fails the test unless err is an *Error whose message is exactly message, or
// - with a trailing "..." - starts with it, or - with a leading "..." - contains it.
func requireKeyVaultError(t *testing.T, err error, message string) *Error {
	t.Helper()
	var kvErr *Error
	if !errors.As(err, &kvErr) || !errors.Is(err, ErrKeyVault) {
		t.Fatalf("got %v (%T); want an *azurekeyvault.Error", err, err)
	}
	if text, ok := strings.CutPrefix(message, "..."); ok {
		if !strings.Contains(kvErr.Message, text) {
			t.Errorf("message %q; want it to contain %q", kvErr.Message, text)
		}
	} else if prefix, ok := strings.CutSuffix(message, "..."); ok {
		if !strings.HasPrefix(kvErr.Message, prefix) {
			t.Errorf("message %q; want it to start %q", kvErr.Message, prefix)
		}
	} else if kvErr.Message != message {
		t.Errorf("message %q; want %q", kvErr.Message, message)
	}
	return kvErr
}
