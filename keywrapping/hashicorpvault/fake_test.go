package hashicorpvault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"

	"github.com/runsecure/hkdfguard-go"
)

const (
	testToken   = "hvs.CAESIFakeTokenForTests"
	testKeyName = "myapp-kek"
	testContext = "hkdfguard.test"
)

// fakeTransit stands in for a transit secrets engine behind Vault's HTTP API, served by an
// httptest.Server the tests reach through a real *api.Client. A POST to encrypt, decrypt or
// datakey/wrapped for a key it holds, with the expected token, is answered as Vault 1.19 answers
// it: the ciphertext is "vault:v{version}:" and base64 of AES-GCM under that key version's own local
// key, with associated_data as the AAD, so decrypt fails unless the key, its version and the context
// all match. A key can be rotated, and given a min_decryption_version. datakey/wrapped ignores
// associated_data and says so in its warnings, as Vault does. A request without the token is
// refused with 403; any other request is recorded in unexpected and refused with 405.
type fakeTransit struct {
	t      *testing.T
	server *httptest.Server

	// mountPath and pathPrefix are where the engine is mounted, and the path /v1/ is under (Vault
	// behind a reverse proxy).
	mountPath  string
	pathPrefix string

	mu         sync.Mutex
	keys       map[string][][]byte // each key's versions' AES keys, version 1 first
	minVersion map[string]int
	requests   []transitRequest
	unexpected []string
	// answer, when set, answers a request in place of the engine: its status, headers and body, or
	// ok false to let the engine answer. Given the request and how many have arrived, this one
	// included.
	answer func(request transitRequest, count int) (status int, header http.Header, body string, ok bool)
	// onRequest runs inside every request before it is answered, e.g. to hold it open.
	onRequest func(r *http.Request)
	// ignoresAssociatedData answers as a Vault too old for associated_data would: ignoring it,
	// with a warning.
	ignoresAssociatedData bool
}

// transitRequest is one request as it arrived: its operation ("encrypt", "decrypt" or "datakey"),
// key, body (a copy), token, namespace and the headers that matter.
type transitRequest struct {
	Operation, Key string
	Body           []byte
	Token          string
	Namespace      string
	ContentType    string
	VaultRequest   string
}

// field is the request body's member name, as a string; "" if there is none.
func (r transitRequest) field(name string) string {
	var fields map[string]any
	if err := json.Unmarshal(r.Body, &fields); err != nil {
		return ""
	}
	if value, ok := fields[name].(string); ok {
		return value
	}
	return ""
}

func newFakeTransit(t *testing.T) *fakeTransit {
	t.Helper()
	f := &fakeTransit{t: t, mountPath: "transit", keys: map[string][][]byte{}, minVersion: map[string]int{}}
	f.addKey(testKeyName)
	f.server = httptest.NewServer(f)
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeTransit) addKey(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys[name] = [][]byte{random(32)}
}

// rotate adds a version to the key, as transit/keys/{name}/rotate does; ciphertexts made under
// earlier ones still decrypt.
func (f *fakeTransit) rotate(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys[name] = append(f.keys[name], random(32))
}

// setMinDecryptionVersion refuses ciphertexts made under an earlier version, as Vault's
// min_decryption_version does.
func (f *fakeTransit) setMinDecryptionVersion(name string, version int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.minVersion[name] = version
}

func (f *fakeTransit) setAnswer(answer func(request transitRequest, count int) (int, http.Header, string, bool)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answer = answer
}

// answerAlways answers every request with status and body.
func (f *fakeTransit) answerAlways(status int, body string) {
	f.setAnswer(func(transitRequest, int) (int, http.Header, string, bool) { return status, nil, body, true })
}

func (f *fakeTransit) setOnRequest(onRequest func(r *http.Request)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.onRequest = onRequest
}

func (f *fakeTransit) recorded() []transitRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]transitRequest(nil), f.requests...)
}

func (f *fakeTransit) unexpectedRequests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.unexpected...)
}

func (f *fakeTransit) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	prefix := f.pathPrefix + "/v1/" + f.mountPath + "/"
	route, _ := strings.CutPrefix(r.URL.Path, prefix)
	if !strings.HasPrefix(r.URL.Path, prefix) {
		route = ""
	}
	operation, key := "", ""
	for _, op := range []struct{ route, name string }{{"encrypt/", "encrypt"}, {"decrypt/", "decrypt"}, {"datakey/wrapped/", "datakey"}} {
		if rest, ok := strings.CutPrefix(route, op.route); ok {
			operation, key = op.name, rest
		}
	}
	if r.Method != http.MethodPost || operation == "" || strings.Contains(key, "/") || r.URL.RawQuery != "" {
		f.mu.Lock()
		f.unexpected = append(f.unexpected, r.Method+" "+r.URL.RequestURI())
		f.mu.Unlock()
		respond(w, http.StatusMethodNotAllowed, nil, `{"errors":["1 error occurred:\n\t* unsupported operation\n\n"]}`)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		respond(w, http.StatusBadRequest, nil, `{"errors":["can't read the body"]}`)
		return
	}
	request := transitRequest{
		Operation: operation, Key: key, Body: body,
		Token: r.Header.Get("X-Vault-Token"), Namespace: r.Header.Get("X-Vault-Namespace"),
		ContentType: r.Header.Get("Content-Type"), VaultRequest: r.Header.Get("X-Vault-Request"),
	}
	f.mu.Lock()
	f.requests = append(f.requests, request)
	count, answer, onRequest, ignores := len(f.requests), f.answer, f.onRequest, f.ignoresAssociatedData
	versions := f.keys[key]
	minVersion := f.minVersion[key]
	f.mu.Unlock()

	if onRequest != nil {
		onRequest(r)
	}
	if request.Token != testToken {
		respond(w, http.StatusForbidden, nil, `{"errors":["1 error occurred:\n\t* permission denied\n\n"]}`)
		return
	}
	if answer != nil {
		if status, header, body, ok := answer(request, count); ok {
			respond(w, status, header, body)
			return
		}
	}
	if versions == nil {
		respond(w, http.StatusBadRequest, nil, `{"errors":["encryption key not found"]}`)
		return
	}

	var fields map[string]any
	if err := json.Unmarshal(body, &fields); err != nil {
		respond(w, http.StatusBadRequest, nil, `{"errors":["failed to parse JSON input"]}`)
		return
	}
	var ignored []string
	for name := range fields {
		known := map[string]bool{
			"encrypt": name == "plaintext" || (name == "associated_data" && !ignores),
			"decrypt": name == "ciphertext" || (name == "associated_data" && !ignores),
			"datakey": name == "bits",
		}[operation]
		if !known {
			ignored = append(ignored, name)
		}
	}
	var aad []byte
	if encoded, ok := fields["associated_data"].(string); ok && !contains(ignored, "associated_data") {
		if aad, err = base64.StdEncoding.DecodeString(encoded); err != nil {
			respond(w, http.StatusBadRequest, nil, `{"errors":["failed to base64-decode associated_data"]}`)
			return
		}
	}
	var warnings []string
	if len(ignored) > 0 {
		warnings = []string{"Endpoint ignored these unrecognized parameters: [" + strings.Join(ignored, " ") + "]"}
	}
	latest := len(versions)

	switch operation {
	case "encrypt":
		plaintext, err := base64.StdEncoding.DecodeString(fmt.Sprint(fields["plaintext"]))
		if err != nil {
			respond(w, http.StatusBadRequest, nil, `{"errors":["failed to base64-decode plaintext"]}`)
			return
		}
		respond(w, http.StatusOK, nil, envelope(map[string]any{"ciphertext": seal(versions[latest-1], latest, plaintext, aad), "key_version": latest}, warnings))
	case "datakey":
		bits, _ := fields["bits"].(float64)
		respond(w, http.StatusOK, nil, envelope(map[string]any{"ciphertext": seal(versions[latest-1], latest, random(int(bits)/8), aad), "key_version": latest}, warnings))
	default:
		ciphertext := fmt.Sprint(fields["ciphertext"])
		rest, ok := strings.CutPrefix(ciphertext, "vault:v")
		digits, encoded, ok2 := strings.Cut(rest, ":")
		version, err := strconv.Atoi(digits)
		if !ok || !ok2 || err != nil {
			respond(w, http.StatusBadRequest, nil, `{"errors":["invalid ciphertext: no prefix"]}`)
			return
		}
		if version < minVersion {
			respond(w, http.StatusBadRequest, nil, `{"errors":["ciphertext or signature version is disallowed by policy (too old)"]}`)
			return
		}
		if version < 1 || version > latest {
			respond(w, http.StatusBadRequest, nil, `{"errors":["invalid key version"]}`)
			return
		}
		sealed, err := base64.StdEncoding.DecodeString(encoded)
		plaintext, openErr := open(versions[version-1], sealed, aad)
		if err != nil || openErr != nil {
			respond(w, http.StatusBadRequest, nil, `{"errors":["cipher: message authentication failed"]}`)
			return
		}
		respond(w, http.StatusOK, nil, envelope(map[string]any{"plaintext": base64.StdEncoding.EncodeToString(plaintext)}, warnings))
	}
}

func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

func respond(w http.ResponseWriter, status int, header http.Header, body string) {
	for name, values := range header {
		w.Header()[name] = values
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

// envelope is a body shaped as Vault shapes a successful answer.
func envelope(data any, warnings []string) string {
	encoded, err := json.Marshal(map[string]any{
		"request_id":     "0f3c2a8e-1b2d-4c5e-8f9a-0b1c2d3e4f5a",
		"lease_id":       "",
		"renewable":      false,
		"lease_duration": 0,
		"data":           data,
		"wrap_info":      nil,
		"warnings":       warnings,
		"auth":           nil,
		"mount_type":     "transit",
	})
	if err != nil {
		panic(err)
	}
	return string(encoded)
}

func seal(key []byte, version int, plaintext, aad []byte) string {
	aead := gcm(key)
	nonce := random(12)
	return fmt.Sprintf("vault:v%d:%s", version, base64.StdEncoding.EncodeToString(aead.Seal(nonce, nonce, plaintext, aad)))
}

func open(key, sealed, aad []byte) ([]byte, error) {
	if len(sealed) < 12+16 {
		return nil, errors.New("too short")
	}
	return gcm(key).Open(nil, sealed[:12], sealed[12:], aad)
}

func gcm(key []byte) cipher.AEAD {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return aead
}

// newClient is a real *api.Client over the fake, as api.DefaultConfig makes one - redirects not
// followed by its HTTP client - with the test token, no namespace, and retries that don't wait.
func (f *fakeTransit) newClient(t *testing.T) *api.Client {
	t.Helper()
	return newClientAt(t, f.server.URL+f.pathPrefix, nil)
}

// newClientAt is a real *api.Client at address; change, if any, adjusts its configuration first.
func newClientAt(t *testing.T, address string, change func(*api.Config)) *api.Client {
	t.Helper()
	config := api.DefaultConfig()
	if config.Error != nil {
		t.Fatal(config.Error)
	}
	config.Address = address
	config.MinRetryWait = time.Millisecond
	config.MaxRetryWait = 2 * time.Millisecond
	config.MaxRetries = 2
	config.Timeout = 10 * time.Second
	if change != nil {
		change(config)
	}
	client, err := api.NewClient(config)
	if err != nil {
		t.Fatal(err)
	}
	client.SetToken(testToken)
	client.ClearNamespace()
	return client
}

func random(length int) []byte {
	b := make([]byte, length)
	_, _ = rand.Read(b)
	return b
}

func filled(length int) []byte { return bytes.Repeat([]byte{0xaa}, length) }

// newWrapper is a wrapper over testKeyName through client, with options' mount path, context, key
// file trust and redirects.
func newWrapper(t *testing.T, client *api.Client, options ...Options) *KeyWrapper {
	t.Helper()
	return newWrapperOver(t, client, testKeyName, options...)
}

func newWrapperOver(t *testing.T, client *api.Client, name string, options ...Options) *KeyWrapper {
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

// requireVaultError fails the test unless err is an *Error whose message is exactly message, or -
// with a trailing "..." - starts with it, or - with a leading "..." - contains it, or - with both -
// contains what is between them.
func requireVaultError(t *testing.T, err error, message string) *Error {
	t.Helper()
	var vaultErr *Error
	if !errors.As(err, &vaultErr) || !errors.Is(err, ErrVault) {
		t.Fatalf("got %v (%T); want a *hashicorpvault.Error", err, err)
	}
	if text, ok := strings.CutPrefix(message, "..."); ok {
		text = strings.TrimSuffix(text, "...")
		if !strings.Contains(vaultErr.Message, text) {
			t.Errorf("message %q; want it to contain %q", vaultErr.Message, text)
		}
	} else if prefix, ok := strings.CutSuffix(message, "..."); ok {
		if !strings.HasPrefix(vaultErr.Message, prefix) {
			t.Errorf("message %q; want it to start %q", vaultErr.Message, prefix)
		}
	} else if vaultErr.Message != message {
		t.Errorf("message %q; want %q", vaultErr.Message, message)
	}
	return vaultErr
}
