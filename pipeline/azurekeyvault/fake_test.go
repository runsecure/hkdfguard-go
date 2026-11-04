package azurekeyvault

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
)

const vaultURL = "https://hkdfguard-test.vault.azure.net/"

// fakeVault is Key Vault's secrets endpoint, as the transport under a real azsecrets client: a
// request without a bearer token gets Key Vault's 401 challenge, and an authorized Get Secret is
// answered with the secret's JSON (names compared ignoring case, as Key Vault does) or a 404. Any
// request other than Get Secret - listing secrets or versions among them - is recorded in
// unexpected and refused. options also installs a per-call policy recording every body the SDK was
// given to parse, so a test can check the secret never reached it.
type fakeVault struct {
	mu         sync.Mutex
	secrets    map[string]string // by lower-cased name
	gets       []string          // the name of every authorized Get Secret, in order
	unexpected []string          // every other request, as "METHOD path"
	bodiesSeen []string          // every response body the SDK parsed

	failWith int    // when set, an authorized Get Secret is answered with this status and an error body
	rawBody  string // when set, an authorized Get Secret is answered with this body as it is
	onGet    func() // runs inside every authorized Get Secret before it answers, e.g. to hold it open
}

func newFakeVault() *fakeVault { return &fakeVault{secrets: map[string]string{}} }

func (v *fakeVault) set(name, value string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.secrets[strings.ToLower(name)] = value
}

func (v *fakeVault) fail(status int) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.failWith = status
}

func (v *fakeVault) getNames() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]string(nil), v.gets...)
}

func (v *fakeVault) bodies() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]string(nil), v.bodiesSeen...)
}

// options are client options sending every request here, without retries.
func (v *fakeVault) options() *azsecrets.ClientOptions {
	return &azsecrets.ClientOptions{ClientOptions: azcore.ClientOptions{
		Transport:       v,
		Retry:           policy.RetryOptions{MaxRetries: -1},
		PerCallPolicies: []policy.Policy{bodyRecorder{v}},
	}}
}

func (v *fakeVault) Do(req *http.Request) (*http.Response, error) {
	path := strings.Split(strings.Trim(req.URL.Path, "/"), "/")
	if req.Method != http.MethodGet || len(path) != 2 || path[0] != "secrets" {
		v.mu.Lock()
		v.unexpected = append(v.unexpected, req.Method+" "+req.URL.Path)
		v.mu.Unlock()
		return respond(req, http.StatusForbidden, `{"error":{"code":"Forbidden","message":"Not allowed in a test."}}`), nil
	}
	if req.Header.Get("Authorization") == "" {
		challenge := respond(req, http.StatusUnauthorized, "")
		challenge.Header.Set("WWW-Authenticate",
			`Bearer authorization="https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000", resource="https://vault.azure.net"`)
		return challenge, nil
	}

	name := path[1]
	v.mu.Lock()
	v.gets = append(v.gets, name)
	onGet, failWith, rawBody := v.onGet, v.failWith, v.rawBody
	value, found := v.secrets[strings.ToLower(name)]
	v.mu.Unlock()
	if onGet != nil {
		onGet()
	}
	switch {
	case failWith != 0:
		return respond(req, failWith, `{"error":{"code":"Forbidden","message":"Refused in a test."}}`), nil
	case rawBody != "":
		return respond(req, http.StatusOK, rawBody), nil
	case !found:
		return respond(req, http.StatusNotFound,
			fmt.Sprintf(`{"error":{"code":"SecretNotFound","message":"A secret with (name/id) %s was not found in this key vault."}}`, name)), nil
	}
	body, err := json.Marshal(map[string]any{
		"value":      value,
		"id":         vaultURL + "secrets/" + name + "/0123456789abcdef0123456789abcdef",
		"attributes": map[string]any{"enabled": true, "created": 1700000000, "updated": 1700000000, "recoveryLevel": "Recoverable+Purgeable"},
		"tags":       map[string]string{"value": "a tag, not the secret"},
	})
	if err != nil {
		return nil, err
	}
	return respond(req, http.StatusOK, string(body)), nil
}

func respond(req *http.Request, status int, body string) *http.Response {
	return &http.Response{
		StatusCode:    status,
		Status:        fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Header:        http.Header{"Content-Type": []string{"application/json; charset=utf-8"}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}
}

// bodyRecorder records each response body as the SDK will parse it. A per-call policy, above
// retries and every per-retry policy, so it sees the response exactly as GetSecret does.
type bodyRecorder struct{ vault *fakeVault }

func (b bodyRecorder) Do(req *policy.Request) (*http.Response, error) {
	resp, err := req.Next()
	if err != nil {
		return resp, err
	}
	body, err := runtime.Payload(resp)
	if err != nil {
		return resp, err
	}
	b.vault.mu.Lock()
	b.vault.bodiesSeen = append(b.vault.bodiesSeen, string(body))
	b.vault.mu.Unlock()
	return resp, nil
}

// fakeCredential always has a token.
type fakeCredential struct{}

func (fakeCredential) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "fake-token", ExpiresOn: time.Now().Add(time.Hour)}, nil
}
