package hashicorpvault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/vault/api"
)

// TestMain clears every VAULT_* variable, so a developer's own Vault environment (VAULT_ADDR,
// VAULT_TOKEN, VAULT_NAMESPACE, ...) never reaches the clients the tests make.
func TestMain(m *testing.M) {
	for _, variable := range os.Environ() {
		if name, _, _ := strings.Cut(variable, "="); strings.HasPrefix(strings.ToUpper(name), "VAULT_") {
			_ = os.Unsetenv(name)
		}
	}
	os.Exit(m.Run())
}

const testToken = "hvs.test-token-never-logged"

// answer is a canned response.
type answer struct {
	status int
	body   string
}

// request is what the fake was asked.
type request struct {
	path, token, namespace string
}

// fakeVault is an httptest server answering KV reads with canned Vault responses: each path under
// /v1/ answers as set, and any other 404s with an empty error list, as Vault answers a missing
// secret. failWith, when set, answers every request.
type fakeVault struct {
	server *httptest.Server

	mu       sync.Mutex
	answers  map[string][]answer // by request path; the last stays once the others are used
	requests []request
	failWith *answer
}

func newFakeVault(t *testing.T) *fakeVault {
	t.Helper()
	f := &fakeVault{answers: map[string][]answer{}}
	f.server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeVault) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests = append(f.requests, request{path: r.URL.Path, token: r.Header.Get("X-Vault-Token"), namespace: r.Header.Get("X-Vault-Namespace")})
	queued := f.answers[r.URL.Path]
	a := answer{status: http.StatusNotFound, body: `{"errors":[]}`}
	if len(queued) > 0 {
		a = queued[0]
		if len(queued) > 1 {
			f.answers[r.URL.Path] = queued[1:]
		}
	}
	if f.failWith != nil {
		a = *f.failWith
	}
	f.mu.Unlock()

	if a.status/100 == 3 {
		w.Header().Set("Location", a.body)
		w.WriteHeader(a.status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(a.status)
	_, _ = w.Write([]byte(a.body))
}

// answer sets what path (the full request path, e.g. /v1/secret/data/item) answers, in turn.
func (f *fakeVault) answer(path string, answers ...answer) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answers[path] = answers
}

// fail makes every request answer a.
func (f *fakeVault) fail(a answer) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failWith = &a
}

// setKV2Raw stores data - the JSON text of an object, which may hold a member twice - as the latest
// version of the KV version 2 secret at mount/secret.
func (f *fakeVault) setKV2Raw(mount, secret, data string) {
	f.answer("/v1/"+mount+"/data/"+secret, answer{http.StatusOK,
		`{"request_id":"1","lease_id":"","renewable":false,"lease_duration":0,"data":{"data":` + data +
			`,"metadata":{"version":1,"deletion_time":"","destroyed":false}}}`})
}

// setKV2 stores data as the latest version of the KV version 2 secret at mount/secret.
func (f *fakeVault) setKV2(t *testing.T, mount, secret string, data map[string]any) {
	t.Helper()
	encoded, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	f.setKV2Raw(mount, secret, string(encoded))
}

// setKV1 stores data as the KV version 1 secret at mount/secret.
func (f *fakeVault) setKV1(t *testing.T, mount, secret string, data map[string]any) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"request_id": "1", "lease_duration": 2764800, "data": data})
	if err != nil {
		t.Fatal(err)
	}
	f.answer("/v1/"+mount+"/"+secret, answer{http.StatusOK, string(body)})
}

// setDeletedKV2 makes the latest version of the KV version 2 secret at mount/secret deleted: Vault
// then answers 404 with the version's metadata and no errors.
func (f *fakeVault) setDeletedKV2(mount, secret string) {
	f.answer("/v1/"+mount+"/data/"+secret, answer{http.StatusNotFound,
		`{"request_id":"1","data":{"data":null,"metadata":{"version":2,"deletion_time":"2026-01-01T00:00:00Z","destroyed":false}}}`})
}

// paths are the request paths the fake was asked for, in order.
func (f *fakeVault) paths() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var paths []string
	for _, r := range f.requests {
		paths = append(paths, r.path)
	}
	return paths
}

func (f *fakeVault) allRequests() []request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]request(nil), f.requests...)
}

// newClient is a client for address as an application would make one - api.DefaultConfig with
// redirects disabled - holding testToken, with no retries unless configure adds them.
func newClient(t *testing.T, address string, configure ...func(*api.Config)) *api.Client {
	t.Helper()
	config := api.DefaultConfig()
	if config.Error != nil {
		t.Fatal(config.Error)
	}
	config.Address = address
	config.DisableRedirects = true
	config.MaxRetries = 0
	for _, c := range configure {
		c(config)
	}
	client, err := api.NewClient(config)
	if err != nil {
		t.Fatal(err)
	}
	client.SetToken(testToken)
	return client
}
