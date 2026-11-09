package hashicorpvault

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/internal/vaultcheck"
	"github.com/runsecure/hkdfguard-go/pipeline"
	"github.com/runsecure/hkdfguard-go/pipeline/internal/pipelinetest"
)

// contractStore is the writer, through a real client, against a fake Vault: a name without a key
// reads the default key, "value".
type contractStore struct {
	t     *testing.T
	vault *fakeVault
}

func (c *contractStore) NewWriter(protector hkdfguard.PipelineDataProtector, secretNames []string) (hkdfguard.SecretPipelineWriter, error) {
	return New(newClient(c.t, c.vault.server.URL), protector, secretNames, Options{})
}

func (c *contractStore) SetText(name, text string) {
	c.vault.setKV2(c.t, "secret", name, map[string]any{"value": text})
}

func (c *contractStore) SetKeys(name, json string) { c.vault.setKV2Raw("secret", name, json) }

func (c *contractStore) FailReads() {
	c.vault.fail(answer{http.StatusForbidden, `{"errors":["permission denied"]}`})
}

func (c *contractStore) IsReadFailure(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.StatusCode == http.StatusForbidden
}

func (c *contractStore) Reads() []string {
	var names []string
	for _, path := range c.vault.paths() {
		names = append(names, strings.TrimPrefix(path, "/v1/secret/data/"))
	}
	return names
}

// The writer's contract, with its real client against a fake Vault.
func TestContract(t *testing.T) {
	pipelinetest.Contract(t, func(t *testing.T) pipelinetest.Store { return &contractStore{t: t, vault: newFakeVault(t)} })
}

func newWriter(t *testing.T, vault *fakeVault, protector hkdfguard.PipelineDataProtector, options Options, names ...string) *pipeline.Writer {
	t.Helper()
	w, err := New(newClient(t, vault.server.URL), protector, names, options)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func TestEveryRead_SendsTheClientsToken(t *testing.T) {
	vault := newFakeVault(t)
	vault.setKV2(t, "secret", "myapp/db", map[string]any{"username": "app"})
	protector := pipelinetest.NewProtector(t)
	w := newWriter(t, vault, protector, Options{}, "myapp/db#username")

	if err := w.PullSecrets(t.Context()); err != nil {
		t.Fatal(err)
	}

	if got := pipelinetest.Decrypt(t, protector, w.ProtectedSecrets()["myapp__db__username"], "myapp__db__username"); got != "app" {
		t.Fatalf("myapp__db__username is %q", got)
	}
	requests := vault.allRequests()
	if len(requests) != 1 || requests[0].path != "/v1/secret/data/myapp/db" || requests[0].token != testToken || requests[0].namespace != "" {
		t.Fatalf("requests: %+v", requests)
	}
}

func TestTheClientsNamespace_IsSent(t *testing.T) {
	vault := newFakeVault(t)
	vault.setKV2(t, "secret", "item", map[string]any{"value": "s3cret"})
	client := newClient(t, vault.server.URL)
	client.SetNamespace("team-a/prod")
	w, err := New(client, pipelinetest.NewProtector(t), []string{"item"}, Options{})
	if err != nil {
		t.Fatal(err)
	}

	if err := w.PullSecrets(t.Context()); err != nil {
		t.Fatal(err)
	}

	if requests := vault.allRequests(); len(requests) != 1 || requests[0].namespace != "team-a/prod" {
		t.Fatalf("requests: %+v", requests)
	}
}

func TestADeletedLatestVersion_OrABodyWithoutData_IsMissing(t *testing.T) {
	vault := newFakeVault(t)
	vault.setDeletedKV2("secret", "gone")
	w := newWriter(t, vault, pipelinetest.NewProtector(t), Options{}, "gone")
	if err := w.PullSecrets(t.Context()); !errors.Is(err, pipeline.ErrSecretNotFound) {
		t.Fatalf("a deleted version: %v; want pipeline.ErrSecretNotFound", err)
	}

	vault.answer("/v1/secret/data/gone", answer{http.StatusOK, `{"data":{"metadata":{"version":3}}}`})
	err := w.PullSecrets(t.Context())
	if !errors.Is(err, pipeline.ErrSecretNotFound) || !strings.Contains(err.Error(), "gone") {
		t.Fatalf("a body without data: %v; want pipeline.ErrSecretNotFound naming gone", err)
	}
}

func TestTheDefaultKey_IsTheOptionsOne(t *testing.T) {
	vault := newFakeVault(t)
	vault.setKV2(t, "secret", "myapp/db", map[string]any{"password": "s3cret"})
	protector := pipelinetest.NewProtector(t)
	w := newWriter(t, vault, protector, Options{DefaultKey: "password"}, "myapp/db")

	if err := w.PullSecrets(t.Context()); err != nil {
		t.Fatal(err)
	}

	if got := pipelinetest.Decrypt(t, protector, w.ProtectedSecrets()["myapp__db"], "myapp__db"); got != "s3cret" {
		t.Fatalf("myapp__db is %q", got)
	}
}

func TestKVVersion1_IsReadAtTheMountPath(t *testing.T) {
	vault := newFakeVault(t)
	vault.setKV1(t, "kv", "item", map[string]any{"value": "s3cret"})
	protector := pipelinetest.NewProtector(t)
	w := newWriter(t, vault, protector, Options{KVVersion: V1, MountPath: "kv"}, "item")

	if err := w.PullSecrets(t.Context()); err != nil {
		t.Fatal(err)
	}

	if got := pipelinetest.Decrypt(t, protector, w.ProtectedSecrets()["item"], "item"); got != "s3cret" {
		t.Fatalf("item is %q", got)
	}
	if got := vault.paths(); !slices.Equal(got, []string{"/v1/kv/item"}) {
		t.Fatalf("paths: %q", got)
	}
}

func TestAVaultError_FailsThePull_WithItsStatusAndErrors(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
		detail string
	}{
		{http.StatusForbidden, `{"errors":["permission denied"]}`, ": permission denied"},
		{http.StatusNotFound, `{"errors":["no handler for route \"secret/data/item\""]}`, `: no handler for route "secret/data/item"`},
		{http.StatusNotFound, "<html>Not Found</html>", ""},
		{http.StatusInternalServerError, "", ""},
		{http.StatusBadGateway, "<html>Bad Gateway</html>", ""},
	} {
		t.Run(tc.body, func(t *testing.T) {
			vault := newFakeVault(t)
			vault.answer("/v1/secret/data/item", answer{tc.status, tc.body})
			w := newWriter(t, vault, pipelinetest.NewProtector(t), Options{}, "item")

			err := w.PullSecrets(t.Context())

			var e *Error
			if !errors.As(err, &e) || !errors.Is(err, ErrVault) || e.StatusCode != tc.status || e.Path != "item" {
				t.Fatalf("PullSecrets: %v", err)
			}
			if want := fmt.Sprintf("Vault refused to read 'item': %d %s%s", tc.status, http.StatusText(tc.status), tc.detail); e.Error() != want {
				t.Fatalf("message %q; want %q", e.Error(), want)
			}
			if strings.Contains(e.Error(), testToken) {
				t.Fatal("the error holds the token")
			}
			if len(w.ProtectedSecrets()) != 0 {
				t.Fatal("something was kept")
			}
		})
	}
}

func TestASuccessThatIsntVaultsJSON_IsRefused(t *testing.T) {
	for _, body := range []string{`[]`, ``, `{"data":`, "not json"} {
		t.Run(body, func(t *testing.T) {
			vault := newFakeVault(t)
			vault.answer("/v1/secret/data/item", answer{http.StatusOK, body})
			w := newWriter(t, vault, pipelinetest.NewProtector(t), Options{}, "item")

			err := w.PullSecrets(t.Context())

			if !errors.Is(err, pipeline.ErrInvalidSecretData) {
				t.Fatalf("PullSecrets: %v; want pipeline.ErrInvalidSecretData", err)
			}
			if body != "" && strings.Contains(err.Error(), body) {
				t.Fatalf("the error quotes the body: %v", err)
			}
			if len(w.ProtectedSecrets()) != 0 {
				t.Fatal("something was kept")
			}
		})
	}
}

func TestTheClientsRetries_AreUsed(t *testing.T) {
	vault := newFakeVault(t)
	vault.answer("/v1/secret/data/item",
		answer{http.StatusServiceUnavailable, `{"errors":["Vault is sealed"]}`},
		answer{http.StatusOK, `{"data":{"data":{"value":"value"}}}`})
	client := newClient(t, vault.server.URL, func(config *api.Config) {
		config.MaxRetries, config.MinRetryWait, config.MaxRetryWait = 2, time.Millisecond, time.Millisecond
	})
	w, err := New(client, pipelinetest.NewProtector(t), []string{"item"}, Options{})
	if err != nil {
		t.Fatal(err)
	}

	if err := w.PullSecrets(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := vault.paths(); len(got) != 2 {
		t.Fatalf("paths: %q", got)
	}
}

func TestNoAnswer_FailsThePull(t *testing.T) {
	vault := newFakeVault(t)
	w := newWriter(t, vault, pipelinetest.NewProtector(t), Options{}, "item")
	vault.server.Close()

	err := w.PullSecrets(t.Context())

	var e *Error
	if !errors.As(err, &e) || e.StatusCode != 0 || e.Path != "item" {
		t.Fatalf("PullSecrets: %v", err)
	}
}

func TestTheCallersContext_EndsThePull(t *testing.T) {
	vault := newFakeVault(t)
	w := newWriter(t, vault, pipelinetest.NewProtector(t), Options{}, "item")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if err := w.PullSecrets(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("PullSecrets: %v; want context.Canceled", err)
	}
}

func TestARedirect_FailsThePull_AndIsntFollowed(t *testing.T) {
	vault := newFakeVault(t)
	vault.answer("/v1/secret/data/item", answer{http.StatusTemporaryRedirect, vault.server.URL + "/elsewhere"})
	w := newWriter(t, vault, pipelinetest.NewProtector(t), Options{}, "item")

	err := w.PullSecrets(t.Context())

	var e *Error
	if !errors.As(err, &e) || e.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("PullSecrets: %v", err)
	}
	if got := vault.paths(); !slices.Equal(got, []string{"/v1/secret/data/item"}) {
		t.Fatalf("the redirect was followed: %q", got)
	}
}

func TestAClientThatFollowsRedirects_IsRefused_UnlessAllowed(t *testing.T) {
	vault := newFakeVault(t)
	protector := pipelinetest.NewProtector(t)
	for name, configure := range map[string]func(*api.Config){
		"DisableRedirects false": func(config *api.Config) { config.DisableRedirects = false },
		"CheckRedirect nil":      func(config *api.Config) { config.HttpClient.CheckRedirect = nil },
		"CheckRedirect allows": func(config *api.Config) {
			config.HttpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return nil }
		},
	} {
		t.Run(name, func(t *testing.T) {
			client := newClient(t, vault.server.URL, configure)
			if _, err := New(client, protector, []string{"item"}, Options{}); !errors.Is(err, ErrInvalidArgument) || !strings.Contains(err.Error(), "redirect") {
				t.Fatalf("New: %v", err)
			}
			if _, err := New(client, protector, []string{"item"}, Options{AllowRedirects: true}); err != nil {
				t.Fatalf("New with AllowRedirects: %v", err)
			}
		})
	}
}

func TestDisableRedirects_CanBeReadFromThisVersionOfTheClient(t *testing.T) {
	vault := newFakeVault(t)
	for _, want := range []bool{true, false} {
		client := newClient(t, vault.server.URL, func(config *api.Config) { config.DisableRedirects = want })
		if disables, known := vaultcheck.DisablesRedirects(client); !known || disables != want {
			t.Fatalf("want %v: got %v, known %v", want, disables, known)
		}
	}
}

func TestAnAddressThatWouldExposeTheToken_IsRefused(t *testing.T) {
	protector := pipelinetest.NewProtector(t)
	for _, address := range []string{"http://vault.example.com:8200", "https://user:pass@vault.example.com", "https://vault.example.com/?x=1"} {
		if _, err := New(newClient(t, address), protector, []string{"item"}, Options{}); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("%s: %v; want ErrInvalidArgument", address, err)
		}
	}
	for _, address := range []string{"https://vault.example.com:8200", "http://127.0.0.1:8200", "http://localhost:8200", "unix:///run/vault-agent.sock"} {
		if _, err := New(newClient(t, address), protector, []string{"item"}, Options{}); err != nil {
			t.Errorf("%s: %v", address, err)
		}
	}
}

func TestANameThatIsntAPath_IsRefused(t *testing.T) {
	vault := newFakeVault(t)
	protector := pipelinetest.NewProtector(t)
	for _, secretName := range []string{"ConnectionStrings:Admin", "../escape", ".hidden", "a//b", "/abs"} {
		_, err := New(newClient(t, vault.server.URL), protector, []string{secretName}, Options{})
		if !errors.Is(err, ErrInvalidArgument) || !errors.Is(err, pipeline.ErrInvalidArgument) {
			t.Errorf("%q: %v; want ErrInvalidArgument and pipeline.ErrInvalidArgument", secretName, err)
		}
	}
}

func TestIsValidSecretName_AcceptsPathsUpToTheLimit(t *testing.T) {
	if !IsValidSecretName(strings.Repeat("a", MaxSecretNameLength)) || IsValidSecretName(strings.Repeat("a", MaxSecretNameLength+1)) {
		t.Fatal("the limit isn't MaxSecretNameLength")
	}
	if IsValidSecretName("") {
		t.Fatal("an empty path is valid")
	}
}

func TestNew_ChecksTheClientAndOptions(t *testing.T) {
	vault := newFakeVault(t)
	client := newClient(t, vault.server.URL)
	protector := pipelinetest.NewProtector(t)
	names := []string{"item"}
	for name, create := range map[string]func() error{
		"no client":       func() error { _, err := New(nil, protector, names, Options{}); return err },
		"mount ../sys":    func() error { _, err := New(client, protector, names, Options{MountPath: "../sys"}); return err },
		"mount /secret":   func() error { _, err := New(client, protector, names, Options{MountPath: "/secret"}); return err },
		"default key a#b": func() error { _, err := New(client, protector, names, Options{DefaultKey: "a#b"}); return err },
		"KV version 3":    func() error { _, err := New(client, protector, names, Options{KVVersion: 3}); return err },
	} {
		if err := create(); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("%s: %v; want ErrInvalidArgument", name, err)
		}
	}
}

func TestAClientThatDoesntVerifyTLS_IsRefused(t *testing.T) {
	vault := newFakeVault(t)
	client := newClient(t, vault.server.URL, func(c *api.Config) {
		if err := c.ConfigureTLS(&api.TLSConfig{Insecure: true}); err != nil {
			t.Fatal(err)
		}
	})
	_, err := New(client, pipelinetest.NewProtector(t), []string{"item"}, Options{AllowRedirects: true})
	if !errors.Is(err, ErrInvalidArgument) || !strings.Contains(err.Error(), "TLS certificate") {
		t.Fatalf("got %v", err)
	}
}
