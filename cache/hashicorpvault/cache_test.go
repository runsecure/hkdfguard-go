package hashicorpvault

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"

	"github.com/runsecure/hkdfguard-go/cache"
	"github.com/runsecure/hkdfguard-go/diagnostics"
)

// newCache is a cache over vault's KV engine, through a client made as newClient makes one.
func newCache(t *testing.T, vault *fakeVault, options Options, configure ...func(*api.Config)) *cache.RemoteCache {
	t.Helper()
	c, err := New(newClient(t, vault.server.URL, configure...), newTestRing(t), options)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// decryptString is the value for name, "" when there is none; a failed lookup fails the test.
func decryptString(t *testing.T, c *cache.RemoteCache, name string) string {
	t.Helper()
	value, err := tryDecrypt(c, name)
	if err != nil {
		t.Fatalf("Decrypt(%q): %v", name, err)
	}
	return value
}

func tryDecrypt(c *cache.RemoteCache, name string) (string, error) {
	result := make([]byte, 64*1024)
	n, err := c.Decrypt(context.Background(), name, result)
	return string(result[:n]), err
}

func TestDecrypt_OnMiss_ReadsTheOneSecret_ThenServesItFromTheCache(t *testing.T) {
	vault := newFakeVault(t)
	vault.setKV2(t, "secret", "myapp/Db", map[string]any{"value": "s3cret"})
	c := newCache(t, vault, Options{})

	for range 2 {
		if got := decryptString(t, c, "myapp/Db"); got != "s3cret" {
			t.Fatalf("got %q", got)
		}
	}
	requests := vault.allRequests()
	if len(requests) != 1 || requests[0].path != "/v1/secret/data/myapp/Db" || requests[0].token != testToken {
		t.Fatalf("requests: %+v", requests)
	}
}

func TestOneRead_CachesEveryKeyTheSecretHolds(t *testing.T) {
	vault := newFakeVault(t)
	vault.setKV2(t, "secret", "myapp/db", map[string]any{
		"username": "app", "password": "s3cret", "value": "default", "Mixed-Case.key:1": "mixed",
	})
	c := newCache(t, vault, Options{})

	for name, want := range map[string]string{
		"myapp/db#password": "s3cret", "myapp/db#username": "app", "myapp/db": "default",
		"myapp/db#value": "default", "myapp/db#Mixed-Case.key:1": "mixed",
	} {
		if got := decryptString(t, c, name); got != want {
			t.Errorf("%s: got %q, want %q", name, got, want)
		}
	}
	if got := vault.paths(); !slices.Equal(got, []string{"/v1/secret/data/myapp/db"}) {
		t.Fatalf("paths: %v", got)
	}
}

func TestMaxDecryptedLength_ReadsTheSecret(t *testing.T) {
	vault := newFakeVault(t)
	vault.setKV2(t, "secret", "item", map[string]any{"value": "s3cret"})
	c := newCache(t, vault, Options{})

	max, ok, err := c.MaxDecryptedLength(context.Background(), "item")
	if err != nil || !ok || max < len("s3cret") {
		t.Fatalf("max %d, ok %v, err %v", max, ok, err)
	}
	if _, ok, err := c.MaxDecryptedLength(context.Background(), "missing"); err != nil || ok {
		t.Fatalf("missing: ok %v, err %v", ok, err)
	}
}

func TestTheDefaultKey_IsConfigurable(t *testing.T) {
	vault := newFakeVault(t)
	vault.setKV2(t, "secret", "item", map[string]any{"value": "wrong", "secret_value": "right"})
	c := newCache(t, vault, Options{DefaultKey: "secret_value"})

	if got := decryptString(t, c, "item"); got != "right" {
		t.Fatalf("got %q", got)
	}
}

func TestKVVersion1_IsReadAtTheMountsOwnPath(t *testing.T) {
	vault := newFakeVault(t)
	vault.setKV1(t, "kv", "myapp/db", map[string]any{"password": "v1 value"})
	c := newCache(t, vault, Options{KVVersion: V1, MountPath: "kv"})

	if got := decryptString(t, c, "myapp/db#password"); got != "v1 value" {
		t.Fatalf("got %q", got)
	}
	if got := decryptString(t, c, "missing"); got != "" {
		t.Fatalf("missing: got %q", got)
	}
	if got := vault.paths(); !slices.Equal(got, []string{"/v1/kv/myapp/db", "/v1/kv/missing"}) {
		t.Fatalf("paths: %v", got)
	}
}

func TestANestedMountPath_AndAnAddressPrefix_AreKept(t *testing.T) {
	vault := newFakeVault(t)
	vault.answer("/vault/v1/kv/team-a/data/item", answer{http.StatusOK, `{"data":{"data":{"value":"prefixed"}}}`})
	c, err := New(newClient(t, vault.server.URL+"/vault"), newTestRing(t), Options{MountPath: "kv/team-a"})
	if err != nil {
		t.Fatal(err)
	}

	if got := decryptString(t, c, "item"); got != "prefixed" {
		t.Fatalf("got %q (paths %v)", got, vault.paths())
	}
}

func TestTheClientsNamespace_IsSent_OnlyWhenSet(t *testing.T) {
	vault := newFakeVault(t)
	vault.setKV2(t, "secret", "item", map[string]any{"value": "v"})
	withNamespace := newClient(t, vault.server.URL)
	withNamespace.SetNamespace("team-a/prod")
	ring := newTestRing(t)
	a, err := New(withNamespace, ring, Options{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(newClient(t, vault.server.URL), ring, Options{})
	if err != nil {
		t.Fatal(err)
	}

	decryptString(t, a, "item")
	decryptString(t, b, "item")

	requests := vault.allRequests()
	if len(requests) != 2 || requests[0].namespace != "team-a/prod" || requests[1].namespace != "" {
		t.Fatalf("requests: %+v", requests)
	}
}

func TestEachRead_UsesTheTokenTheClientHoldsThen(t *testing.T) {
	vault := newFakeVault(t)
	client := newClient(t, vault.server.URL)
	c, err := New(client, newTestRing(t), Options{})
	if err != nil {
		t.Fatal(err)
	}

	decryptString(t, c, "first")
	client.SetToken("hvs.renewed")
	decryptString(t, c, "second")

	requests := vault.allRequests()
	if len(requests) != 2 || requests[0].token != testToken || requests[1].token != "hvs.renewed" {
		t.Fatalf("requests: %+v", requests)
	}
}

func TestAValueWithJSONEscapes_IsUnescapedExactly(t *testing.T) {
	vault := newFakeVault(t)
	const secret = "p\"a\\ss/wörd\n\u0001秘密"
	vault.setKV2(t, "secret", "escaped", map[string]any{"value": secret})
	c := newCache(t, vault, Options{})

	if got := decryptString(t, c, "escaped"); got != secret {
		t.Fatalf("got %q", got)
	}
}

func TestALargeSecret_RoundTrips(t *testing.T) {
	vault := newFakeVault(t)
	large := strings.Repeat("é-秘密-", 1500)
	vault.setKV2(t, "secret", "large", map[string]any{"value": large})
	c := newCache(t, vault, Options{})

	if got := decryptString(t, c, "large"); got != large {
		t.Fatalf("got %d bytes, want %d", len(got), len(large))
	}
}

func TestPathsDifferingOnlyInCase_AreDifferentSecrets(t *testing.T) {
	vault := newFakeVault(t)
	vault.setKV2(t, "secret", "myapp/Db", map[string]any{"value": "upper"})
	vault.setKV2(t, "secret", "myapp/db", map[string]any{"value": "lower"})
	c := newCache(t, vault, Options{})

	if decryptString(t, c, "myapp/Db") != "upper" || decryptString(t, c, "myapp/db") != "lower" ||
		decryptString(t, c, "MYAPP/DB") != "" || decryptString(t, c, "myapp/Db") != "upper" {
		t.Fatal("paths differing in case were confused")
	}
	if got := vault.paths(); len(got) != 3 {
		t.Fatalf("paths: %v", got)
	}
}

func TestAMissingSecret_ReturnsZero_AndIsLookedUpAgainUntilItExists(t *testing.T) {
	vault := newFakeVault(t)
	c := newCache(t, vault, Options{})

	if got := decryptString(t, c, "later"); got != "" {
		t.Fatalf("got %q", got)
	}
	vault.setKV2(t, "secret", "later", map[string]any{"value": "now here"})
	if got := decryptString(t, c, "later"); got != "now here" {
		t.Fatalf("got %q", got)
	}
	if got := vault.paths(); len(got) != 2 {
		t.Fatalf("paths: %v", got)
	}
}

func TestADeletedLatestVersion_IsReportedMissing(t *testing.T) {
	vault := newFakeVault(t)
	vault.setDeletedKV2("secret", "gone")
	c := newCache(t, vault, Options{})

	if got := decryptString(t, c, "gone"); got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestNumbersAndBooleans_AreCachedAsTheirText_AndOtherValuesAreMissing(t *testing.T) {
	vault := newFakeVault(t)
	vault.setKV2(t, "secret", "item", map[string]any{
		"number": 5432, "flag": true, "empty": "", "object": map[string]any{"value": "nested"}, "array": []string{"x"}, "null": nil,
	})
	c := newCache(t, vault, Options{})

	if got := decryptString(t, c, "item#number"); got != "5432" {
		t.Fatalf("number: %q", got)
	}
	if got := decryptString(t, c, "item#flag"); got != "true" {
		t.Fatalf("flag: %q", got)
	}
	for _, key := range []string{"absent", "empty", "object", "array", "null", "value"} {
		if got := decryptString(t, c, "item#"+key); got != "" {
			t.Errorf("%s: got %q", key, got)
		}
	}
}

func TestAResponseThatCantBeTrusted_IsRefused(t *testing.T) {
	for _, body := range []string{"not json", `["value"]`, `{"data":{"data":{"value":"a","value":"b"}}}`} {
		t.Run(body, func(t *testing.T) {
			vault := newFakeVault(t)
			vault.answer("/v1/secret/data/item", answer{http.StatusOK, body})
			c := newCache(t, vault, Options{})

			_, err := tryDecrypt(c, "item")
			if !errors.Is(err, cache.ErrInvalidSecretData) {
				t.Fatalf("got %v", err)
			}
			if strings.Contains(err.Error(), `"a"`) || strings.Contains(err.Error(), "not json") {
				t.Fatalf("the error quotes the body: %v", err)
			}
		})
	}
}

func TestAnyOtherAnswer_IsAnError_WithVaultsStatusAndErrors(t *testing.T) {
	for _, tc := range []struct {
		status   int
		body     string
		expected string
		listed   []string
	}{
		{http.StatusNotFound, `{"errors":["no handler for route \"nope/data/item\". route entry not found."]}`, "no handler for route", []string{`no handler for route "nope/data/item". route entry not found.`}},
		{http.StatusNotFound, "<html>Not Found</html>", "404 Not Found", nil},
		{http.StatusNotFound, "", "404 Not Found", nil},
		{http.StatusForbidden, `{"errors":["permission denied"]}`, "403 Forbidden: permission denied", []string{"permission denied"}},
		{http.StatusServiceUnavailable, `{"errors":["Vault is sealed"]}`, "Vault is sealed", []string{"Vault is sealed"}},
		{http.StatusInternalServerError, `["internal"]`, "500 Internal Server Error", nil},
		{http.StatusInternalServerError, `{"errors":"internal"}`, "500 Internal Server Error", nil},
		{http.StatusBadGateway, `{"request_id":"x"}`, "502 Bad Gateway", nil},
	} {
		t.Run(tc.expected, func(t *testing.T) {
			vault := newFakeVault(t)
			vault.answer("/v1/secret/data/item", answer{tc.status, tc.body}, answer{http.StatusOK, `{"data":{"data":{"value":"value"}}}`})
			c := newCache(t, vault, Options{})

			_, err := tryDecrypt(c, "item")
			var e *Error
			if !errors.As(err, &e) || !errors.Is(err, ErrVault) {
				t.Fatalf("got %v", err)
			}
			if e.StatusCode != tc.status || e.Path != "item" || !slices.Equal(e.Errors, tc.listed) {
				t.Fatalf("got %+v", e)
			}
			if !strings.Contains(e.Error(), tc.expected) || !strings.Contains(e.Error(), "'item'") {
				t.Fatalf("message: %s", e.Error())
			}
			if strings.Contains(e.Error(), testToken) {
				t.Fatal("the error holds the token")
			}
			var refused *api.ResponseError
			if !errors.As(err, &refused) || refused.StatusCode != tc.status {
				t.Fatalf("doesn't unwrap to the client's error: %v", err)
			}

			// A failure isn't remembered.
			if got := decryptString(t, c, "item"); got != "value" {
				t.Fatalf("after: got %q", got)
			}
		})
	}
}

func TestTheClientsRetries_AreUsed(t *testing.T) {
	vault := newFakeVault(t)
	vault.answer("/v1/secret/data/item",
		answer{http.StatusServiceUnavailable, `{"errors":["Vault is sealed"]}`},
		answer{http.StatusTooManyRequests, `{"errors":["rate limit quota exceeded"]}`},
		answer{http.StatusOK, `{"data":{"data":{"value":"value"}}}`})
	c := newCache(t, vault, Options{}, func(config *api.Config) {
		config.MaxRetries, config.MinRetryWait, config.MaxRetryWait = 2, time.Millisecond, time.Millisecond
	})

	if got := decryptString(t, c, "item"); got != "value" {
		t.Fatalf("got %q", got)
	}
	if got := vault.paths(); len(got) != 3 {
		t.Fatalf("paths: %v", got)
	}
}

func TestNoAnswer_IsAnError(t *testing.T) {
	vault := newFakeVault(t)
	c := newCache(t, vault, Options{})
	vault.server.Close()

	_, err := tryDecrypt(c, "item")
	var e *Error
	if !errors.As(err, &e) || !errors.Is(err, ErrVault) || e.StatusCode != 0 || e.Path != "item" {
		t.Fatalf("got %v", err)
	}
}

func TestTheCallersContext_EndsTheRead(t *testing.T) {
	vault := newFakeVault(t)
	release := make(chan struct{})
	defer close(release)
	vault.onRead = func(r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}
	c := newCache(t, vault, Options{})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := c.Decrypt(ctx, "item", make([]byte, 16))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
}

func TestTheClientsTimeout_EndsTheRead(t *testing.T) {
	vault := newFakeVault(t)
	release := make(chan struct{})
	defer close(release)
	vault.onRead = func(r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}
	c := newCache(t, vault, Options{}, func(config *api.Config) { config.Timeout = 100 * time.Millisecond })

	_, err := tryDecrypt(c, "item")
	if !errors.Is(err, ErrVault) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
}

func TestARedirect_IsAnError_AndNotFollowed(t *testing.T) {
	vault := newFakeVault(t)
	vault.answer("/v1/secret/data/item", answer{http.StatusTemporaryRedirect, vault.server.URL + "/elsewhere"})
	c := newCache(t, vault, Options{})

	_, err := tryDecrypt(c, "item")
	var e *Error
	if !errors.As(err, &e) || e.StatusCode != http.StatusTemporaryRedirect || !strings.Contains(e.Error(), "307") {
		t.Fatalf("got %v", err)
	}
	if got := vault.paths(); !slices.Equal(got, []string{"/v1/secret/data/item"}) {
		t.Fatalf("the redirect was followed: %v", got)
	}
}

func TestAClientThatFollowsRedirects_IsRefused(t *testing.T) {
	vault := newFakeVault(t)
	ring := newTestRing(t)
	for name, configure := range map[string]func(*api.Config){
		"DisableRedirects false": func(config *api.Config) { config.DisableRedirects = false },
		"CheckRedirect nil":      func(config *api.Config) { config.HttpClient.CheckRedirect = nil },
		"CheckRedirect allows": func(config *api.Config) {
			config.HttpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return nil }
		},
		"CheckRedirect panics": func(config *api.Config) {
			config.HttpClient.CheckRedirect = func(*http.Request, []*http.Request) error { panic("no") }
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := New(newClient(t, vault.server.URL, configure), ring, Options{})
			if !errors.Is(err, ErrInvalidArgument) || !strings.Contains(err.Error(), "redirect") {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestAClientThatFollowsRedirects_IsAccepted_WhenExplicitlyAllowed(t *testing.T) {
	vault := newFakeVault(t)
	vault.answer("/v1/secret/data/item", answer{http.StatusTemporaryRedirect, vault.server.URL + "/v1/secret/data/moved"})
	vault.setKV2(t, "secret", "moved", map[string]any{"value": "followed"})
	c := newCache(t, vault, Options{AllowRedirects: true}, func(config *api.Config) { config.DisableRedirects = false })

	if got := decryptString(t, c, "item"); got != "followed" {
		t.Fatalf("got %q", got)
	}
	requests := vault.allRequests()
	if len(requests) != 2 || requests[1].token != testToken {
		t.Fatalf("requests: %+v", requests)
	}
}

func TestAClientThatFollowsNoRedirects_IsAccepted(t *testing.T) {
	// api.DefaultConfig's CheckRedirect, and one of the application's own that stops every redirect.
	vault := newFakeVault(t)
	for _, configure := range []func(*api.Config){
		func(*api.Config) {},
		func(config *api.Config) {
			config.HttpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("no redirects") }
		},
	} {
		if _, err := New(newClient(t, vault.server.URL, configure), newTestRing(t), Options{}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDisableRedirects_CanBeReadFromThisVersionOfTheClient(t *testing.T) {
	// New reads it by reflection; if a new version of the client moves it, this fails first.
	vault := newFakeVault(t)
	for _, want := range []bool{true, false} {
		client := newClient(t, vault.server.URL, func(config *api.Config) { config.DisableRedirects = want })
		if disables, known := disablesRedirects(client); !known || disables != want {
			t.Fatalf("want %v: got %v, known %v", want, disables, known)
		}
	}
}

func TestAnAddressThatWouldExposeTheToken_IsRefused(t *testing.T) {
	ring := newTestRing(t)
	for _, address := range []string{
		"http://vault.example.com:8200",
		"http://10.0.0.1:8200",
		"https://user:pass@vault.example.com",
		"https://vault.example.com/?x=1",
		"https://vault.example.com/#frag",
	} {
		t.Run(address, func(t *testing.T) {
			_, err := New(newClient(t, address), ring, Options{})
			if !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestHTTPSAndLoopbackAddresses_AreAccepted(t *testing.T) {
	ring := newTestRing(t)
	for _, address := range []string{
		"https://vault.example.com:8200",
		"https://vault.example.com/vault",
		"http://127.0.0.1:8200",
		"http://127.1.2.3:8200",
		"http://[::1]:8200",
		"http://localhost:8200",
		"unix:///run/vault-agent.sock",
	} {
		t.Run(address, func(t *testing.T) {
			if _, err := New(newClient(t, address), ring, Options{}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAnAgentAddress_IsTheAddressChecked(t *testing.T) {
	_, err := New(newClient(t, "https://vault.example.com", func(config *api.Config) {
		config.AgentAddress = "http://agent.example.com:8100"
	}), newTestRing(t), Options{})
	if !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("got %v", err)
	}
}

func TestNew_RefusesInvalidArguments(t *testing.T) {
	vault := newFakeVault(t)
	client := newClient(t, vault.server.URL)
	ring := newTestRing(t)
	for name, create := range map[string]func() error{
		"no client":         func() error { _, err := New(nil, ring, Options{}); return err },
		"no ring":           func() error { _, err := New(client, nil, Options{}); return err },
		"mount ../sys":      func() error { _, err := New(client, ring, Options{MountPath: "../sys"}); return err },
		"mount /secret":     func() error { _, err := New(client, ring, Options{MountPath: "/secret"}); return err },
		"mount secret/":     func() error { _, err := New(client, ring, Options{MountPath: "secret/"}); return err },
		"default key a b":   func() error { _, err := New(client, ring, Options{DefaultKey: "a b"}); return err },
		"default key bang!": func() error { _, err := New(client, ring, Options{DefaultKey: "bang!"}); return err },
		"default key a#b":   func() error { _, err := New(client, ring, Options{DefaultKey: "a#b"}); return err },
		"KV version 3":      func() error { _, err := New(client, ring, Options{KVVersion: 3}); return err },
		"KV version -1":     func() error { _, err := New(client, ring, Options{KVVersion: -1}); return err },
	} {
		if err := create(); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

func TestANameThatIsntAPathAndKey_IsMissing_WithoutCallingVault(t *testing.T) {
	vault := newFakeVault(t)
	c := newCache(t, vault, Options{})
	for _, name := range []string{
		"", "ConnectionStrings:Admin", "../sys/seal-status", "myapp/../other", "myapp/./db", "..", "/leading",
		"trailing/", "double//slash", "has space", "café", "bang!", "query?list=true", "percent%2F",
		"item#", "#key", "item#a#b", "item#a b", "item#bang!", strings.Repeat("x", MaxSecretNameLength+1),
	} {
		if got := decryptString(t, c, name); got != "" {
			t.Errorf("%q: got %q", name, got)
		}
		if _, ok, err := c.MaxDecryptedLength(context.Background(), name); ok || err != nil {
			t.Errorf("%q: ok %v, err %v", name, ok, err)
		}
	}
	if got := vault.paths(); len(got) != 0 {
		t.Fatalf("Vault was called: %v", got)
	}
}

func TestIsValidSecretName_AcceptsPaths_UpToTheLimit(t *testing.T) {
	for name, want := range map[string]bool{
		"a":                                      true,
		"team-a/my_app/db.v2":                    true,
		"...x/x..":                               true,
		"myapp/db#password":                      false,
		strings.Repeat("x", MaxSecretNameLength): true,
		strings.Repeat("x", MaxSecretNameLength+1): false,
		"":     false,
		".":    false,
		"a/..": false,
	} {
		if got := IsValidSecretName(name); got != want {
			t.Errorf("IsValidSecretName(%.20q) = %v", name, got)
		}
	}
}

func TestConcurrentMissesOnDifferentKeys_ShareOneRead(t *testing.T) {
	vault := newFakeVault(t)
	vault.setKV2(t, "secret", "shared", map[string]any{"a": "1", "b": "2", "value": "3"})
	release := make(chan struct{})
	vault.onRead = func(*http.Request) { <-release }
	c := newCache(t, vault, Options{})

	names := []string{"shared#a", "shared#b", "shared"}
	results := make([]string, len(names))
	var wg sync.WaitGroup
	for i, name := range names {
		wg.Go(func() { results[i], _ = tryDecrypt(c, name) })
	}
	time.Sleep(200 * time.Millisecond)
	close(release)
	wg.Wait()

	if !slices.Equal(results, []string{"1", "2", "3"}) {
		t.Fatalf("got %v", results)
	}
	if got := vault.paths(); len(got) != 1 {
		t.Fatalf("paths: %v", got)
	}
}

func TestACachedSecret_StillDecryptsAfterTheRingRotates(t *testing.T) {
	vault := newFakeVault(t)
	vault.setKV2(t, "secret", "before", map[string]any{"value": "v1 value"})
	vault.setKV2(t, "secret", "after", map[string]any{"value": "v2 value"})
	ring := newTestRing(t, 1)
	c, err := New(newClient(t, vault.server.URL), ring, Options{})
	if err != nil {
		t.Fatal(err)
	}

	if got := decryptString(t, c, "before"); got != "v1 value" {
		t.Fatalf("got %q", got)
	}
	if err := ring.Add(context.Background(), 2, newTestKey(t)); err != nil {
		t.Fatal(err)
	}
	if decryptString(t, c, "after") != "v2 value" || decryptString(t, c, "before") != "v1 value" {
		t.Fatal("a value didn't survive rotation")
	}
}

func TestInACollection_OnlyNamesTheEarlierSourcesMiss_ReachVault(t *testing.T) {
	vault := newFakeVault(t)
	vault.setKV2(t, "secret", "from-vault", map[string]any{"value": "vault value"})
	ring := newTestRing(t)
	local := cache.New(ring)
	if err := local.Add(context.Background(), "ConnectionStrings:Admin", []byte("local value")); err != nil {
		t.Fatal(err)
	}
	vaultCache, err := New(newClient(t, vault.server.URL), ring, Options{})
	if err != nil {
		t.Fatal(err)
	}
	collection := cache.NewCollection(local, vaultCache)

	result := make([]byte, 64)
	for name, want := range map[string]string{"ConnectionStrings:Admin": "local value", "from-vault": "vault value"} {
		n, err := collection.Decrypt(context.Background(), name, result)
		if err != nil || string(result[:n]) != want {
			t.Fatalf("%s: got %q, %v", name, result[:n], err)
		}
	}
	if got := vault.paths(); !slices.Equal(got, []string{"/v1/secret/data/from-vault"}) {
		t.Fatalf("paths: %v", got)
	}
}

func TestWithSensitiveLogging_AReadLogsThePathOnly_AndAFailureLogsAnError(t *testing.T) {
	vault := newFakeVault(t)
	vault.setKV2(t, "secret", "myapp/Item", map[string]any{"value": "never-logged"})
	vault.answer("/v1/secret/data/other", answer{http.StatusServiceUnavailable, `{"errors":["Vault is sealed"]}`})
	var logged bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelDebug}))
	c := newCache(t, vault, Options{Logger: logger})

	original := diagnostics.Cache.SensitiveLoggingEnabled()
	diagnostics.Cache.SetSensitiveLogging(true)
	t.Cleanup(func() { diagnostics.Cache.SetSensitiveLogging(original) })
	if got := decryptString(t, c, "myapp/Item"); got != "never-logged" {
		t.Fatalf("got %q", got)
	}
	if _, err := tryDecrypt(c, "other"); !errors.Is(err, ErrVault) {
		t.Fatalf("got %v", err)
	}

	text := logged.String()
	if !strings.Contains(text, "myapp/Item") || !strings.Contains(text, "level=ERROR") {
		t.Fatalf("log: %s", text)
	}
	if strings.Contains(text, "never-logged") || strings.Contains(text, testToken) {
		t.Fatalf("the log holds a secret: %s", text)
	}
}
