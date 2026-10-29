package azurekeyvault

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/cache"
	"github.com/runsecure/hkdfguard-go/diagnostics"
)

// A real azsecrets client, with the cache's own pipeline policy, against a fake Key Vault transport.

func newCache(t *testing.T, credential azcore.TokenCredential, logger *slog.Logger) (*cache.RemoteCache, *fakeVault) {
	t.Helper()
	vault := newFakeVault()
	c, err := New(vaultURL, credential, newRing(t), Options{ClientOptions: vault.options(), Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	return c, vault
}

func requireMissing(t *testing.T, c hkdfguard.ProtectedReadOnlyCache, name string) {
	t.Helper()
	if n, err := c.Decrypt(t.Context(), name, make([]byte, 16)); n != 0 || err != nil {
		t.Fatalf("Decrypt(%q): %d, %v; want 0, nil", name, n, err)
	}
	if _, ok, err := c.MaxDecryptedLength(t.Context(), name); ok || err != nil {
		t.Fatalf("MaxDecryptedLength(%q): %v, %v; want false, nil", name, ok, err)
	}
}

func requireGets(t *testing.T, vault *fakeVault, want ...string) {
	t.Helper()
	if got := vault.getNames(); !slices.Equal(got, want) {
		t.Fatalf("Get Secret calls: %q; want %q", got, want)
	}
}

func TestDecrypt_OnMiss_FetchesTheOneSecret_ThenServesItFromTheCache(t *testing.T) {
	c, vault := newCache(t, fakeCredential{}, nil)
	vault.set("Db-Password", "s3cret")

	mustGet(t, c, "Db-Password", "s3cret")
	mustGet(t, c, "Db-Password", "s3cret")

	requireGets(t, vault, "Db-Password")
	if len(vault.unexpected) != 0 {
		t.Fatalf("unexpected requests: %q", vault.unexpected)
	}
}

// A key/value secret as AWS Secrets Manager's console stores one.
const keyValueSecret = `{
  "test-credential-1": "This is my first credential",
  "service-credential-3": "This is my third credential",
  "api-credential-21": "0k4sBPf0vQw6SDn6r7g4lMODn9bB5JrXyYVkvhFl3f0oM2xVhW3vXKz6u4Fuw2VwCs+6xXK8WaF9JUYg9l0L8Q==",
  "domain-credential-17": "fakedomain/thiscredential",
  "port": 5432
}`

func TestAJSONSecret_IsCachedWholeAndByKey_FromOneCall_AndTheSDKNeverSeesIt(t *testing.T) {
	c, vault := newCache(t, fakeCredential{}, nil)
	vault.set("App-Credentials", keyValueSecret)

	mustGet(t, c, "App-Credentials#api-credential-21", "0k4sBPf0vQw6SDn6r7g4lMODn9bB5JrXyYVkvhFl3f0oM2xVhW3vXKz6u4Fuw2VwCs+6xXK8WaF9JUYg9l0L8Q==")
	mustGet(t, c, "app-credentials#test-credential-1", "This is my first credential")
	mustGet(t, c, "APP-CREDENTIALS#domain-credential-17", "fakedomain/thiscredential")
	mustGet(t, c, "App-Credentials#port", "5432")
	mustGet(t, c, "App-Credentials", keyValueSecret)

	// Secret names ignore case; keys don't. A key the secret doesn't hold costs a fetch.
	requireMissing(t, c, "App-Credentials#PORT")

	requireGets(t, vault, "App-Credentials", "App-Credentials", "App-Credentials")
	for _, body := range vault.bodies() {
		if strings.Contains(body, "credential") {
			t.Fatalf("the SDK was given the secret: %s", body)
		}
	}
}

func TestTheSDK_IsOnlyEverGivenTheBodyWithTheValueBlanked(t *testing.T) {
	c, vault := newCache(t, fakeCredential{}, nil)
	vault.set("Db-Password", "s3cret")

	mustGet(t, c, "Db-Password", "s3cret")

	bodies := vault.bodies()
	if len(bodies) != 1 {
		t.Fatalf("bodies: %q; want one", bodies)
	}
	body := bodies[0]
	if strings.Contains(body, "s3cret") || !strings.Contains(body, `"value":""`) {
		t.Fatalf("body: %s; want the value blanked", body)
	}
	// Only the top-level value is taken: a nested property of the same name is left alone.
	if !strings.Contains(body, "a tag, not the secret") {
		t.Fatalf("body: %s; want the tag left alone", body)
	}
}

func TestAValueWithJSONEscapes_IsUnescapedExactly(t *testing.T) {
	c, vault := newCache(t, fakeCredential{}, nil)
	const secret = "p\"a\\ss/wörd\n\u0001秘密"
	vault.set("escaped", secret)

	mustGet(t, c, "escaped", secret)
	if bodies := vault.bodies(); len(bodies) != 1 || strings.Contains(bodies[0], "wörd") || strings.Contains(bodies[0], `wörd`) {
		t.Fatalf("bodies: %q; want one, the value blanked", bodies)
	}
}

func TestMaxDecryptedLength_OnMiss_FetchesTheSecret(t *testing.T) {
	c, vault := newCache(t, fakeCredential{}, nil)
	vault.set("api-key", "value")

	if n, ok, err := c.MaxDecryptedLength(t.Context(), "api-key"); !ok || err != nil || n < 5 {
		t.Fatalf("%d, %v, %v; want at least 5", n, ok, err)
	}
	mustGet(t, c, "api-key", "value")
	requireGets(t, vault, "api-key")
}

func TestNamesDifferingInCase_AreOneEntry_AndOneFetch(t *testing.T) {
	c, vault := newCache(t, fakeCredential{}, nil)
	vault.set("Db-Password", "s3cret")

	mustGet(t, c, "db-password", "s3cret")
	mustGet(t, c, "DB-PASSWORD", "s3cret")
	requireGets(t, vault, "db-password")
}

func TestAMissingSecret_IsMissing_AndIsLookedUpAgainUntilItExists(t *testing.T) {
	c, vault := newCache(t, fakeCredential{}, nil)

	requireMissing(t, c, "later") // Decrypt and MaxDecryptedLength: two fetches

	vault.set("later", "now here")
	mustGet(t, c, "later", "now here")
	if gets := vault.getNames(); len(gets) != 3 {
		t.Fatalf("Get Secret calls: %q; want 3", gets)
	}
}

func TestAnEmptySecret_IsReportedMissing(t *testing.T) {
	c, vault := newCache(t, fakeCredential{}, nil)
	vault.set("empty", "")

	requireMissing(t, c, "empty")
}

func TestANameKeyVaultCantHold_IsMissing_WithoutCallingTheVault(t *testing.T) {
	for _, name := range []string{"", "ConnectionStrings:Admin", "db_password", "../keys/other", "name/version",
		"name?api-version=1", "café", "has space", strings.Repeat("x", MaxSecretNameLength+1)} {
		t.Run(name, func(t *testing.T) {
			c, vault := newCache(t, fakeCredential{}, nil)

			requireMissing(t, c, name)
			requireGets(t, vault)
		})
	}
}

func TestIsValidSecretName_AcceptsLettersDigitsAndHyphens_UpTo127(t *testing.T) {
	for _, name := range []string{"a", "Db-Password-2", "-", strings.Repeat("x", MaxSecretNameLength)} {
		if !IsValidSecretName(name) {
			t.Errorf("IsValidSecretName(%q) = false", name)
		}
	}
	for _, name := range []string{"", strings.Repeat("x", MaxSecretNameLength+1), "a_b", "a.b", "a#b", "é"} {
		if IsValidSecretName(name) {
			t.Errorf("IsValidSecretName(%q) = true", name)
		}
	}
}

func TestAVaultFailure_IsReturnedAsTheResponseError_AndIsRetriedOnTheNextLookup(t *testing.T) {
	c, vault := newCache(t, fakeCredential{}, nil)
	vault.set("item", "value")
	vault.fail(http.StatusForbidden)

	_, err := c.Decrypt(t.Context(), "item", make([]byte, 16))
	var responseErr *azcore.ResponseError
	if !errors.As(err, &responseErr) || responseErr.StatusCode != http.StatusForbidden || responseErr.ErrorCode != "Forbidden" {
		t.Fatalf("got %v; want a 403 *azcore.ResponseError", err)
	}

	vault.fail(0)
	mustGet(t, c, "item", "value")
	if gets := vault.getNames(); len(gets) != 2 {
		t.Fatalf("Get Secret calls: %q; want 2", gets)
	}
}

func TestAResponseThatIsNotJSON_IsRefused_AndNotRetried(t *testing.T) {
	vault := newFakeVault()
	vault.rawBody = "not json"
	options := vault.options()
	options.Retry = policy.RetryOptions{MaxRetries: 3, RetryDelay: time.Millisecond, MaxRetryDelay: time.Millisecond}
	c, err := New(vaultURL, fakeCredential{}, newRing(t), Options{ClientOptions: options})
	if err != nil {
		t.Fatal(err)
	}

	_, err = c.Decrypt(t.Context(), "item", make([]byte, 16))
	var captureErr *captureError
	if !errors.Is(err, cache.ErrInvalidSecretData) || errors.As(err, &captureErr) {
		t.Fatalf("got %v; want cache.ErrInvalidSecretData, as it is", err)
	}
	if strings.Contains(err.Error(), "not json") {
		t.Fatalf("the error quotes the body: %v", err)
	}
	requireGets(t, vault, "item")
}

func TestACredentialFailure_IsReturned(t *testing.T) {
	c, vault := newCache(t, throwingCredential{}, nil)
	vault.set("item", "value")

	if _, err := c.Decrypt(t.Context(), "item", make([]byte, 16)); !errors.Is(err, errNoToken) {
		t.Fatalf("got %v; want the credential's error", err)
	}
	requireGets(t, vault)
}

func TestConcurrentMissesOnOneName_ShareOneFetch(t *testing.T) {
	c, vault := newCache(t, fakeCredential{}, nil)
	vault.set("shared", "value")
	release := make(chan struct{})
	vault.onGet = func() {
		select {
		case <-release:
		case <-time.After(10 * time.Second):
		}
	}

	var wg sync.WaitGroup
	values := make([]string, 8)
	for i := range values {
		wg.Go(func() { values[i], _ = get(t, c, "shared") })
	}
	time.Sleep(200 * time.Millisecond)
	close(release)
	wg.Wait()

	for _, v := range values {
		if v != "value" {
			t.Fatalf("values: %q; want each to be value", values)
		}
	}
	requireGets(t, vault, "shared")
}

func TestALargeSecret_RoundTrips(t *testing.T) {
	c, vault := newCache(t, fakeCredential{}, nil)
	large := strings.Repeat("é-秘密-", 1500) // past the capture's first 16 KiB buffer
	vault.set("large", large)

	mustGet(t, c, "large", large)
}

func TestACachedSecret_StillDecryptsAfterTheRingRotates(t *testing.T) {
	vault := newFakeVault()
	ring := newRing(t)
	c, err := New(vaultURL, fakeCredential{}, ring, Options{ClientOptions: vault.options()})
	if err != nil {
		t.Fatal(err)
	}
	vault.set("before", "v1 value")
	vault.set("after", "v2 value")

	mustGet(t, c, "before", "v1 value")
	if err := ring.Add(t.Context(), 2, newTestKey(t)); err != nil {
		t.Fatal(err)
	}
	mustGet(t, c, "after", "v2 value")
	mustGet(t, c, "before", "v1 value")
}

func TestInACollection_OnlyNamesTheEarlierSourcesMiss_ReachTheVault(t *testing.T) {
	vaultCache, vault := newCache(t, fakeCredential{}, nil)
	vault.set("from-vault", "vault value")
	local := cache.New(newRing(t))
	if err := local.Add(t.Context(), "ConnectionStrings:Admin", []byte("local value")); err != nil {
		t.Fatal(err)
	}
	collection := cache.NewCollection(local, vaultCache)

	mustGet(t, collection, "ConnectionStrings:Admin", "local value")
	mustGet(t, collection, "from-vault", "vault value")
	requireGets(t, vault, "from-vault")
}

func TestWithSensitiveLogging_AFetchLogsTheNameOnly_AndAFailureLogsAnError(t *testing.T) {
	handler := &capturingHandler{}
	c, vault := newCache(t, fakeCredential{}, slog.New(handler))
	vault.set("item", "never-logged")

	original := diagnostics.Cache.SensitiveLoggingEnabled()
	diagnostics.Cache.SetSensitiveLogging(true)
	t.Cleanup(func() { diagnostics.Cache.SetSensitiveLogging(original) })

	mustGet(t, c, "item", "never-logged")
	vault.fail(http.StatusInternalServerError)
	if _, err := c.Decrypt(t.Context(), "other", make([]byte, 16)); err == nil {
		t.Fatal("want the vault's failure")
	}

	var debugNamesItem, errorHasResponseError bool
	handler.mu.Lock()
	defer handler.mu.Unlock()
	for _, r := range handler.records {
		text := r.Message
		r.Attrs(func(a slog.Attr) bool {
			text += " " + a.Value.String()
			var responseErr *azcore.ResponseError
			if err, ok := a.Value.Any().(error); ok && r.Level == slog.LevelError && errors.As(err, &responseErr) {
				errorHasResponseError = true
			}
			return true
		})
		if strings.Contains(text, "never-logged") {
			t.Fatalf("a record holds the value: %s", text)
		}
		debugNamesItem = debugNamesItem || (r.Level == slog.LevelDebug && strings.Contains(r.Message, "item"))
	}
	if !debugNamesItem || !errorHasResponseError {
		t.Fatalf("records: %v; want a debug record naming item and an error record with the response error", handler.records)
	}
}

func TestOptionsThatLogResponseBodies_AreRefused(t *testing.T) {
	options := &azsecrets.ClientOptions{ClientOptions: azcore.ClientOptions{Logging: policy.LogOptions{IncludeBody: true}}}

	if _, err := New(vaultURL, fakeCredential{}, newRing(t), Options{ClientOptions: options}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("got %v; want ErrInvalidArgument", err)
	}
}

type markerPolicy struct{}

func (markerPolicy) Do(req *policy.Request) (*http.Response, error) { return req.Next() }

func TestTheCallersOptions_AreNotChanged_AndAnotherClientBuiltFromThemReadsSecretsAsUsual(t *testing.T) {
	vault := newFakeVault()
	vault.set("Db-Password", "s3cret")
	options := vault.options()
	// Spare capacity an append would write into, were the caller's slice appended to.
	options.PerRetryPolicies = make([]policy.Policy, 1, 4)
	options.PerRetryPolicies[0] = markerPolicy{}
	before := *options

	c, err := New(vaultURL, fakeCredential{}, newRing(t), Options{ClientOptions: options})
	if err != nil {
		t.Fatal(err)
	}
	mustGet(t, c, "Db-Password", "s3cret")

	if len(options.PerRetryPolicies) != 1 || options.PerRetryPolicies[:2][1] != nil ||
		len(options.PerCallPolicies) != len(before.PerCallPolicies) || options.Transport != before.Transport {
		t.Fatalf("the caller's options were changed: %+v", options)
	}
	client, err := azsecrets.NewClient(vaultURL, fakeCredential{}, options)
	if err != nil {
		t.Fatal(err)
	}
	got, err := client.GetSecret(t.Context(), "Db-Password", "", nil)
	if err != nil || got.Value == nil || *got.Value != "s3cret" {
		t.Fatalf("got %v, %v; want the secret", got.Value, err)
	}
}

func TestThePolicy_LeavesARequestWithoutASinkAlone(t *testing.T) {
	vault := newFakeVault()
	vault.set("Db-Password", "s3cret")
	options := vault.options()
	options.PerRetryPolicies = []policy.Policy{capturePolicy{}}
	client, err := azsecrets.NewClient(vaultURL, fakeCredential{}, options)
	if err != nil {
		t.Fatal(err)
	}

	got, err := client.GetSecret(t.Context(), "Db-Password", "", nil)
	if err != nil || got.Value == nil || *got.Value != "s3cret" {
		t.Fatalf("got %v, %v; want the secret", got.Value, err)
	}
}

func TestTheDefaultOptions_MakeNoCallUntilASecretIsRequested(t *testing.T) {
	c, err := New("https://example.vault.azure.net/", throwingCredential{}, newRing(t), Options{})
	if err != nil {
		t.Fatal(err)
	}

	// An invalid name never reaches the client, so this needs no network or credential.
	requireMissing(t, c, "not:a:secret")
}

func TestNew_RefusesMissingOrInvalidArguments(t *testing.T) {
	ring := newRing(t)
	for name, call := range map[string]func() error{
		"empty URL": func() error { _, err := New("", fakeCredential{}, ring, Options{}); return err },
		"http URL": func() error {
			_, err := New("http://myvault.vault.azure.net/", fakeCredential{}, ring, Options{})
			return err
		},
		"relative URL":  func() error { _, err := New("myvault.vault.azure.net", fakeCredential{}, ring, Options{}); return err },
		"no credential": func() error { _, err := New(vaultURL, nil, ring, Options{}); return err },
		"no ring":       func() error { _, err := New(vaultURL, fakeCredential{}, nil, Options{}); return err },
	} {
		if err := call(); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("%s: got %v; want ErrInvalidArgument", name, err)
		}
	}
}

func TestAnEndedContext_IsReturned(t *testing.T) {
	c, vault := newCache(t, fakeCredential{}, nil)
	vault.set("item", "value")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if _, err := c.Decrypt(ctx, "item", make([]byte, 16)); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v; want context.Canceled", err)
	}
}
