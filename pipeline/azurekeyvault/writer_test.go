package azurekeyvault

import (
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/pipeline"
	"github.com/runsecure/hkdfguard-go/pipeline/internal/pipelinetest"
)

// contractStore is the writer, with a real azsecrets client and its own pipeline policy, against a
// fake Key Vault transport.
type contractStore struct{ vault *fakeVault }

func (c contractStore) NewWriter(protector hkdfguard.PipelineDataProtector, secretNames []string) (hkdfguard.SecretPipelineWriter, error) {
	return New(vaultURL, fakeCredential{}, protector, secretNames, Options{ClientOptions: c.vault.options()})
}
func (c contractStore) SetText(name, text string) { c.vault.set(name, text) }
func (c contractStore) SetKeys(name, json string) { c.vault.set(name, json) }
func (c contractStore) FailReads()                { c.vault.fail(http.StatusForbidden) }
func (c contractStore) Reads() []string           { return c.vault.getNames() }

func (c contractStore) IsReadFailure(err error) bool {
	var responseErr *azcore.ResponseError
	return errors.As(err, &responseErr) && responseErr.StatusCode == http.StatusForbidden
}

// The writer's contract, with a real azsecrets client and its own pipeline policy against a fake
// Key Vault.
func TestContract(t *testing.T) {
	pipelinetest.Contract(t, func(*testing.T) pipelinetest.Store { return contractStore{newFakeVault()} })
}

func newWriter(t *testing.T, vault *fakeVault, protector hkdfguard.PipelineDataProtector, names ...string) *pipeline.Writer {
	t.Helper()
	w, err := New(vaultURL, fakeCredential{}, protector, names, Options{ClientOptions: vault.options()})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func TestTheSDK_SeesOnlyAnEmptyObject(t *testing.T) {
	vault := newFakeVault()
	vault.set("Item", "s3cret")
	w := newWriter(t, vault, pipelinetest.NewProtector(t), "Item")

	if err := w.PullSecrets(t.Context()); err != nil {
		t.Fatal(err)
	}

	if got := vault.bodies(); !slices.Equal(got, []string{"{}"}) {
		t.Fatalf("the SDK parsed %q; want only an empty object", got)
	}
	if len(vault.unexpected) != 0 {
		t.Fatalf("unexpected requests: %q", vault.unexpected)
	}
}

func TestAnotherClientOnTheSameOptions_ReadsSecretsAsUsual(t *testing.T) {
	vault := newFakeVault()
	vault.set("Item", "s3cret")
	options := vault.options()
	newWriter := func() {
		if _, err := New(vaultURL, fakeCredential{}, pipelinetest.NewProtector(t), []string{"Item"}, Options{ClientOptions: options}); err != nil {
			t.Fatal(err)
		}
	}
	newWriter()
	other, err := azsecrets.NewClient(vaultURL, fakeCredential{}, options)
	if err != nil {
		t.Fatal(err)
	}

	response, err := other.GetSecret(t.Context(), "Item", "", nil)

	if err != nil || response.Value == nil || *response.Value != "s3cret" {
		t.Fatalf("GetSecret: %v", err)
	}
	if len(options.PerRetryPolicies) != 0 {
		t.Fatalf("the caller's options were changed: %d per-retry policies", len(options.PerRetryPolicies))
	}
}

func TestANameWithoutAKey_ReadsTheWholeValue(t *testing.T) {
	vault := newFakeVault()
	vault.set("Db-Login", `{"user":"app"}`)
	protector := pipelinetest.NewProtector(t)
	w := newWriter(t, vault, protector, "Db-Login", "Db-Login#user")

	if err := w.PullSecrets(t.Context()); err != nil {
		t.Fatal(err)
	}

	secrets := w.ProtectedSecrets()
	if got := pipelinetest.Decrypt(t, protector, secrets["Db-Login"], "Db-Login"); got != `{"user":"app"}` {
		t.Errorf("Db-Login is %q", got)
	}
	if got := pipelinetest.Decrypt(t, protector, secrets["Db-Login__user"], "Db-Login__user"); got != "app" {
		t.Errorf("Db-Login__user is %q", got)
	}
	if got := vault.getNames(); !slices.Equal(got, []string{"Db-Login"}) {
		t.Fatalf("read %q; want Db-Login once", got)
	}
}

func TestAResponseThatIsntKeyVaultsJSON_IsRefused_AndNotRetried(t *testing.T) {
	for _, body := range []string{`{"value":"x" `, `["value"]`, `{"value":"a","value":"b"}`} {
		t.Run(body, func(t *testing.T) {
			vault := newFakeVault()
			vault.rawBody = body
			options := vault.options()
			options.Retry = policy.RetryOptions{MaxRetries: 2}
			w, err := New(vaultURL, fakeCredential{}, pipelinetest.NewProtector(t), []string{"Item"}, Options{ClientOptions: options})
			if err != nil {
				t.Fatal(err)
			}

			if err := w.PullSecrets(t.Context()); !errors.Is(err, pipeline.ErrInvalidSecretData) {
				t.Fatalf("PullSecrets: %v; want pipeline.ErrInvalidSecretData", err)
			}
			if len(w.ProtectedSecrets()) != 0 {
				t.Fatal("something was kept")
			}
			if got := vault.getNames(); len(got) != 1 {
				t.Fatalf("read %q; want one try", got)
			}
		})
	}
}

func TestAResponseWithoutAStringValue_HoldsNothing(t *testing.T) {
	vault := newFakeVault()
	vault.rawBody = `{"value":5,"id":"x"}`
	w := newWriter(t, vault, pipelinetest.NewProtector(t), "Item")

	if err := w.PullSecrets(t.Context()); !errors.Is(err, pipeline.ErrSecretNotFound) {
		t.Fatalf("PullSecrets: %v; want pipeline.ErrSecretNotFound", err)
	}
}

func TestANameKeyVaultCantHold_IsRefused(t *testing.T) {
	vault := newFakeVault()
	protector := pipelinetest.NewProtector(t)
	for _, secretName := range []string{"Db_Password", "prod/app", strings.Repeat("a", MaxSecretNameLength+1)} {
		_, err := New(vaultURL, fakeCredential{}, protector, []string{secretName}, Options{ClientOptions: vault.options()})
		if !errors.Is(err, ErrInvalidArgument) || !errors.Is(err, pipeline.ErrInvalidArgument) {
			t.Errorf("%.20q: %v; want ErrInvalidArgument and pipeline.ErrInvalidArgument", secretName, err)
		}
	}
}

func TestIsValidSecretName_IsKeyVaultsRule(t *testing.T) {
	for name, want := range map[string]bool{
		"Db-Login-2":                               true,
		strings.Repeat("a", MaxSecretNameLength):   true,
		strings.Repeat("a", MaxSecretNameLength+1): false,
		"": false,
	} {
		if got := IsValidSecretName(name); got != want {
			t.Errorf("IsValidSecretName(%.20q) = %v; want %v", name, got, want)
		}
	}
}

func TestNew_ChecksTheVaultCredentialAndOptions(t *testing.T) {
	protector := pipelinetest.NewProtector(t)
	names := []string{"Item"}
	logging := &azsecrets.ClientOptions{}
	logging.Logging.IncludeBody = true
	for name, create := range map[string]func() error{
		"no vault URL": func() error { _, err := New("", fakeCredential{}, protector, names, Options{}); return err },
		"an http vault URL": func() error {
			_, err := New("http://x.vault.azure.net/", fakeCredential{}, protector, names, Options{})
			return err
		},
		"no credential": func() error { _, err := New(vaultURL, nil, protector, names, Options{}); return err },
		"logged bodies": func() error {
			_, err := New(vaultURL, fakeCredential{}, protector, names, Options{ClientOptions: logging})
			return err
		},
	} {
		if err := create(); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("%s: %v; want ErrInvalidArgument", name, err)
		}
	}
	if _, err := New(vaultURL, fakeCredential{}, protector, names, Options{}); err != nil {
		t.Fatalf("the defaults: %v", err)
	}
}
