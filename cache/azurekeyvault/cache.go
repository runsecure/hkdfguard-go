package azurekeyvault

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/cache"
)

// MaxSecretNameLength is the longest name Key Vault accepts for a secret.
const MaxSecretNameLength = 127

// ErrInvalidArgument reports an argument New refuses: a vault URL that isn't an https URL, no
// credential or key ring, or client options that log response bodies.
var ErrInvalidArgument = errors.New("azurekeyvault: invalid argument")

// Options are a cache's optional settings; the zero value gives its Key Vault client the SDK's
// defaults and logs nothing.
type Options struct {
	// ClientOptions configure the cache's Key Vault client - retries, transport, the API version,
	// challenge resource verification; nil is the SDK's defaults. They are copied by New, which adds
	// its own policy to the copy only: the caller's value, and any other client built from it, is
	// left as it was. Options that log response bodies (Logging.IncludeBody) are refused, since they
	// would log every secret's value.
	ClientOptions *azsecrets.ClientOptions

	// Logger receives a debug record per fetched name while sensitive logging is enabled
	// (diagnostics.Cache), and an error record per failed fetch; see cache.RemoteOptions.
	Logger *slog.Logger
}

// New returns a cache.RemoteCache over the secrets in the vault at vaultURL
// (https://{vault}.vault.azure.net/), every call authorized by credential - a managed identity,
// say, or azidentity.DefaultAzureCredential, which finds it - and every fetched secret encrypted
// under ring's current key. The ring is the caller's: the cache never closes keys. The first lookup
// of a name that isn't cached yet reads that one secret (its current version) with GetSecret;
// fetching, encryption, caching and telemetry are cache.RemoteCache's. It never lists the vault's
// secrets, so the principal needs only get on secrets (the Key Vault Secrets User role), never list.
// No call is made until a secret is looked up.
//
// Key Vault secret names are 1-127 ASCII letters, digits and hyphens, compared ignoring case, so
// "Db-Password" and "DB-PASSWORD" are one entry and one secret. Any other name (a configuration
// path such as "ConnectionStrings:Admin", say) is reported missing without a call - and is never
// spliced into a request URL.
//
// A secret whose value is a JSON object, such as {"username":"app","password":"..."}, is cached
// whole under its name and each member under "name#key" - "Db-Login#password" - all from one call
// (see cache.RemoteCache). Keys are matched exactly, though secret names aren't.
//
// A secret that doesn't exist (404) or whose value is empty is reported missing. Any other failure
// is returned as the Azure SDK's error: an *azcore.ResponseError for a refusal (access denied, a
// disabled secret), or the credential's or transport's error (no token, the vault unreachable). A
// response body that isn't one a Get Secret answers with fails with cache.ErrInvalidSecretData,
// and isn't retried.
//
// The secret never becomes a Go string. The cache makes its own azsecrets.Client, with a pipeline
// policy that stops azcore buffering the Get Secret response, reads the body off the network into a
// buffer of its own, takes the value out of it as bytes (cache.CaptureJSONBody), and hands the SDK
// the body with the value blanked; every buffer here that held the value is zeroed once it is
// encrypted. What can't be zeroed is below the pipeline: the HTTP stack's own buffers (TLS
// decryption, the connection's read buffer, and gzip's when the transport decompresses a response).
//
// It fails with ErrInvalidArgument when vaultURL isn't an https URL, credential or ring is nil, or
// options.ClientOptions log response bodies; or with the SDK's error when it refuses the client
// options.
func New(vaultURL string, credential azcore.TokenCredential, ring hkdfguard.KeyRing, options Options) (*cache.RemoteCache, error) {
	if u, err := url.Parse(vaultURL); err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("%w: the vault URL '%s' isn't one: https://{vault}.vault.azure.net/", ErrInvalidArgument, vaultURL)
	}
	if credential == nil {
		return nil, fmt.Errorf("%w: a credential is required (an azcore.TokenCredential, from azidentity for example)", ErrInvalidArgument)
	}
	if ring == nil {
		return nil, fmt.Errorf("%w: a key ring is required", ErrInvalidArgument)
	}

	var clientOptions azsecrets.ClientOptions
	if options.ClientOptions != nil {
		clientOptions = *options.ClientOptions
	}
	if clientOptions.Logging.IncludeBody {
		return nil, fmt.Errorf("%w: logging response bodies would log every secret's value; turn Logging.IncludeBody off for this client", ErrInvalidArgument)
	}
	// Clipped, so the append copies rather than writing into spare capacity of the caller's slice.
	// Last of the per-retry policies: closest to the transport, so every policy the caller added
	// sees the body with the value blanked.
	clientOptions.PerRetryPolicies = append(slices.Clip(clientOptions.PerRetryPolicies), capturePolicy{})
	client, err := azsecrets.NewClient(vaultURL, credential, &clientOptions)
	if err != nil {
		return nil, err
	}
	return cache.NewRemote(ring, secretStore{client: client}, cache.RemoteOptions{
		Matching: cache.IgnoreASCIICase,
		Logger:   options.Logger,
	})
}

// IsValidSecretName reports whether Key Vault accepts name as a secret name: 1-127 ASCII letters,
// digits and hyphens.
func IsValidSecretName(name string) bool {
	if name == "" || len(name) > MaxSecretNameLength {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// secretStore reads one secret by name from one vault, for a cache.RemoteCache.
type secretStore struct {
	client *azsecrets.Client
}

func (secretStore) IsValidName(name string) bool { return IsValidSecretName(name) }

// Fetch reads the secret's current version. The value reaches sink through capturePolicy; what
// GetSecret returns holds it blanked, so it isn't read here.
func (s secretStore) Fetch(ctx context.Context, name string, sink *cache.SecretSink) error {
	_, err := s.client.GetSecret(context.WithValue(ctx, sinkKey{}, sink), name, "", nil)
	var responseErr *azcore.ResponseError
	var captureErr *captureError
	switch {
	case errors.As(err, &responseErr) && responseErr.StatusCode == http.StatusNotFound:
		return nil // missing: nothing handed over
	case errors.As(err, &captureErr):
		return captureErr.err
	}
	return err
}

var _ policy.Policy = capturePolicy{}
