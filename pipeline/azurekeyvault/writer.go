package azurekeyvault

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/pipeline"
)

// MaxSecretNameLength is the longest name Key Vault accepts for a secret.
const MaxSecretNameLength = 127

// ErrInvalidArgument reports an argument New refuses: a vault URL that isn't an https URL, no
// credential, or client options that log response bodies - and, matching
// pipeline.ErrInvalidArgument too, whatever pipeline.New refuses of the protector and the secret
// names.
var ErrInvalidArgument = errors.New("azurekeyvault: invalid argument")

// Options are a writer's optional settings; the zero value gives its Key Vault client the SDK's
// defaults.
type Options struct {
	// ClientOptions configure the writer's Key Vault client - retries, transport, the API version,
	// challenge resource verification; nil is the SDK's defaults. They are copied by New, which adds
	// its own policy to the copy only: the caller's value, and any other client built from it, is
	// left as it was. Options that log response bodies (Logging.IncludeBody) are refused, since they
	// would log every secret's value.
	ClientOptions *azsecrets.ClientOptions
}

// New returns a *pipeline.Writer pulling secretNames from the vault at vaultURL
// (https://{vault}.vault.azure.net/), every call authorized by credential - a managed identity, or
// azidentity.DefaultAzureCredential or WorkloadIdentityCredential, which find Microsoft Entra
// Workload Identity on AKS - and every value encrypted by protector: the Go port of the .NET
// AzureKeyVaultSecretPipelineWriter. Each secret's current version is read once with GetSecret, so
// the principal needs only get on secrets (the Key Vault Secrets User role), never list; naming,
// encrypting, keeping and writing are the pipeline.Writer's.
//
// A secret name is a Key Vault secret name - 1-127 ASCII letters, digits and hyphens - optionally
// with a key after '#': "Api-Key" reads the secret's whole value, and "Db-Login#password" the
// password member of a secret whose value is a JSON object (written as Api-Key and
// Db-Login__password). A member's string is read as its text; a number, true or false as its JSON
// text. Key Vault compares names ignoring case; so do file names, so two names differing only in
// case are refused.
//
// A secret that doesn't exist (404) or whose value is empty is reported missing
// (pipeline.ErrSecretNotFound). A response body that isn't one a Get Secret answers with, or a JSON
// object value holding a key twice, fails the pull with pipeline.ErrInvalidSecretData, and isn't
// retried. Any other failure is returned as the Azure SDK's error: an *azcore.ResponseError for a
// refusal (access denied, a disabled secret), or the credential's or transport's error (no token,
// the vault unreachable).
//
// The secret never becomes a Go string. The writer makes its own azsecrets.Client, with a pipeline
// policy that stops azcore buffering the Get Secret response, reads the body off the network into a
// buffer of its own (pipeline.ReadBody), encrypts the value from there, and hands the SDK an empty
// object in its place; every buffer that held the value is zeroed once it is encrypted. What can't
// be zeroed is below the pipeline: the HTTP stack's own buffers (TLS decryption, the connection's
// read buffer, and gzip's when the transport decompresses a response). Retries and timeouts are the
// client options'. The protector is the caller's: the writer never closes it. New makes no call.
//
// It fails with ErrInvalidArgument when vaultURL isn't an https URL, credential is nil, or
// options.ClientOptions log response bodies; with the SDK's error when it refuses the client
// options; and, matching pipeline.ErrInvalidArgument too, when pipeline.New refuses the protector or
// secretNames: no protector, no names, a name Key Vault can't hold (see IsValidSecretName) with a
// key after '#' if any, one whose file name cache/filepersecret can't read, or two with the same
// file name in any case.
func New(vaultURL string, credential azcore.TokenCredential, protector hkdfguard.PipelineDataProtector, secretNames []string,
	options Options) (*pipeline.Writer, error) {
	if u, err := url.Parse(vaultURL); err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("%w: the vault URL '%s' isn't one: https://{vault}.vault.azure.net/", ErrInvalidArgument, vaultURL)
	}
	if credential == nil {
		return nil, fmt.Errorf("%w: a credential is required (an azcore.TokenCredential, from azidentity for example)", ErrInvalidArgument)
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
	// sees the empty object.
	clientOptions.PerRetryPolicies = append(slices.Clip(clientOptions.PerRetryPolicies), capturePolicy{})
	client, err := azsecrets.NewClient(vaultURL, credential, &clientOptions)
	if err != nil {
		return nil, err
	}
	writer, err := pipeline.New(protector, secretNames, secretStore{client: client}, pipeline.Options{})
	if err != nil {
		return nil, &argumentError{err: err}
	}
	return writer, nil
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

// secretStore reads one secret by name from one vault, for a pipeline.Writer.
type secretStore struct {
	client *azsecrets.Client
}

func (secretStore) IsValidName(name string) bool { return IsValidSecretName(name) }

// ReadSecret reads the secret's current version. The value reaches secret through capturePolicy;
// what GetSecret returns holds nothing, so it isn't read here.
func (s secretStore) ReadSecret(ctx context.Context, name string, secret *pipeline.Secret) error {
	_, err := s.client.GetSecret(context.WithValue(ctx, captureKey{}, &capture{ctx: ctx, secret: secret}), name, "", nil)
	if err != nil {
		secret.Reset()
	}
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

// argumentError is what pipeline.New refused, matching both ErrInvalidArgument and
// pipeline.ErrInvalidArgument, with pipeline.New's message.
type argumentError struct{ err error }

func (e *argumentError) Error() string   { return e.err.Error() }
func (e *argumentError) Unwrap() []error { return []error{ErrInvalidArgument, e.err} }

var _ policy.Policy = capturePolicy{}
