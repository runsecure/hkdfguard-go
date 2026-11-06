package hashicorpvault

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/hashicorp/vault/api"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/internal/vaultcheck"
	"github.com/runsecure/hkdfguard-go/pipeline"
)

// MaxSecretNameLength is the longest secret path read.
const MaxSecretNameLength = 512

const (
	defaultMountPath = "secret"
	defaultKey       = "value"
)

// KVVersion is the version of a KV secrets engine, which decides its read path and response shape.
type KVVersion int

const (
	// V1 is KV version 1: one unversioned set of keys per path, read at {mount}/{path}.
	V1 KVVersion = 1

	// V2 is KV version 2: versioned secrets, read at {mount}/data/{path}; the latest version is
	// read. The zero KVVersion means V2.
	V2 KVVersion = 2
)

// Options are which KV secrets engine New's writer reads, and what it accepts of the client; the
// zero value reads KV version 2 at "secret", reading the key "value" for a name without one.
//
// Everything about reaching Vault - its address, TLS, the namespace, the token and how it is
// obtained, the timeout and the retries - is the *api.Client's, configured by the application: see
// the package documentation.
type Options struct {
	// MountPath is where the KV secrets engine is mounted, e.g. "secret" (used when empty) or
	// "kv/team-a".
	MountPath string

	// KVVersion is the engine's version: V2 (used when zero) or V1.
	KVVersion KVVersion

	// DefaultKey is the key read from a secret named without one: "myapp/db" reads this key of the
	// secret at myapp/db, while "myapp/db#password" reads its password key. "value" when empty.
	DefaultKey string

	// AllowRedirects accepts a client that follows redirects, sending the Vault token along to every
	// redirect target. Set it only when every address a redirect could lead to may see the token.
	// Default false: New refuses a client that would follow one (see New).
	AllowRedirects bool
}

// secretStore is the pipeline.SecretStore over one KV engine, reached through the application's
// client.
type secretStore struct {
	client     *api.Client
	readPrefix string   // the engine's read path, before the secret's path: "secret/data/"
	dataPath   []string // the member names leading to the secret's keys in a response
}

// New returns a *pipeline.Writer pulling secretNames from one HashiCorp Vault KV secrets engine
// through client, every value encrypted by protector - the Go port of the .NET
// HashiCorpVaultSecretPipelineWriter. Each secret is read once (GET on its path through
// client.Logical().ReadRawWithContext; for KV version 2, its latest version); naming, encrypting,
// keeping and writing are the pipeline.Writer's. It never lists secrets, so the token's policy needs
// only read on the paths it reads.
//
// A secret name is a path within the engine, with the key to read after '#': "myapp/db#password"
// reads the password key of the secret at myapp/db, and "myapp/db" reads its Options.DefaultKey
// (written as myapp__db__password and myapp__db). A string is read as its text; a number, true or
// false as its JSON text.
//
// A secret that doesn't exist (404 with no errors, as Vault answers), whose latest version is
// deleted or destroyed, or that has no such key, or whose value there is empty or isn't a value, is
// reported missing (pipeline.ErrSecretNotFound). Any other answer - 403 for a token that is invalid
// or not allowed to read the path, a 404 naming an error such as a mount that doesn't exist, 503
// while sealed, a redirect that isn't followed - and a read that couldn't be made, fails the pull
// with an *Error (ErrVault) carrying Vault's status and errors; a body that isn't Vault's JSON, or
// holds a key twice, with pipeline.ErrInvalidSecretData. Retries, the timeout and the token are the
// client's: a read is one ReadRawWithContext, which the client retries and times out as it is
// configured to, under the pull's context.
//
// The secret never becomes a string: the raw response's body is read off the network into a buffer
// of the writer's own (pipeline.ReadBody), and each value is unescaped into another and encrypted
// from there; every buffer that held it is zeroed. What can't be zeroed is below the client: Go's
// HTTP stack's own buffers, and the token, which the client holds as a Go string.
//
// New refuses, with ErrInvalidArgument, a nil client; a client whose address isn't https, or http
// on a loopback address (or a Unix socket), or that holds credentials, a query or a fragment; and,
// unless Options.AllowRedirects is set, a client that would follow a redirect - one whose api.Config
// left DisableRedirects false, or whose HttpClient's CheckRedirect is nil or lets a redirect through
// - since the redirect would carry X-Vault-Token wherever it points. It also refuses a mount path
// that isn't a Vault path and a KV version that isn't one; and, matching pipeline.ErrInvalidArgument
// too, what pipeline.New refuses - no protector, no secret names, a name that isn't a path (see
// IsValidSecretName) with a key after '#' if any, one whose file name cache/filepersecret can't
// read, two with the same file name in any case, or a default key holding '#'. The protector and
// the client are the caller's: the writer never closes them, and never changes the client.
func New(client *api.Client, protector hkdfguard.PipelineDataProtector, secretNames []string, options Options) (*pipeline.Writer, error) {
	if client == nil {
		return nil, invalidArgument("a Vault client is required (an *api.Client).")
	}
	mountPath := options.MountPath
	if mountPath == "" {
		mountPath = defaultMountPath
	}
	httpClient := func() *http.Client { return client.CloneConfig().HttpClient }
	if reason := vaultcheck.Check(client.Address(), client, httpClient, options.AllowRedirects, mountPath); reason != "" {
		return nil, invalidArgument("%s", reason)
	}
	key := options.DefaultKey
	if key == "" {
		key = defaultKey
	}

	store := &secretStore{client: client}
	switch options.KVVersion {
	case 0, V2:
		store.readPrefix, store.dataPath = mountPath+"/data/", []string{"data", "data"}
	case V1:
		store.readPrefix, store.dataPath = mountPath+"/", []string{"data"}
	default:
		return nil, invalidArgument("the KV version must be V1 or V2, not %d.", options.KVVersion)
	}
	writer, err := pipeline.New(protector, secretNames, store, pipeline.Options{DefaultKey: key})
	if err != nil {
		return nil, &argumentError{err: err}
	}
	return writer, nil
}

// IsValidSecretName reports whether name is a secret's path: '/'-separated segments of ASCII
// letters, digits, '-', '_' and '.', no segment "." or "..", at most MaxSecretNameLength
// characters. A key to read follows it in a secret name, after '#'.
func IsValidSecretName(name string) bool {
	return name != "" && len(name) <= MaxSecretNameLength && vaultcheck.IsValidPath(name)
}

// IsValidName implements pipeline.SecretStore.
func (s *secretStore) IsValidName(name string) bool { return IsValidSecretName(name) }

// ReadSecret implements pipeline.SecretStore: one read of the secret at name, through the client.
func (s *secretStore) ReadSecret(ctx context.Context, name string, secret *pipeline.Secret) error {
	// ReadRawWithContext, never Read: Read decodes the body into strings, which can't be zeroed.
	// The raw response's body for a 2xx answer is the network body itself.
	response, err := s.client.Logical().ReadRawWithContext(ctx, s.readPrefix+name)
	if response != nil && response.Body != nil {
		defer response.Body.Close()
	}
	if err != nil {
		var refused *api.ResponseError
		if !errors.As(err, &refused) {
			return &Error{Path: name, Message: fmt.Sprintf("couldn't read '%s' from Vault: %v", name, err), Err: err}
		}

		// Nothing at the path: Vault answers 404 with an empty error list - or, for a KV version 2
		// secret whose latest version is deleted or destroyed, with its metadata and none. A 404
		// naming an error (no such mount) or that isn't Vault's JSON (a proxy's page) is a failure.
		if refused.StatusCode == http.StatusNotFound && !refused.RawError && len(refused.Errors) == 0 {
			return nil
		}
		var listed []string
		if !refused.RawError {
			// Otherwise Errors is the raw body, which may be anything: not quoted.
			listed = refused.Errors
		}
		return vaultError(name, refused.StatusCode, listed, err)
	}
	if response == nil || response.Body == nil {
		return &Error{Path: name, Message: fmt.Sprintf("Vault returned no response reading '%s'.", name)}
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		// The client returns a redirect it didn't follow as an answer, not an error.
		return vaultError(name, response.StatusCode, nil, nil)
	}

	body, err := pipeline.ReadBody(response.Body)
	if err != nil {
		return fmt.Errorf("hashicorpvault: reading '%s': %w", name, err)
	}
	defer hkdfguard.Wipe(body)
	if err := secret.ProtectBodyKeys(ctx, body, s.dataPath); err != nil {
		return fmt.Errorf("hashicorpvault: reading '%s': %w", name, err)
	}
	return nil
}

func vaultError(path string, status int, listed []string, cause error) *Error {
	detail := ""
	if len(listed) > 0 {
		// Vault's errors often end in blank lines ("1 error occurred:\n\t* permission denied\n\n").
		trimmed := make([]string, len(listed))
		for i, e := range listed {
			trimmed[i] = strings.TrimSpace(e)
		}
		detail = ": " + strings.Join(trimmed, "; ")
	}
	return &Error{
		Path:       path,
		StatusCode: status,
		Errors:     listed,
		Message:    fmt.Sprintf("Vault refused to read '%s': %d %s%s", path, status, http.StatusText(status), detail),
		Err:        cause,
	}
}
