package hashicorpvault

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strings"

	"github.com/hashicorp/vault/api"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/cache"
)

// MaxSecretNameLength is the longest secret path looked up.
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

// Options are which KV secrets engine New's cache reads, and what it accepts of the client; the
// zero value reads KV version 2 at "secret", reading the key "value" for a name without one.
//
// Everything about reaching Vault - its address, TLS, the namespace, the token and how it is
// obtained and renewed, the timeout and the retries - is the *api.Client's, configured by the
// application: see the package documentation.
type Options struct {
	// MountPath is where the KV secrets engine is mounted, e.g. "secret" (used when empty) or
	// "kv/team-a".
	MountPath string

	// KVVersion is the engine's version: V2 (used when zero) or V1.
	KVVersion KVVersion

	// DefaultKey is the key read from a secret looked up without one: "myapp/db" reads this key of
	// the secret at myapp/db, while "myapp/db#password" reads its password key. "value" when empty.
	DefaultKey string

	// AllowRedirects accepts a client that follows redirects, sending the Vault token along to every
	// redirect target. Set it only when every address a redirect could lead to may see the token.
	// Default false: New refuses a client that would follow one (see New).
	AllowRedirects bool

	// Logger receives a debug record per fetched secret path while sensitive logging is enabled
	// (diagnostics.Cache), and an error record per failed read; nil logs nothing.
	Logger *slog.Logger
}

// secretStore is the cache.SecretStore over one KV engine, reached through the application's
// client.
type secretStore struct {
	client     *api.Client
	readPrefix string   // the engine's read path, before the secret's path: "secret/data/"
	dataPath   []string // the member names leading to the secret's keys in a response
}

// New returns a cache.RemoteCache over the secrets in one HashiCorp Vault KV secrets engine - the Go
// port of the .NET HashiCorpVaultSecretCache. The first lookup of a name that isn't cached yet reads
// that one secret (GET on its path through client.Logical().ReadRawWithContext; for KV version 2,
// its latest version); fetching, encryption, caching and telemetry are the RemoteCache's. It never
// lists secrets, so the token's policy needs only read on the paths it reads, never list.
//
// A name is a secret's path within the engine, with the key to read after '#': "myapp/db#password"
// reads the password key of the secret at myapp/db, and "myapp/db" reads its Options.DefaultKey.
// One read caches every key the secret holds, so the first lookup of any of them reads the secret
// once and the rest are already cached. A string is cached as its UTF-8 bytes; a number, true or
// false as its JSON text; a null, object or array value isn't cached. Paths are matched exactly, as
// Vault matches them, and so are keys (cache.Exact). A path that isn't one - see IsValidSecretName;
// the configuration path "ConnectionStrings:Admin", say - is reported missing without a call.
//
// A secret that doesn't exist (404 with no errors, as Vault answers), whose latest version is
// deleted or destroyed, or that has no such key, or whose value there is empty or isn't cached, is
// reported missing. Any other answer - 403 for a token that is invalid or not allowed to read the
// path, a 404 naming an error such as a mount that doesn't exist, 503 while sealed, a redirect that
// isn't followed - and a read that couldn't be made, is returned as an *Error (ErrVault) carrying
// Vault's status and errors. Retries, the timeout and the token are the client's: a fetch is one
// ReadRawWithContext, which the client retries and times out as it is configured to, under the
// lookup's context.
//
// The secret never becomes a string: the raw response's body is read off the network into a buffer
// of the cache's own, and each value is unescaped into another and encrypted from there
// (cache.CaptureJSONKeys); every buffer that held it is zeroed. Error answers, which hold no secret,
// are parsed by the client. What can't be zeroed is below the client: Go's HTTP stack's own buffers
// (TLS decryption, socket reads), and the token, which the client holds as a Go string.
//
// New refuses, with ErrInvalidArgument, a nil client or ring; a client whose address isn't https,
// or http on a loopback address (or a Unix socket), or that holds credentials, a query or a
// fragment; and, unless Options.AllowRedirects is set, a client that would follow a redirect - one
// whose api.Config left DisableRedirects false, or whose HttpClient's CheckRedirect is nil or lets
// a redirect through - since the redirect would carry X-Vault-Token wherever it points. It also
// refuses a mount path that isn't a Vault path, a default key that isn't a key, and a KV version
// that isn't one. The ring and the client are the caller's: the cache never closes keys, and never
// changes the client.
func New(client *api.Client, ring hkdfguard.KeyRing, options Options) (*cache.RemoteCache, error) {
	if client == nil {
		return nil, invalidArgument("a Vault client is required (an *api.Client).")
	}
	if ring == nil {
		return nil, invalidArgument("a key ring is required.")
	}
	if err := checkAddress(client.Address()); err != nil {
		return nil, err
	}
	if !options.AllowRedirects {
		if err := checkRedirects(client); err != nil {
			return nil, err
		}
	}

	mountPath := options.MountPath
	if mountPath == "" {
		mountPath = defaultMountPath
	}
	if !isValidPath(mountPath) {
		return nil, invalidArgument("the mount path '%s' isn't a Vault path: '/'-separated segments of ASCII letters, digits, '-', '_' and '.', none \".\" or \"..\".", mountPath)
	}
	key := options.DefaultKey
	if key == "" {
		key = defaultKey
	}
	if !cache.IsValidKey(key) {
		return nil, invalidArgument("the default key '%s' isn't a key: 1-%d printable ASCII characters other than space, '!' and '#'.", key, cache.MaxKeyLength)
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
	return cache.NewRemote(ring, store, cache.RemoteOptions{Matching: cache.Exact, DefaultKey: key, Logger: options.Logger})
}

// IsValidSecretName reports whether name is a secret's path: '/'-separated segments of ASCII
// letters, digits, '-', '_' and '.', no segment "." or "..", at most MaxSecretNameLength
// characters. A key to read follows it in a lookup, after '#' (see cache.IsValidKey).
func IsValidSecretName(name string) bool {
	return name != "" && len(name) <= MaxSecretNameLength && isValidPath(name)
}

// IsValidName implements cache.SecretStore.
func (s *secretStore) IsValidName(name string) bool { return IsValidSecretName(name) }

// Fetch implements cache.SecretStore: one read of the secret at name, through the client.
func (s *secretStore) Fetch(ctx context.Context, name string, sink *cache.SecretSink) error {
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
	if err := cache.CaptureJSONKeys(response.Body, sink, s.dataPath); err != nil {
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

// checkAddress refuses an address that would send the token in the clear (http anywhere but
// loopback) or that carries credentials, a query or a fragment. A client whose address is a Unix
// socket (unix://, a local Vault Agent's listener) reports it as http://localhost, and is accepted:
// the token never leaves the host, and the socket's file permissions decide who listens on it.
func checkAddress(address string) error {
	u, err := url.Parse(address)
	if err != nil || u.Host == "" {
		return invalidArgument("the Vault client's address '%s' isn't absolute, e.g. https://vault.example.com:8200.", address)
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && isLoopback(u.Hostname())) {
		return invalidArgument("the Vault client's address '%s' must be https; http is allowed only on a loopback address (a local Vault Agent or dev server), since every request carries a token.", address)
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return invalidArgument("the Vault client's address '%s' must not hold credentials, a query or a fragment.", address)
	}
	return nil
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// checkRedirects refuses a client that would follow a redirect, carrying X-Vault-Token to wherever
// it points. The client follows one 301, 302 or 307 itself unless its api.Config set
// DisableRedirects (VAULT_DISABLE_REDIRECTS); and its HttpClient follows any number unless its
// CheckRedirect stops them, as api.DefaultConfig's does (http.ErrUseLastResponse). Go's HTTP client
// drops only Authorization and cookies on a redirect to another host, never X-Vault-Token.
func checkRedirects(client *api.Client) error {
	if disables, known := disablesRedirects(client); !known {
		return invalidArgument("whether the Vault client follows redirects can't be told with this version of github.com/hashicorp/vault/api; set Options.AllowRedirects only if every redirect target may see the token.")
	} else if !disables {
		return invalidArgument("the Vault client follows a redirect itself, which would send the Vault token wherever it points. Set DisableRedirects on the api.Config it was made from (or VAULT_DISABLE_REDIRECTS=true), or set Options.AllowRedirects if every redirect target may see the token.")
	}
	if followsHTTPRedirects(client.CloneConfig().HttpClient) {
		return invalidArgument("the Vault client's HttpClient follows redirects, which would send the Vault token wherever they point. Make its CheckRedirect return http.ErrUseLastResponse, as api.DefaultConfig's does, or set Options.AllowRedirects if every redirect target may see the token.")
	}
	return nil
}

// disablesRedirects reads the DisableRedirects the client was made with. The client has no getter
// for it, and CloneConfig doesn't copy it, so it is read from the client's configuration by
// reflection - read only, and set only before the client is made, so never written while it is
// read. known is false when this version of the client keeps it elsewhere, which New treats as
// following redirects.
func disablesRedirects(client *api.Client) (disables, known bool) {
	config := reflect.ValueOf(client).Elem().FieldByName("config")
	if config.Kind() != reflect.Pointer || config.IsNil() {
		return false, false
	}
	field := config.Elem().FieldByName("DisableRedirects")
	if field.Kind() != reflect.Bool {
		return false, false
	}
	return field.Bool(), true
}

// followsHTTPRedirects reports whether httpClient would follow a redirect from Vault to another host:
// its CheckRedirect is nil, or lets one through (or panics).
func followsHTTPRedirects(httpClient *http.Client) (follows bool) {
	if httpClient == nil || httpClient.CheckRedirect == nil {
		return true
	}
	defer func() {
		if recover() != nil {
			follows = true
		}
	}()
	from, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://vault.invalid/v1/secret/data/item", nil)
	if err != nil {
		return true
	}
	to, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://redirect.invalid/v1/secret/data/item", nil)
	if err != nil {
		return true
	}
	to.Response = &http.Response{StatusCode: http.StatusTemporaryRedirect, Request: from}
	return httpClient.CheckRedirect(to, []*http.Request{from}) == nil
}

// isValidPath reports whether path is '/'-separated segments, none empty, "." or "..", of ASCII
// letters, digits, '-', '_' and '.': a path that stays where it's put.
func isValidPath(path string) bool {
	for segment := range strings.SplitSeq(path, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
		for i := 0; i < len(segment); i++ {
			c := segment[i]
			if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-' || c == '_' || c == '.') {
				return false
			}
		}
	}
	return true
}
