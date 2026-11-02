// Package hashicorpvault implements a hkdfguard.ProtectedReadOnlyCache over the secrets in one
// HashiCorp Vault KV secrets engine (version 2 or 1) - the Go port of the .NET
// HkdfGuard.Cache.HashiCorpVault library. Nothing is fetched up front: the first lookup of a name
// reads that one secret's path through an *api.Client (github.com/hashicorp/vault/api) the
// application creates and configures, encrypts every key the secret holds under the ring's current
// key, and caches only the ciphertext. It never lists secrets, so the token's policy needs only read
// on the paths it reads.
//
// A name is the secret's path with the key after '#'; a name without one reads Options.DefaultKey
// ("value" unless set):
//
//	config := api.DefaultConfig() // VAULT_ADDR, VAULT_CACERT, VAULT_NAMESPACE, ... from the environment
//	config.DisableRedirects = true // or VAULT_DISABLE_REDIRECTS=true; New refuses a client that follows redirects
//	client, err := api.NewClient(config) // VAULT_TOKEN, or log in with an auth method and SetToken
//	if err != nil { ... }
//	secrets, err := hashicorpvault.New(client, ring, hashicorpvault.Options{MountPath: "secret"}) // KV version 2
//	if err != nil { ... }
//	n, err := secrets.Decrypt(ctx, "myapp/db#password", buffer) // 0 if there's no such secret or key
//
// # What the client owns
//
// The .NET cache speaks Vault's HTTP API itself, so it has its own address, namespace, timeout,
// retry and HTTP handler options, and an IVaultTokenProvider handing it a token protected under the
// key ring. Here HashiCorp's own client does all of that, configured as for any other use of it:
//
//   - The address (the .NET constructor's address): api.Config.Address or VAULT_ADDR, or
//     AgentAddress / VAULT_AGENT_ADDR for a local Vault Agent - a path kept as a prefix, as in .NET.
//   - TLS (a .NET HttpMessageHandler trusting a private CA): api.Config.ConfigureTLS, or VAULT_CACERT
//     and the other VAULT_* TLS variables.
//   - The namespace (Namespace): client.SetNamespace or VAULT_NAMESPACE; it is sent as
//     X-Vault-Namespace on every read.
//   - The token (IVaultTokenProvider, StaticVaultToken, TokenPurpose): client.SetToken or
//     VAULT_TOKEN; to log in, an auth method (approle, kubernetes, cert, ...) with
//     client.Auth().Login, renewed by an api.LifetimeWatcher; or Vault Agent's API proxy with
//     use_auto_auth_token, in which case the client holds no token at all. Each read uses the token
//     the client holds at that moment.
//   - The timeout (Timeout): api.Config.Timeout or VAULT_CLIENT_TIMEOUT, which bounds each read and
//     its whole response; the lookup's context is honoured too.
//   - Retries (RetryCount, RetryDelay): api.Config.MaxRetries, MinRetryWait, MaxRetryWait, Backoff
//     and CheckRetry (VAULT_MAX_RETRIES). The client's default policy retries 412, 429 and 5xx
//     (other than 501) and connection failures.
//
// What remains are Options' MountPath, KVVersion, DefaultKey, AllowRedirects and Logger.
//
// # Redirects and the address
//
// A redirect would carry X-Vault-Token wherever it points. The client follows one 301, 302 or 307
// itself unless api.Config.DisableRedirects (VAULT_DISABLE_REDIRECTS) is set, and an HttpClient
// whose CheckRedirect is nil follows them too - api.DefaultConfig's returns http.ErrUseLastResponse.
// So New refuses a client that would follow one unless Options.AllowRedirects is set, as the .NET
// cache refuses an HttpMessageHandler with AllowAutoRedirect on. Vault's standbys forward requests to
// the active node themselves, so with redirects disabled a redirect is answered as an error instead.
// The client has no getter for DisableRedirects, so New reads it by reflection, refusing the client
// when it can't (a future version of the client that keeps it elsewhere).
//
// The client's address must be https, except on a loopback address (a local Vault Agent or dev
// server), and must not hold credentials, a query or a fragment. A Unix socket (unix://, a Vault
// Agent listener) is accepted: the token never leaves the host there, and the socket's permissions
// decide who listens on it.
//
// # What is zeroed, and what isn't
//
// A secret never becomes a string: each read is client.Logical().ReadRawWithContext - never Read,
// which decodes the response into strings - and the raw response's body is read off the network
// into a buffer of the cache's own, each value unescaped into another and encrypted from there
// (cache.CaptureJSONKeys); every buffer that held it is zeroed. What can't be zeroed is below the
// client: Go's HTTP stack's own buffers (TLS decryption, socket reads), as in every language.
//
// The token is the trade-off. The .NET cache holds it encrypted under the key ring and decrypts it
// only into the one string a request's header needs, zeroing that string once the request is sent.
// Here the client holds it as a Go string for its whole life (and copies it into each request's
// headers), and Go strings can't be zeroed. Prefer short-lived tokens, renewed or replaced by the
// application, or Vault Agent's auto-auth, so the client holds none.
//
// It is a module of its own (github.com/runsecure/hkdfguard-go/cache/hashicorpvault) so that only
// applications that use it depend on HashiCorp's Vault client.
package hashicorpvault
