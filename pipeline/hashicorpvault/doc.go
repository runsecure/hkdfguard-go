// Package hashicorpvault is a provisioning pipeline's hkdfguard.SecretPipelineWriter over one
// HashiCorp Vault KV secrets engine (version 2 or 1) - the Go port of the .NET
// HkdfGuard.Pipeline.HashiCorpVault library. New returns a *pipeline.Writer that pulls a fixed list
// of secrets through an *api.Client (github.com/hashicorp/vault/api) the application creates and
// configures, encrypts each with a hkdfguard.PipelineDataProtector as soon as it is read, and writes
// them out as one file per secret - the folder layout cache/filepersecret reads at runtime. It is
// independent of cache/hashicorpvault's runtime cache, and of any key ring:
//
//	protector, err := aesgcm256.NewPipelineDataProtector(dek.NewDefaultFormatProvider(), 3)
//	if err != nil { ... }
//	defer protector.Close()
//	config := api.DefaultConfig()  // VAULT_ADDR, VAULT_CACERT, VAULT_NAMESPACE, ... from the environment
//	config.DisableRedirects = true // or VAULT_DISABLE_REDIRECTS=true; New refuses a client that follows redirects
//	client, err := api.NewClient(config) // VAULT_TOKEN, or log in with an auth method and SetToken
//	if err != nil { ... }
//	writer, err := hashicorpvault.New(client, protector,
//		[]string{"myapp/db#username", "myapp/db#password", "myapp/api"}, hashicorpvault.Options{})
//	if err != nil { ... }
//	if err := writer.PullSecrets(ctx); err != nil { ... }
//	if err := writer.WriteProtectedSecretFiles(`C:\HkdfGuardSecrets\myapp`); err != nil { ... }
//	// Then hand protector.KeyBase64() to the wrap tool, and register the key at version 3.
//
// A secret name is a path within the engine, with the key to read after '#'; a name without one
// reads Options.DefaultKey ("value" unless set).
//
// # What the client owns
//
// The .NET writer speaks Vault's HTTP API itself, so it has its own address, namespace, timeout,
// retry, TLS and HTTP handler options, and an IVaultTokenSource handing it the token in pinned
// memory. Here HashiCorp's own client does all of that, as for cache/hashicorpvault: the address
// (api.Config.Address or VAULT_ADDR, or a local Vault Agent's), TLS (api.Config.ConfigureTLS or
// VAULT_CACERT and the other VAULT_* TLS variables, client certificates included), the namespace
// (client.SetNamespace or VAULT_NAMESPACE), the token (client.SetToken or VAULT_TOKEN, an auth
// method, or Vault Agent's auto-auth), the timeout (api.Config.Timeout) and retries
// (api.Config.MaxRetries, MinRetryWait, MaxRetryWait; by default 412, 429 and 5xx other than 501,
// and connection failures). What remains are Options' MountPath, KVVersion, DefaultKey and
// AllowRedirects.
//
// # Redirects and the address
//
// A redirect would carry X-Vault-Token wherever it points, so New refuses a client that would
// follow one unless Options.AllowRedirects is set, as the .NET writer refuses an HttpMessageHandler
// that follows redirects: set api.Config.DisableRedirects, and keep api.DefaultConfig's
// CheckRedirect. The client has no getter for DisableRedirects, so New reads it by reflection,
// refusing the client when it can't. The client's address must be https, except on a loopback
// address (a local Vault Agent or dev server) or a Unix socket, and must not hold credentials, a
// query or a fragment.
//
// # What is zeroed, and what isn't
//
// A secret never becomes a string: each read is client.Logical().ReadRawWithContext - never Read,
// which decodes the response into strings - and the raw response's body is read off the network
// into a buffer of the writer's own, each value unescaped into another and encrypted from there;
// every buffer that held it is zeroed. What can't be zeroed is below the client: Go's HTTP stack's
// own buffers (TLS decryption, socket reads). The token is held by the client as a Go string, which
// can't be zeroed: prefer a short-lived token for a pipeline run, or Vault Agent's auto-auth.
//
// It is a module of its own (github.com/runsecure/hkdfguard-go/pipeline/hashicorpvault) so that only
// pipelines that use it depend on HashiCorp's Vault client.
package hashicorpvault
