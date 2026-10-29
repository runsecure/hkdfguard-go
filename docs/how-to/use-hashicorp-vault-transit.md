# Wrap keys with HashiCorp Vault transit

This page sets up a key in a HashiCorp Vault transit secrets engine as HkdfGuard's KEK and uses it
from Go with `hashicorpvault.KeyWrapper`, in place of the native TPM, Secure Enclave or Platform
Crypto Provider KEK.

Use it when your applications already authenticate to Vault, or run somewhere a cloud KMS isn't
available, and you want key access controlled by Vault policy and recorded in Vault's audit log
rather than tied to one machine's TPM.

To run the transit integration tests against a Vault dev server, see
[Run the HashiCorp Vault transit integration tests](run-hashicorp-vault-transit-integration-tests.md).

## How it differs from the native wrapper

| | Native (`nativev1`) | Vault transit (`hashicorpvault.KeyWrapper`) |
|---|---|---|
| KEK | A P-256 key in the TPM, Secure Enclave or Platform Crypto Provider | An `aes256-gcm96` transit key |
| Identified by | A service name | The Vault client's address, the mount and the key's name |
| Who may wrap and unwrap | Local accounts and groups the native library allows | Tokens whose policy grants `update` on the key's `encrypt`, `decrypt` and `datakey/wrapped` paths |
| Each call | Local, synchronous | A request to Vault's HTTP API through your `*api.Client`, recorded in Vault's audit log |
| Key file reads | Through the native library, which refuses files another account could have replaced | The same rules, checked in Go; who else is trusted is set with `Options.KeyFileTrust` |
| Client | None | The application's `*api.Client` (`github.com/hashicorp/vault/api`) |

Wrapped DEKs aren't interchangeable between wrapper types: a key file wrapped by one can't be
unwrapped by another, so each DEK belongs to the wrapper type that created it. Between languages it
is the same file: a transit-wrapped DEK is Vault's ciphertext as it returns it, `vault:v1:...`, about
89 bytes of ASCII, so one made by the .NET `HashiCorpVaultTransitKeyWrapper` is read by this one,
and the other way round, given the same Vault key and context.

## 1. Create the transit key

As a Vault operator, enable the engine (once) and create the key:

```bash
vault secrets enable transit
vault write -f transit/keys/myapp-kek type=aes256-gcm96
```

| Setting | Choose | Why |
|---|---|---|
| `type` | `aes256-gcm96` (the default), `aes128-gcm96` or `chacha20-poly1305` | The wrapper needs an AEAD key for its context (associated data) |
| `derived` | `false` (the default) | A derived key needs a `context` on every request, which the wrapper doesn't send. Worse, a key that *isn't* derived silently ignores one, so the wrapper binds its context as `associated_data` instead |
| `exportable` | `false` (the default) | Nothing here needs the key material out of Vault |
| `deletion_allowed` | `false` (the default) | Deleting the key makes every DEK wrapped under it unreadable, for good |

Rotate it with `vault write -f transit/keys/myapp-kek/rotate`. New DEKs are wrapped under the latest
version; existing key files keep revealing as long as their version is at or above the key's
`min_decryption_version`, so don't raise that until every key file is rewrapped.

## 2. Grant each role only what it calls

Give `update`, and never `create`, on exactly the paths each role uses. `transit/encrypt/{name}`
creates a key that doesn't exist yet when the token has `create`, so with it a mistyped key name
would quietly wrap DEKs under a brand-new key.

A release pipeline that creates key files:

```hcl
path "transit/encrypt/myapp-kek"         { capabilities = ["update"] }
path "transit/datakey/wrapped/myapp-kek" { capabilities = ["update"] }
```

The application, which only reads existing key files:

```hcl
path "transit/decrypt/myapp-kek" { capabilities = ["update"] }
```

Add `transit/encrypt/myapp-kek` (and `transit/datakey/wrapped/myapp-kek`) to the application only
if it generates ephemeral keys at startup.

```bash
vault policy write myapp-kek-pipeline pipeline.hcl
vault policy write myapp-kek-app app.hcl
```

Then bind each policy to the auth method its role logs in with (AppRole, Kubernetes, a certificate,
a cloud IAM role).

## 3. Give the process a Vault client

Everything about reaching Vault is the client's, configured as for any other use of HashiCorp's Go
client: `api.DefaultConfig()` reads `VAULT_ADDR`, `VAULT_CACERT`, `VAULT_CLIENT_TIMEOUT`,
`VAULT_MAX_RETRIES` and the rest of Vault's environment variables, and `api.NewClient` reads
`VAULT_TOKEN` and `VAULT_NAMESPACE`.

- **The token is the client's.** Log in with any auth method the SDK supports (the `api/auth/...`
  modules for AppRole, Kubernetes, AWS, Azure, GCP, certificates) and keep the token alive with a
  `LifetimeWatcher`, or point the client at a local Vault Agent with `use_auto_auth_token`, which
  renews it itself. A token the application replaces with `SetToken` is used from the next call on.
- **The namespace is the client's**: `client.SetNamespace("team-a/prod")` or `VAULT_NAMESPACE`.
- **TLS is the client's**: `config.ConfigureTLS(&api.TLSConfig{CACert: "/etc/vault/ca.pem"})`, or
  `VAULT_CACERT`, to trust a private CA.
- **Timeout and retries are the client's.** By default the client gives each call 60 seconds and
  retries a request that got no answer, or was answered 429 or a 5xx other than 501, twice,
  waiting 1 to 1.5 seconds; `config.Timeout`, `config.MaxRetries`, `config.MinRetryWait` and
  `config.MaxRetryWait` change that. Every transit call the wrapper makes is safe to repeat. Every
  wrapper call also takes a `context.Context`, whose cancellation and deadline the client honours.

```go
config := api.DefaultConfig() // VAULT_ADDR, VAULT_CACERT, ...
if config.Error != nil {
	log.Fatal(config.Error)
}
client, err := api.NewClient(config) // VAULT_TOKEN, VAULT_NAMESPACE
if err != nil {
	log.Fatal(err)
}
```

## 4. Create the wrapper

Add the modules, and Vault's client:

```sh
go get github.com/runsecure/hkdfguard-go github.com/runsecure/hkdfguard-go/keywrapping/hashicorpvault \
  github.com/runsecure/hkdfguard-go/cryptoprovider/aesgcm256 \
  github.com/hashicorp/vault/api
```

> **TODO (maintainer):** confirm these module paths resolve once the modules are tagged. Until
> then, add `replace` directives pointing at a checkout of `hkdfguard-go` (the root, `securefile`,
> `keywrapping/hashicorpvault` and `cryptoprovider/aesgcm256`).

`keywrapping/hashicorpvault` brings the `securefile` module, which reads key files with
`golang.org/x/sys`. Neither needs cgo or a C compiler, on any platform.

```go
wrapper, err := hashicorpvault.New(client, "myapp-kek",
	hashicorpvault.Options{Context: "com.example.myapp"})
if err != nil {
	log.Fatal(err)
}
```

- **The address must be https**, except on a loopback address or a Unix socket (`unix://...`, a
  local Vault Agent or dev server): every request carries the token, and wrap and unwrap carry
  plaintext DEKs. `New` checks the client's address, and every call checks it again, since a client
  can be pointed elsewhere with `SetAddress`. A path in the address is kept as a prefix, for Vault
  behind a reverse proxy.
- **No redirect is followed.** A redirect would carry the token wherever it points: `net/http`
  drops only `Authorization` and cookies when it follows one, never `X-Vault-Token`. `New` refuses a
  client whose HTTP client follows redirects itself (a `CheckRedirect` that is nil, or that lets
  them through); the one `api.DefaultConfig` makes doesn't. `*api.Client` also follows one 301,
  302 or 307 itself, unless its `DisableRedirects` is set; the wrapper stops that redirect before it
  is sent. Either way, a redirect fails the call. Vault's standbys forward requests to the active
  node themselves, so you shouldn't meet one. If your cluster redirects instead, and every node may
  see the token, set `Options.AllowRedirects`.
- **The context** is bound into every wrapped DEK as Vault's `associated_data` and must be given
  again, exactly, to reveal it. Use the same value on every wrapper that handles one application's
  key files. It must be valid UTF-8, at most 1,024 bytes. It isn't a secret and must not hold one.
- **With a context, `GenerateAndWrap` generates the DEK in your process** and wraps it with
  `encrypt`, because `datakey/wrapped` ignores `associated_data`. Without one, Vault generates it
  and returns it wrapped only, so the plaintext DEK never leaves Vault on that call. Choose a
  context for the binding, or none for generation in Vault.
- **Old Vaults are refused, not trusted.** If Vault answers that it ignored a parameter, as one
  too old for `associated_data` does, the call fails rather than return a DEK bound to no context.
- **A mount other than `transit`** is `Options.MountPath`, e.g. `"transit/team-a"`.
- **Keep the client** for as long as anything uses the wrapper, a key ring's background refresh
  included. The wrapper never changes the client: one client can serve this wrapper and the rest of
  the application, and several wrappers.
- **Don't have the client print requests instead of sending them.** A client with
  `SetOutputCurlString` or `SetOutputPolicy` on is refused, since it would keep the request, DEK
  and all, in a package variable.

### Coming from the .NET wrapper

The .NET `HashiCorpVaultTransitKeyWrapper` reaches Vault through its own `HttpClient`; here
HashiCorp's client does, so its settings move to the client:

| .NET | Go |
|---|---|
| `address` argument | The client's address (`config.Address`, `VAULT_ADDR`) |
| `IVaultTokenSource`, `StaticVaultTokenSource` | The client's token (`SetToken`, `VAULT_TOKEN`), kept alive by a `LifetimeWatcher` or a Vault Agent |
| `Options.Namespace` | `client.SetNamespace`, `VAULT_NAMESPACE` |
| `Options.Timeout`, `RetryCount`, `RetryDelay` | `config.Timeout`, `MaxRetries`, `MinRetryWait`, `MaxRetryWait` |
| `Options.HttpMessageHandler` | `config.HttpClient`, `config.ConfigureTLS` |
| `Options.AllowRedirects` | `Options.AllowRedirects` |
| `Options.MountPath`, the `context` and `keyFileTrust` arguments | `Options.MountPath`, `Context`, `KeyFileTrust` |
| `Dispose()` | Nothing: the wrapper holds no connections of its own |

## 5. Build a key ring with an ephemeral key

An ephemeral key is generated at startup and never written anywhere:

```go
ring, err := dek.Build(ctx, dek.Config{
	KeyWrapper:            wrapper,
	CryptoProviderFactory: aesgcm256.NewFactory(),
	KeyRefreshInterval:    300 * time.Second,
	EphemeralKeys:         []int{1},
})
if err != nil {
	log.Fatal(err)
}
defer ring.Close()
```

An ephemeral key needs `encrypt` (with a context) or `datakey/wrapped` (without), which step 2
keeps from the application. Everything encrypted under an ephemeral key is lost when the process
exits. Data you store needs a key file.

## 6. Create a key file

The release pipeline creates key files with the wrapper itself, logged in as the pipeline role from
step 2:

```go
wrapped := make([]byte, hkdfguard.MaxWrappedKeyBytes)
n, err := wrapper.GenerateAndWrap(ctx, wrapped)
if err != nil {
	log.Fatal(err)
}
if err := os.WriteFile(`C:\HkdfGuardKeys\myapp\v1.key`, wrapped[:n], 0o640); err != nil {
	log.Fatal(err)
}
```

To wrap a key the pipeline already holds, such as an `aesgcm256.PipelineDataProtector`'s, call
`Wrap` with it and zero your copy afterwards, as
[Wrap keys with AWS KMS](use-aws-kms.md#6-create-a-key-file) shows.

Key files are read only from where no untrusted account could have written or replaced them: anyone
who can replace a key file *and* call `encrypt` on the key could otherwise choose your application's
DEK. The rules, the folder setup and `KeyFileTrust` for a deployer account are the same as for AWS
KMS; see [Where key files can live](use-aws-kms.md#where-key-files-can-live), and set
`Options.KeyFileTrust`. Then use the key file as in [Use the key file](use-aws-kms.md#7-use-the-key-file).

`dek.Build` calls `decrypt` once per key, so the application fails to start if Vault can't be
reached or refuses the key. Each key then calls `decrypt` once per `KeyRefreshInterval`: at 300
seconds, 8,640 requests per key per process every 30 days, each one in the audit log. See
[Choosing a refresh interval](use-aws-kms.md#choosing-a-refresh-interval).

## Limitations

- **The token can't be zeroed.** `*api.Client` holds it as a Go string from `SetToken` (or
  `VAULT_TOKEN`) for as long as it is set, and sets it as the `X-Vault-Token` header of each request
  - a string the garbage collector may copy and that nothing can overwrite. The .NET wrapper copies
  the token into pinned memory it zeroes once each request is sent; using HashiCorp's client trades
  that for its auth methods, token renewal, namespaces, TLS and retries. Keep tokens short-lived
  (a `LifetimeWatcher` or Vault Agent renews them) and use `nativev1.HardenProcess` to keep a
  debugger or crash dump away.
- **What the wrapper does zero.** The `encrypt` request body (the DEK, base64-encoded) is the
  wrapper's own buffer: the client sends it as it is, without copying it, on every attempt, and it
  is zeroed once the call returns. Vault's answer is read off the network into a buffer of the
  wrapper's, walked in place without becoming a Go string, and zeroed with the value read out of it
  and the DEK decoded from that. A failed unwrap zeroes your `result`.
- **Copies the wrapper can't reach**: the HTTP stack's own buffers (TLS records, the connection's
  read buffer); anything a `RoundTripper`, request callback (`WithRequestCallbacks`) or response
  callback you install keeps - they see the request body and the answer, so they must not log or
  keep either; and, with `AllowRedirects`, the copy `encoding/json` makes when the client resends
  the body to a redirect's target.
- The key-file limitations are those of [Wrap keys with AWS KMS](use-aws-kms.md#limitations).

## If something goes wrong

Every Vault failure is a `*hashicorpvault.Error` (matching `hashicorpvault.ErrVault` with
`errors.Is`) whose message names the operation and the key, and for a refusal Vault's status and
errors. It unwraps to the client's error: `errors.As` reaches the `*api.ResponseError`, with
`StatusCode` and `Errors`. A failed unwrap zeroes the caller's buffer. A call whose
`context.Context` was cancelled or expired fails with an error matching `context.Canceled` or
`context.DeadlineExceeded`. Argument errors - a client `New` refuses included - wrap
`hashicorpvault.ErrInvalidArgument`. Reading a key file fails as described for
[AWS KMS](use-aws-kms.md#if-something-goes-wrong).

| The message says | Cause | Fix |
|---|---|---|
| `403 Forbidden` ... `permission denied` | The token's policy doesn't grant `update` on this path, or the token is invalid or expired | Step 2's paths; renew or replace the token |
| `400 Bad Request` ... `encryption key not found` | No key by that name in this mount (or namespace) | Check the key name, `MountPath` and the client's namespace |
| `400 Bad Request` ... `cipher: message authentication failed` | The key file was altered, wrapped under another key, or with a different context | Restore the file; use the key and context it was created with |
| `400 Bad Request` ... `missing 'context' for key derivation` | The key is derived | Create a key with `derived=false` and rewrap |
| `400 Bad Request` ... `disallowed by policy (too old)` | The file's key version is below `min_decryption_version` | Lower it, or rewrap the file under the current version |
| `ignored a parameter` | This Vault doesn't support `associated_data` | Upgrade Vault (the integration tests run against 1.19) |
| `503 Service Unavailable` | Vault is sealed, or electing a leader, beyond the client's retries | Unseal Vault; check its HA status |
| `a redirect` ... `which isn't followed` | Vault, or something in front of it, answered with a redirect | Use the active node's or the load balancer's address; or `AllowRedirects` |
| `no answer within the client's timeout` | No answer within the client's `Timeout` | Check the address and network path |
| `must be https` (`ErrInvalidArgument`) | The client's address is http and not loopback | Use https, or a local Vault Agent |
| `follows redirects` (`ErrInvalidArgument`) | The client's HTTP client has no `CheckRedirect` | Start from `api.DefaultConfig()`'s HTTP client |
