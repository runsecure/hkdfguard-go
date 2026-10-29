# Cache HashiCorp Vault secrets

This page reads secrets from a HashiCorp Vault KV secrets engine into HkdfGuard's protected cache
from Go, with the `cache/hashicorpvault` module. Nothing is fetched up front: the first lookup of a
name reads that one secret, encrypts every key it holds under the key ring's current key, and caches
only the ciphertext. Later lookups never call Vault.

Use it when your application's secrets live in Vault, and you want them held encrypted in memory,
bound to their names, rather than as strings for the life of the process.

## How it differs from the .NET cache

The .NET `HashiCorpVaultSecretCache` speaks Vault's HTTP API itself. The Go cache reads through
HashiCorp's own client, [`github.com/hashicorp/vault/api`](https://pkg.go.dev/github.com/hashicorp/vault/api),
which your application creates and configures, so everything about reaching Vault is set where it
is for any other use of that client:

| .NET option | Go |
|---|---|
| The constructor's `address` | `api.Config.Address` or `VAULT_ADDR`; `AgentAddress` or `VAULT_AGENT_ADDR` for a local Vault Agent |
| `HttpMessageHandler` (a private CA, a proxy) | `api.Config.ConfigureTLS`, `VAULT_CACERT` and the other `VAULT_*` TLS variables, or `api.Config.HttpClient` |
| `Namespace` | `client.SetNamespace` or `VAULT_NAMESPACE` |
| `IVaultTokenProvider`, `StaticVaultToken`, `TokenPurpose` | `client.SetToken` or `VAULT_TOKEN`; an auth method with `client.Auth().Login` and an `api.LifetimeWatcher`; or Vault Agent's `use_auto_auth_token` |
| `Timeout` | `api.Config.Timeout` or `VAULT_CLIENT_TIMEOUT`, plus the lookup's `context.Context` |
| `RetryCount`, `RetryDelay` | `api.Config.MaxRetries`, `MinRetryWait`, `MaxRetryWait`, `Backoff`, `CheckRetry`, or `VAULT_MAX_RETRIES` |
| `AllowRedirects` | `hashicorpvault.Options.AllowRedirects` |
| `MountPath`, `KvVersion`, `DefaultKey` | `hashicorpvault.Options.MountPath`, `KVVersion`, `DefaultKey` |

Names, paths, keys, missing secrets and errors behave as in .NET, and so does the policy the token
needs. What changes is the token's protection; see [What is zeroed](#what-is-zeroed).

## 1. Store the secret

A Vault KV secret is a set of keys. A lookup name is the secret's path with the key after `#`, and a
name without one reads the default key (`value` unless you set another):

```sh
vault kv put secret/myapp/db username=app password='s3cret' value='Server=db;Database=app'
```

| Lookup name | Reads |
|---|---|
| `myapp/db#password` | The `password` key of `secret/myapp/db` |
| `myapp/db#username` | The `username` key |
| `myapp/db` | The `value` key (the default key) |

One read caches every key the secret holds, so the first lookup of any of them reads the secret
once, and the rest are already cached. A string is cached as its UTF-8 bytes, a number, `true` or
`false` as its JSON text. A key holding `null`, an object or an array isn't cached.

Paths and keys are matched exactly, as Vault matches them: `myapp/Db` and `myapp/db` are different
secrets. A path is `/`-separated segments of ASCII letters, digits, `-`, `_` and `.`, none of them
`.` or `..`, at most 512 characters (`hashicorpvault.IsValidSecretName`). Any other name, such as the
configuration path `ConnectionStrings:Admin`, returns 0 without calling Vault, so the cache can go
last in a `cache.Collection` behind other sources.

## 2. Grant the token only `read`

The cache never lists secrets, and never writes them. Give the application's token a policy with
`read` on exactly the paths it reads. For KV version 2, that's the `data/` path:

```hcl
path "secret/data/myapp/*" {
  capabilities = ["read"]
}
```

For KV version 1, it's the path itself (`secret/myapp/*`).

## 3. Give the client a token

The client makes every read with the token it holds at that moment, so anything that changes the
token, such as a login or a renewal, takes effect on the next read.

| Where the process runs | Use | What the process holds |
|---|---|---|
| Beside a Vault Agent | The agent's API proxy with `use_auto_auth_token = true`, on a loopback address or a Unix socket | Nothing: the agent logs in, renews, and adds the token |
| Kubernetes | The Kubernetes auth method (`github.com/hashicorp/vault/api/auth/kubernetes`), renewed with an `api.LifetimeWatcher` | A short-lived token |
| A machine with an identity of its own | AppRole, or TLS certificates, renewed the same way | A short-lived token |
| A developer machine | `VAULT_TOKEN` from `vault login` | A token you can revoke |

> **Security:** don't give a deployed process a long-lived token in an environment variable or a
> file. The token is a Go string inside the client, which can't be zeroed (see
> [What is zeroed](#what-is-zeroed)), so prefer a token that expires soon, or Vault Agent, where the
> process holds none.

## 4. Create the cache

Add the modules, and HashiCorp's client:

```sh
go get github.com/runsecure/hkdfguard-go github.com/runsecure/hkdfguard-go/cache/hashicorpvault \
  github.com/hashicorp/vault/api
```

> **TODO (maintainer):** confirm these module paths resolve once the modules are tagged. Until
> then, add `replace` directives pointing at a checkout of `hkdfguard-go` (the root and
> `cache/hashicorpvault`).

```go
config := api.DefaultConfig() // VAULT_ADDR, VAULT_CACERT, VAULT_NAMESPACE, ... from the environment
if config.Error != nil {
	log.Fatal(config.Error)
}
config.DisableRedirects = true // or VAULT_DISABLE_REDIRECTS=true
client, err := api.NewClient(config) // VAULT_TOKEN, if set
if err != nil {
	log.Fatal(err)
}

secrets, err := hashicorpvault.New(client, ring, hashicorpvault.Options{
	MountPath: "secret", // the default
	KVVersion: hashicorpvault.V2, // the default; V1 for a version 1 engine
})
if err != nil {
	log.Fatal(err)
}

buffer := make([]byte, 256)
defer hkdfguard.Wipe(buffer)
n, err := secrets.Decrypt(ctx, "myapp/db#password", buffer) // 0 if there's no such secret or key
```

`ring` is the application's key ring (`dek.Build`); the cache never closes its keys, and never
changes the client. `New` returns a `*cache.RemoteCache`; size a buffer with `MaxDecryptedLength`
when a value may be long.

`New` refuses, with `hashicorpvault.ErrInvalidArgument`:

- **A client that would follow a redirect.** A redirect would carry the `X-Vault-Token` header
  wherever it points. HashiCorp's client follows one 301, 302 or 307 itself unless
  `DisableRedirects` is set, so set it, as above. An `HttpClient` whose `CheckRedirect` is `nil`
  follows them too; `api.DefaultConfig`'s returns `http.ErrUseLastResponse`, so keep it if you
  replace the `HttpClient`. Vault's standbys forward requests to the active node themselves, so
  with redirects disabled a redirect is answered as an error. Set `Options.AllowRedirects` only if
  every address a redirect could lead to may see the token.
- **An address that would expose the token.** It must be https, except on a loopback address (a
  local Vault Agent or dev server), and must not hold credentials, a query or a fragment. A Unix
  socket (`unix:///run/vault-agent.sock`, a Vault Agent listener) is accepted: the token never
  leaves the host, and the socket's file permissions decide who can listen on it.
- A mount path that isn't a Vault path, a default key that isn't a key, or a KV version that
  isn't `V1` or `V2`.

## 5. Put it behind your other sources

Configuration that isn't in Vault, such as `ConnectionStrings:Admin` from an encrypted
configuration file, can sit in front of the Vault cache in a collection. Only names the earlier
sources miss, and that are Vault paths, reach Vault:

```go
secrets := cache.NewCollection(localCache, vaultCache)
```

## What is zeroed

A secret never becomes a string. Each read is `client.Logical().ReadRawWithContext`, never `Read`,
which would decode the response into strings. The response body is read off the network into a
buffer of the cache's own, each value is unescaped into another and encrypted from there, and
every buffer that held it is zeroed. Error answers, which hold no secret, are parsed by the client.

What can't be zeroed:

- **The token.** The .NET cache holds the token encrypted under the key ring, and decrypts it only
  into the one string a request's header needs, zeroing that string once the request is sent. Here
  the client holds the token as a Go string for as long as it's set, and copies it into each
  request's headers. Go strings can't be zeroed. Use short-lived tokens, or Vault Agent's
  auto-auth, so the client holds none.
- **The HTTP stack's own buffers.** TLS decryption and socket reads, below the client, as in every
  language.

`nativev1.HardenProcess` keeps a debugger or crash dump away from such copies.

## Limitations

- **A cached value isn't refreshed.** A new version of a secret is picked up by a new cache.
- **A secret that's missing, or a key it doesn't hold, is read again on every lookup.** Neither is
  remembered, so a secret created later is found.
- **Only KV.** Dynamic secrets (database credentials, leases) aren't read.

## If something goes wrong

A secret that doesn't exist (404 with no errors, as Vault answers), whose latest version is
deleted or destroyed, or that lacks the key, returns 0 and is looked up again next time. Any other
answer is a `*hashicorpvault.Error`, matching `hashicorpvault.ErrVault` with `errors.Is`, whose
message names the path, Vault's status and the errors Vault listed, never the token or a value. Its
`StatusCode` and `Errors` fields hold them, and it unwraps to the client's error: `errors.As`
reaches the `*api.ResponseError`. A read that ran out of time fails with an error matching
`context.DeadlineExceeded`. A response that isn't a JSON object, or a secret holding a key more
than once, fails with `cache.ErrInvalidSecretData`. The client has already retried what its retry
policy retries (by default 412, 429, 5xx other than 501, and lost connections).

| The error says | Cause | Fix |
|---|---|---|
| `403 Forbidden: permission denied` | The token is missing, invalid or expired, or its policy lacks `read` on the path | Step 2 and step 3; for KV version 2, the policy needs the `data/` path |
| `404 Not Found: no handler for route` | No KV engine is mounted at the mount path | Set `Options.MountPath`, or check the namespace |
| `404 Not Found`, with no errors | A proxy answered, not Vault | Check the address |
| `503 Service Unavailable: Vault is sealed` | Vault is sealed | Unseal it |
| `307 Temporary Redirect` | A standby or proxy redirected the read, which isn't followed | Point the address at the active node or a load balancer |
| `follows a redirect itself` (`ErrInvalidArgument`) | `DisableRedirects` isn't set | Step 4 |
| `must be https` (`ErrInvalidArgument`) | The address is http on a host that isn't loopback | Use https |
| `couldn't read ... from Vault` | Vault couldn't be reached, even after the client's retries | Check the network path, and `api.Config.Timeout` |
| A value you expected returns 0 | The path or key differs in case, the key holds `null`, an object or an array, or the name isn't a Vault path | Step 1 |

## Run the integration tests

The integration tests read a secret you provide, from a KV version 2 engine at `secret`, with a
token that can read it. They're reported as skipped unless `HKDFGUARD_TEST_VAULT_SECRET_NAME` is
set. They read the same variables as the .NET tests:

| Variable | Holds |
|---|---|
| `HKDFGUARD_TEST_VAULT_SECRET_NAME` | The secret's `path#key`, e.g. `hkdfguard/test#value`. Required |
| `HKDFGUARD_TEST_VAULT_ADDR` | Vault's address; `https://127.0.0.1:8200` if unset |
| `HKDFGUARD_TEST_VAULT_TOKEN` | A token that may read the secret |
| `HKDFGUARD_TEST_VAULT_CACERT` | The server's CA, if the operating system doesn't trust it |
| `HKDFGUARD_TEST_VAULT_SECRET_JSON` | Optional: the JSON object of keys the secret holds, each then read and compared |

```sh
vault kv put secret/hkdfguard/test value=s3cret username=app
cd cache/hashicorpvault
HKDFGUARD_TEST_VAULT_ADDR=https://127.0.0.1:8200 HKDFGUARD_TEST_VAULT_TOKEN=... \
HKDFGUARD_TEST_VAULT_CACERT=/path/to/vault-ca.pem HKDFGUARD_TEST_VAULT_SECRET_NAME='hkdfguard/test#value' \
HKDFGUARD_TEST_VAULT_SECRET_JSON='{"value":"s3cret","username":"app"}' \
go test -run TestVaultIntegration -v ./...
```

The tests ignore `VAULT_*` variables, so your own Vault environment doesn't change what they read.
They never list, write or delete.
