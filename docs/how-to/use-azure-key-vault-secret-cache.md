# Cache Azure Key Vault secrets

This page reads secrets from Azure Key Vault in Go with `cache/azurekeyvault`, a
`hkdfguard.ProtectedReadOnlyCache` over the secrets in one vault. Nothing is fetched up front: the
first `Decrypt` or `MaxDecryptedLength` for a name reads that one secret with Get Secret, encrypts it
under the key ring's current key, bound to its name, and caches only the ciphertext. Later lookups
never call Key Vault.

It is the Go port of the .NET `AzureKeyVaultSecretCache` (`HkdfGuard.Cache.AzureKeyVault`), built
on `cache.RemoteCache` like the other secret store caches.

## 1. Grant the application `get` on secrets

The cache never lists the vault, its secrets or their versions: it only reads the secret a lookup
names. So the application needs nothing but **get** on secrets:

- With Azure RBAC, assign the **Key Vault Secrets User** role, on the vault or on each secret it
  reads:

  ```bash
  vaultId=$(az keyvault show -n myvault --query id -o tsv)
  az role assignment create --assignee <app-principal-id> --role "Key Vault Secrets User" \
    --scope "$vaultId/secrets/Db-Password"
  ```

- With vault access policies, give it the **Get** secret permission only.

Never grant **list**: it isn't needed, and it would let anyone controlling the application learn
every secret's name.

## 2. Give the process a credential

Every call is authorized by an `azcore.TokenCredential`. Deployed, use a **managed identity**
(`azidentity.NewManagedIdentityCredential`, or `azidentity.NewDefaultAzureCredential`, which finds
it); on a developer machine, `DefaultAzureCredential` uses your `az login`.

## 3. Create the cache

Add the modules, and `azidentity` for the credential:

```sh
go get github.com/runsecure/hkdfguard-go github.com/runsecure/hkdfguard-go/cache/azurekeyvault \
  github.com/Azure/azure-sdk-for-go/sdk/azidentity
```

> **TODO (maintainer):** confirm these module paths resolve once the modules are tagged. Until
> then, add `replace` directives pointing at a checkout of `hkdfguard-go` (the root and
> `cache/azurekeyvault`).

Build a key ring as in [Wrap keys with Azure Key Vault](use-azure-key-vault.md) or any other key
wrapper, then:

```go
credential, err := azidentity.NewDefaultAzureCredential(nil)
if err != nil {
	log.Fatal(err)
}
secrets, err := azurekeyvault.New("https://myvault.vault.azure.net/", credential, ring, azurekeyvault.Options{})
if err != nil {
	log.Fatal(err)
}

buffer := make([]byte, 256)
defer hkdfguard.Wipe(buffer)
n, err := secrets.Decrypt(ctx, "Db-Password", buffer) // 0 if the secret doesn't exist
if err != nil {
	log.Fatal(err)
}
password := buffer[:n]
```

Size the buffer with `MaxDecryptedLength` when a secret's length isn't known; it fetches the secret
too, if it isn't cached yet. `New` makes no call: the first lookup does.

- **Names.** Key Vault secret names are 1-127 ASCII letters, digits and hyphens, compared ignoring
  case, so `Db-Password` and `DB-PASSWORD` are one secret and one cache entry. Any other name (a
  configuration path such as `ConnectionStrings:Admin`, say) returns 0 without a call, and is never
  put into a request URL, so the cache can go last in a `cache.Collection` behind other sources.
  `azurekeyvault.IsValidSecretName` is the rule.
- **Secrets holding JSON.** A secret whose value is a JSON object, such as
  `{"username":"app","password":"..."}`, is cached whole under its name and each top-level member
  under `name#key` (`Db-Login#password`), all from one call. A string member is cached as its text;
  a number, `true` or `false` as its JSON text; `null`, objects and arrays aren't keys. Keys are
  matched exactly, though secret names aren't.
- **Missing and empty secrets.** A secret that doesn't exist (404), or whose value is empty, returns
  0 and is looked up again next time - as is a key a cached secret doesn't hold, which costs a call
  every time.
- **No refresh.** A cached value is kept for the life of the cache: a new secret version is picked
  up by a new cache.
- **Client options.** `Options.ClientOptions` (an `*azsecrets.ClientOptions`) configures the cache's
  Key Vault client: retries, an HTTP transport with timeouts, the API version. `New` copies it and
  adds its own policy to the copy only, so the value you pass, and any other client built from it,
  is unchanged. Every lookup takes a `context.Context`, whose cancellation and deadline the SDK
  honours.
- **Logging.** With `Options.Logger` set, a failed fetch is logged at error level and, while
  `diagnostics.Cache` has sensitive logging enabled, each fetched secret's name (never its value) at
  debug level.

## A secret never becomes a string

The Azure SDK for Go hands a secret over as a Go `string`, and buffers each response body in a
`[]byte`, neither of which can be zeroed. So the cache makes its own `azsecrets.Client`, with a
pipeline policy of its own, which acts only on the cache's own Get Secret calls:

1. It stops azcore downloading the response body (azcore's body-download policy runs below it).
2. It reads the body off the network into a buffer of its own, takes the top-level `value` out of
   it as bytes, and hands those to the cache to encrypt (`cache.CaptureJSONBody`).
3. It gives the SDK the body with `value` blanked to `""`: the SDK parses that copy as usual, and
   holds nothing secret.

Every buffer the cache's code held the value in is zeroed once it is encrypted. Any other response
to that call (Key Vault's 401 authentication challenge, an error) is buffered as azcore would have,
for the SDK's error handling.

For the same reason, `New` refuses client options that log response bodies
(`Logging.IncludeBody`): azcore's logging policy also runs below the cache's, and would log every
secret's value.

## Limitations

- **Copies the cache can't zero.** What no code above the HTTP stack can reach are that stack's own
  buffers: TLS decryption, the connection's read buffer, and gzip's when the transport decompresses
  a response. `nativev1.HardenProcess` keeps a debugger or crash dump away from them.
- **A transport you supply** in `ClientOptions.Transport` sees every response before the cache does;
  give it nothing that records bodies.
- **No refresh**, as above: rotate a secret, then restart (or rebuild the cache).

## If something goes wrong

A missing or empty secret isn't an error: `Decrypt` returns 0 and `MaxDecryptedLength` false. Any
other failure is returned from the lookup unchanged, and nothing is cached:

| Error | Cause | Fix |
|---|---|---|
| `*azcore.ResponseError`, `Forbidden` / `ForbiddenByRbac` (HTTP 403) | The identity lacks `get` on the secret | Step 1 |
| `*azcore.ResponseError`, `Forbidden` with "operation get is not allowed on a disabled secret" | The secret's current version is disabled | Enable it, or set a new version |
| `DefaultAzureCredential: failed to acquire a token` | No credential could get a token | Step 2 |
| `dial tcp`, `no such host`, `i/o timeout` | The vault can't be reached: no network route, a proxy, or a wrong vault name | Check the network path to the vault |
| `cache.ErrInvalidSecretData` | Key Vault's answer isn't a Get Secret response (a proxy's page, say), or the secret is a JSON object holding a member name twice | Check what answers at the vault URL; fix the secret |
| `azurekeyvault.ErrInvalidArgument` (from `New`) | The vault URL isn't `https://...`, a credential or ring is missing, or the options log bodies | Fix the argument |

Use `errors.As` to reach the `*azcore.ResponseError`, whose `StatusCode` and `ErrorCode` say what Key
Vault refused, and whose `Error()` shows its full answer (an error body never holds a secret).

## Integration tests

The package's integration tests read a real secret, and are skipped unless
`HKDFGUARD_TEST_AZURE_SECRET_ID` names one - in the environment or in `azure.test.properties` at the
repository root, as for the [key wrapper's](run-azure-key-vault-integration-tests.md):

```properties
# The secret's identifier, without a version.
HKDFGUARD_TEST_AZURE_SECRET_ID=https://myvault.vault.azure.net/secrets/hkdfguard-integration-config
# Optional: the JSON object it holds, compared whole and by key ("...#api-credential-21").
HKDFGUARD_TEST_AZURE_SECRET_JSON={"api-credential-21":"..."}
# Optional: true when the vault also holds each of those keys as a secret of its own.
HKDFGUARD_TEST_AZURE_SEPARATE_SECRETS=true
```

```sh
az login
cd cache/azurekeyvault && go test -run TestAzureKeyVaultSecretCacheIntegration -v ./...
```

The identity needs only `get` on those secrets; the tests never list, create, change or delete one.
