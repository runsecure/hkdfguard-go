# Wrap keys with Azure Key Vault

This page sets up two Azure Key Vault keys as HkdfGuard's KEK and uses them from Go with
`azurekeyvault.KeyWrapper`, in place of the native TPM, Secure Enclave or Platform Crypto Provider
KEK.

To run the Azure Key Vault integration tests against keys of your own, see
[Run the Azure Key Vault integration tests](run-azure-key-vault-integration-tests.md).

## Why two keys

A Key Vault (Standard or Premium) offers RSA and EC keys. Only RSA keys can wrap; EC keys can only
sign and verify. RSA-OAEP wrapping needs nothing but the public key, which isn't secret, so on its
own anyone could produce a wrapped DEK holding a key *they* chose, and your application would encrypt
new data under it.

So `azurekeyvault.KeyWrapper` uses:

- an **RSA key** (2048 or 3072 bits) to wrap and unwrap each DEK, with RSA-OAEP-256;
- a separate **EC P-256 key** to sign each wrapped DEK, with ES256.

Signing happens inside Key Vault and needs the `sign` permission. Unwrap checks the signature
before it unwraps anything. So a key file the application accepts proves it was made by a principal
allowed to sign: give that permission to the pipeline that creates key files, never to the
application.

| | AWS KMS | Azure Key Vault |
|---|---|---|
| Keys | One symmetric key | An RSA key to wrap, an EC P-256 key to sign |
| Who can create a key file the app accepts | Principals allowed `kms:Encrypt` | Principals allowed `sign` on the EC key |
| Context binding | Encryption context (AAD) | A context string bound into the signature |
| New DEKs | Generated inside KMS | Generated in the process, then wrapped |
| Client | The application's `*kms.Client` | Created by the wrapper from the application's credential |

Wrapped DEKs aren't interchangeable between wrappers: a key file belongs to the kind of wrapper that
made it. Between languages they are: a key file made by the .NET `AzureKeyVaultKeyWrapper`, the Java
`AzureKeyVaultKeyWrapperImpl`, or the Python or Node `AzureKeyVaultKeyWrapper` is read by this one,
and the other way round, given the same two keys and context.

## 1. Create the keys

Create a vault, or use an existing one, with **purge protection** turned on. Deleting a key makes
every DEK wrapped under it, and all data encrypted under those DEKs, permanently unrecoverable;
purge protection keeps a deleted key recoverable for its retention period.

Create the two keys, each allowed only the operations it needs:

```bash
az keyvault key create --vault-name myvault --name myapp-wrap --kty RSA --size 3072 --ops wrapKey unwrapKey
az keyvault key create --vault-name myvault --name myapp-sign --kty EC --curve P-256 --ops sign verify
```

In the portal: **Keys**, **Generate/Import**, then for the first choose **RSA** and 2048 or 3072
bits, and for the second **EC** and **P-256**. After creating each, open its version and clear every
permitted operation except the two above.

Use 2048 or 3072 bits for the RSA key. A 4096-bit key's wrapped DEK is too large for a key file
(`hkdfguard.MaxWrappedKeyBytes`, 512 bytes), and wrapping under one is refused.

Copy each key's **key identifier** without the version, for example
`https://myvault.vault.azure.net/keys/myapp-wrap`.

## 2. Grant each identity only what it calls

Every operation the wrapper performs is a Key Vault call: `wrapKey` and `sign` to make a key file,
`verify` and `unwrapKey` to read one. It never reads a key, so no identity needs `get`.

With Azure RBAC, assign roles on each **key**, not the vault:

| Identity | On the RSA key | On the EC key |
|---|---|---|
| Release pipeline that creates key files | Key Vault Crypto Service Encryption User | Key Vault Crypto User |
| Application | Key Vault Crypto Service Encryption User | HkdfGuard Key Verifier (below) |

No built-in role allows `verify` without also allowing `sign`, so the application's role on the EC
key is a custom one. Create it once per subscription, from `verifier.json`:

```json
{
  "Name": "HkdfGuard Key Verifier",
  "Description": "Verify signatures with a Key Vault key.",
  "Actions": [],
  "DataActions": ["Microsoft.KeyVault/vaults/keys/verify/action"],
  "AssignableScopes": ["/subscriptions/<subscription-id>"]
}
```

```bash
az role definition create --role-definition @verifier.json

vaultId=$(az keyvault show -n myvault --query id -o tsv)
az role assignment create --assignee <app-principal-id> --role "Key Vault Crypto Service Encryption User" \
  --scope "$vaultId/keys/myapp-wrap"
az role assignment create --assignee <app-principal-id> --role "HkdfGuard Key Verifier" \
  --scope "$vaultId/keys/myapp-sign"
```

With vault access policies instead, which apply to the whole vault: the pipeline gets **Wrap Key**
and **Sign**; the application **Unwrap Key** and **Verify**.

> **Security:** never give the application `sign` on the EC key (Key Vault Crypto User, Crypto
> Officer, or the Sign access policy). With it, anyone controlling the application, and able to
> replace a key file, could choose its DEK.

## 3. Give the process a credential

Every call is authorized by an `azcore.TokenCredential`. Deployed, use a **managed identity**
(`azidentity.NewManagedIdentityCredential`, or `azidentity.NewDefaultAzureCredential`, which finds
it); on a developer machine, `DefaultAzureCredential` uses your `az login`. Don't give a deployed
process a client secret.

## 4. Create the wrapper

Add the modules, and `azidentity` for the credential:

```sh
go get github.com/runsecure/hkdfguard-go github.com/runsecure/hkdfguard-go/keywrapping/azurekeyvault \
  github.com/runsecure/hkdfguard-go/cryptoprovider/aesgcm256 \
  github.com/Azure/azure-sdk-for-go/sdk/azidentity
```

> **TODO (maintainer):** confirm these module paths resolve once the modules are tagged. Until
> then, add `replace` directives pointing at a checkout of `hkdfguard-go` (the root, `securefile`,
> `keywrapping/azurekeyvault` and `cryptoprovider/aesgcm256`).

`keywrapping/azurekeyvault` brings the `securefile` module, which reads key files with
`golang.org/x/sys`. Neither needs cgo or a C compiler, on any platform.

```go
credential, err := azidentity.NewDefaultAzureCredential(nil)
if err != nil {
	log.Fatal(err)
}
wrapper, err := azurekeyvault.New(
	"https://myvault.vault.azure.net/keys/myapp-wrap",
	"https://myvault.vault.azure.net/keys/myapp-sign",
	credential, azurekeyvault.Options{Context: "com.example.myapp"})
if err != nil {
	log.Fatal(err)
}
```

- **Give key identifiers without a version.** Each key file records the versions Key Vault reports
  having used, so both keys can be rotated in Key Vault with no change here: new key files are made
  under the new versions, and old ones keep naming theirs. Keep an old version enabled for as long
  as key files made with it are in use. To pin a version instead, add it to the identifier
  (`.../keys/myapp-wrap/<version>`).
- **The context** is bound into every key file's signature and must be given again, exactly, to
  reveal it. Use one value per application, so a key file made for one can't be used by another
  that shares the keys. It isn't secret.
- **Client options.** `Options.ClientOptions` (an `*azkeys.ClientOptions`, copied by `New`) is given
  to every Key Vault client the wrapper creates: retries, an HTTP transport with timeouts, logging,
  for example `&azkeys.ClientOptions{ClientOptions: azcore.ClientOptions{Retry: policy.RetryOptions{MaxRetries: 2}}}`.
  Every wrapper call also takes a `context.Context`, whose cancellation and deadline the SDK
  honours.
- **Nothing to close.** The wrapper creates one client per vault, which holds nothing that needs
  releasing; keep the wrapper for as long as anything uses it, including a key ring's background
  refresh.

## 5. Build a key ring with an ephemeral key

An ephemeral key is generated at startup and never written anywhere. Key Vault has no "generate data
key", so the wrapper generates it in the process and wraps it:

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

protector, err := ring.CreateProtector("customer-notes")
if err != nil {
	log.Fatal(err)
}
encrypted, err := protector.Encrypt(ctx, []byte("The launch code is 0000"))
```

An ephemeral key needs `sign` to be made, which step 2 keeps from the application. Use key files
instead, or give an identity that only ever uses ephemeral keys its own pair of keys. Everything
encrypted under an ephemeral key is lost when the process exits.

## 6. Create a key file

The release pipeline creates key files with the wrapper itself, running as the pipeline identity
from step 2:

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

To wrap the key of an `aesgcm256.PipelineDataProtector`, use `Wrap` as in
[Wrap keys with AWS KMS](use-aws-kms.md#6-create-a-key-file). An RSA-2048 key's key file is 359
bytes, an RSA-3072 key's 487.

Key files are read only from where no untrusted account could have written or replaced them,
exactly as for AWS KMS: see [Where key files can live](use-aws-kms.md#where-key-files-can-live), and
set `Options.KeyFileTrust` if the pipeline writes key files as an account of its own. Then use the
key file as in [Use the key file](use-aws-kms.md#7-use-the-key-file).

## Choosing a refresh interval

Every key in a ring re-reveals itself once per `KeyRefreshInterval`: a verify and an unwrap, both
Key Vault calls. See [Choosing a refresh interval](use-aws-kms.md#choosing-a-refresh-interval) for
the trade-off, and [Key Vault pricing](https://azure.microsoft.com/pricing/details/key-vault/) for
what each operation costs: RSA 3072 and EC keys are billed at a higher rate than RSA 2048.

## Limitations

- **Every operation is a Key Vault call.** The Azure SDK for Go does no cryptography in the
  process, so wrapping and verifying go to the vault too, as in the Node port; the .NET, Java and
  Python ports do both with the public key in the process.
- **Copies the wrapper can't zero.** The wrapper zeroes its own copy of a key it wraps, and the
  slice the SDK decodes an unwrapped key into once it is copied into your `result`. But the SDK
  sends and receives that key base64-encoded in a JSON body, in buffers it doesn't expose.
  `nativev1.HardenProcess` keeps a debugger or crash dump away from them.
- The key-file limitations are those of [Wrap keys with AWS KMS](use-aws-kms.md#limitations).

## If something goes wrong

Every Key Vault failure is an `*azurekeyvault.Error` (matching `azurekeyvault.ErrKeyVault` with
`errors.Is`) whose message names the operation, the key, and for a refusal Key Vault's error code and
the HTTP status. It unwraps to the SDK's error: `errors.As` reaches the `*azcore.ResponseError`, whose
`Error()` shows Key Vault's full answer. A failed unwrap zeroes the caller's buffer. A cancelled or
expired `context.Context` is returned as the SDK reports it. Argument errors - a key identifier that
isn't one, included - wrap `azurekeyvault.ErrInvalidArgument`. Reading a key file fails as described
for [AWS KMS](use-aws-kms.md#if-something-goes-wrong).

| The message says | Cause | Fix |
|---|---|---|
| `Forbidden (HTTP 403)` | The identity lacks the operation on that key (`ForbiddenByRbac` in the SDK's error), or the key doesn't permit it (`KeyOperationForbidden`): the two identifiers are swapped, or step 1's `--ops` left it out | Step 2; check both identifiers and step 1's `--ops` |
| `KeyNotFound (HTTP 404)` | The identifier is wrong, or the key version a key file names was purged | Check the identifier; restore the version |
| `signature doesn't verify` | The key file was altered, made under another context, or not signed by a principal allowed to sign | Restore it; use the same context |
| `not a wrapped DEK written by AzureKeyVaultKeyWrapper` | The file isn't one of this wrapper's key files | Check the path and wrapper |
| `Use a 2048- or 3072-bit RSA key` | The wrapping key is 4096 bits | Create a smaller RSA key |
| `The signing key must be an EC P-256 key` | The signing key is another curve | Create an EC P-256 key |
| `reported key ... instead` | Key Vault answered for a different key | Check both identifiers |
| `isn't a Key Vault key identifier` (`ErrInvalidArgument`) | An identifier isn't `https://{vault}/keys/{name}`, with an optional version | Copy the key identifier again |
| `dial tcp`, `no such host`, `i/o timeout` | The vault can't be reached: no network route, a proxy, or a wrong vault name | Check the network path to the vault |
| `DefaultAzureCredential: failed to acquire a token` | No credential could get a token | Step 3 |
