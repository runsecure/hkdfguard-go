# hkdfguard-go
HkdfGuard KeyWrapping and Secrets Protection Library for GoLang

The Go port of the HkdfGuard .NET libraries: application code works against a `KeyRing` to
encrypt and decrypt byte payloads under AES-256-GCM data encryption keys (DEKs) that only ever
exist on disk wrapped under a platform-held key-encryption key (KEK): a TPM2 key on Linux, a
Secure Enclave key on macOS, a Platform Crypto Provider key on Windows - or a symmetric AWS KMS
key, a pair of Azure Key Vault keys, or a symmetric Google Cloud KMS key. Values, key files,
purposes and names are byte-identical between the ports, so one deployment serves both.

**Documentation:** [docs/](docs/README.md) - a [getting-started tutorial](docs/getting-started.md),
the [`hkdfguard` tool reference](docs/reference/cli.md), and how to
[wrap keys with AWS KMS](docs/how-to/use-aws-kms.md),
[with Azure Key Vault](docs/how-to/use-azure-key-vault.md) or
[with Google Cloud KMS](docs/how-to/use-google-kms.md).

## Packages

### `hkdfguard` (module root)

Go port of `HkdfGuard.Abstractions`: the interfaces every implementation satisfies
(`KeyWrapper`, `CryptoProviderFactory`/`CryptoProvider`, `DataEncryptionKey`, `KeyRing`,
`EncryptedFormatProvider`, `DataProtector`, `PipelineDataProtector`, `SecretPipelineWriter`,
`ProtectedCache`), the shared
cross-port rules (`ConfigurationPurpose`/`ConfigurationAAD`, `ValidateServiceName`), limits and
defaults, and the `Wipe`/`IsZero` secret-memory helpers. Implementation packages import this one
and never each other, so each can be swapped independently.

### `diagnostics`

Go port of `HkdfGuard.Diagnostics`: OpenTelemetry tracing, metrics, a per-component
sensitive-logging toggle, and `log/slog` helpers. Span, event, metric, and attribute names are
identical to the .NET port.

```go
ctx, span := diagnostics.Cache.Start(ctx, diagnostics.SpanCacheAdd)
defer span.End()

if err := doWork(ctx); err != nil {
	diagnostics.RecordError(span, err)
	diagnostics.OperationFailed(ctx, logger, diagnostics.SpanCacheAdd, err)
	diagnostics.CacheOperations().Add(ctx, 1, metric.WithAttributes(
		diagnostics.AttrOperationName.String(diagnostics.SpanCacheAdd),
		diagnostics.AttrResult.String(diagnostics.ResultError)))
	return err
}
diagnostics.Cache.LogSensitiveOperation(span, diagnostics.SpanCacheAdd, diagnostics.AttrName.String(name))
```

Tracers and meters come from the global providers (`otel.SetTracerProvider` /
`otel.SetMeterProvider`) at call time, so providers can be installed at any point.

### `dek`

Go port of `HkdfGuard.DataEncryptionKey`: `Key`, `KeyRing` (keys by version, with ephemeral-key
rotation and retention), its `DataProtector`s, `DefaultFormatProvider` (`enc::v<version>::<base64>`),
and `Build`, which assembles a ring from key files and ephemeral keys:

```go
ring, err := dek.Build(ctx, dek.Config{
	KeyWrapper:            wrapper,               // e.g. nativev1.New("com.example.orders")
	CryptoProviderFactory: aesgcm256.NewFactory(), // the cipher: swap for another factory
	KeyRefreshInterval:    time.Minute,
	KeyFiles:              map[int]string{1: "/etc/app/key.v1"},
})
protector, err := ring.CreateProtector("orders")
```

`Build` reads every key file through its `KeyWrapper` (`KeyWrapper.ReadKeyFile`), never with
ordinary file I/O: whoever can replace a key file chooses the key new data is encrypted under, so
reading one is part of the key wrapper's contract, and a wrapper must refuse a file another account
could have written or replaced. The native key wrapper reads through the native library's checks
(see below). A file that isn't a wrapped key fails with an error wrapping
`hkdfguard.ErrInvalidKeyFile` (`dek.ErrInvalidKeyFile` is the same sentinel).

Settings can also come from a file. `dek.Options` has the field names and units of the .NET
port's `HkdfGuardOptions`, so one `appsettings.json` section configures both ports:

```go
options, err := dek.OptionsFromJSON(appsettingsJSON, "HkdfGuard") // validated by Config
config, err := options.Config(wrapper, aesgcm256.NewFactory())
ring, err := dek.Build(ctx, config)
```

### `cache`

Go port of `HkdfGuard.Cache` and `ProtectedCacheBase`: values encrypted under a `KeyRing` and bound
to their names (`hkdfguard.CacheAAD`), matched ignoring ASCII case only.

- `cache.New(ring)` - the read/write `ProtectedCache` (`Add`, `AddOrUpdate`, `Decrypt`).
- `cache.NewReadOnly(ring, source)` - filled on demand from a `cache.Source`, one value per name.
- `cache.NewRemote(ring, store, options)` - the port of `RemoteSecretCache`: a read-only cache over a
  remote secret store, filled one secret per fetch. A name is a secret's name, optionally followed
  by `#` and a key (`"app-config#password"`); one fetch caches the whole value and every member of a
  JSON object it holds, and concurrent misses on the same secret share one fetch. A store
  implements only `cache.SecretStore` (`IsValidName`, `Fetch`); `cache.CaptureJSONBody` and
  `cache.CaptureJSONKeys` take a secret out of a JSON response body before an SDK can turn it into
  a string, so a fetched secret is never a Go string. The stores HkdfGuard ships are the
  `cache/*` modules below.
- `cache.NewCollection(a, b, ...)` - several caches behind one lookup, first match wins. A source
  that fails fails the lookup, even when a later source holds the name, so add local sources (a
  `cache.Cache`, a `cache/filepersecret` cache) before remote ones: a remote cache doesn't remember a
  name its store lacks, so one added first makes a network call for every local-only name.

### `encryptedconfig`

Go port of `HkdfGuard.EncryptedConfiguration`: reads the secrets a deployment pipeline encrypted
into configuration (with `aesgcm256.PipelineDataProtector`), each bound to its configuration key.
It works with any configuration source through a `Lookup` function, with helpers for the .NET
conventions so one pipeline output serves both ports:

```go
values, _ := encryptedconfig.FlattenJSON(appsettingsJSON) // {"A":{"B":..}} -> "A:B"
lookup, _ := encryptedconfig.NewMapLookup(values)         // ASCII-case-insensitive
// or: lookup := encryptedconfig.EnvLookup("APP_")       // "A:B" -> APP_A__B
secrets := encryptedconfig.New(ring, lookup)
n, err := secrets.Decrypt(ctx, "ConnectionStrings:Admin", buf)
```

A `Reader` is a `ProtectedReadOnlyCache`, so it can join a `cache.Collection`. `Decrypt` returns 0
both for a missing key and for a protected empty value; `TryDecrypt` also reports whether the key
was found, when the two must be told apart.

### `cryptoprovider/aesgcm256` (separate module)

Go port of `HkdfGuard.CryptoProvider.AesGcm256`: the AES-256-GCM `CryptoProviderFactory` (keys
re-revealed in the background, fail-closed refresh policy, per-key encryption budget) and the
`PipelineDataProtector`. Ciphertext is byte-compatible with the .NET port. Failures callers act on
use the cipher-neutral errors in `hkdfguard` (`ErrAuthenticationFailed`, `ErrKeyAccessSuspended`,
`ErrEncryptionLimitReached`, `ErrClosed`), so another cipher module can replace it unchanged.

#### Encryption budget

With random 96-bit nonces, AES-GCM is safe for about 2^32 encryptions under one key (NIST
SP 800-38D). Each crypto provider counts the encryptions under its key, warns at 2^28, and
refuses to encrypt past 2^31 (`aesgcm256.MaxEncryptionsPerKey`). Decryption is never limited.

That count is kept per process, by design. It is exact for the key an application should encrypt
with at runtime: an ephemeral key, generated at startup and held only in that process's memory, so
no other process or restart ever adds to its use. Key files are different. They carry what the
deployment pipeline encrypted and are meant to be decrypted at runtime; every process that loads a
key file, and every restart, starts a fresh count for it.

**For encrypt operations, add an ephemeral key** at a version above every key file
(`EphemeralKeys: []int{2}` beside `KeyFiles: map[int]string{1: ...}` in `dek.Config`). New values are then encrypted under it, while the pipeline's values still decrypt
under their key files. A value encrypted under an ephemeral key can't be decrypted once the process
exits, which suits caches and other in-process data; never persist it.

If an application does encrypt values that must outlive the process under a key file, its
encryptions under that file are not counted together across instances and restarts. Bound them by
deploying a new key file at a higher version regularly. `dek.Config.KeyFileMaxAgeDays` (365 days by default) enforces this: a
current key file stops encrypting at that age, and decryption under it never stops.

### `keywrapping/nativev1` (separate module)

Go port of `HkdfGuard.KeyWrapping.V1`: a `hkdfguard.KeyWrapper` over the OS's native HkdfGuard KMS
library (TPM2 on Linux, Secure Enclave on macOS, Platform Crypto Provider on Windows). The library
is loaded only from its fixed install location, after verifying path ownership and permissions,
the code signature (Authenticode / Developer ID), and the dynamic linker's environment; after
loading, the file the OS actually mapped must be the verified one on every platform. On macOS
the per-user location is found from the account database, never `$HOME`, and the library must be
at least version 0.9.0 (its `LC_ID_DYLIB` current version, covered by the signature), so an older
signed release can't be planted in its place. On Windows the same 0.9.0 floor applies to
`HkdfGuard.dll`'s signed version resource, and a DLL with none is refused. On Linux, before
loading, the process's own dynamic linker is asked in list mode (`ld.so --list`, what `ldd` uses)
where it would find every library `libhkdfguard.so.1` pulls in; each must pass the same ownership
checks, so a dependency found somewhere writable is refused before any of its code runs. The Linux
library is not content-pinned; verify a release with Sigstore/cosign (`gh attestation verify`)
before installing it.

Certificate revocation: on Windows, once the signature and its pins have passed, the loader asks
WinVerifyTrust once more, now checking revocation across the signing chain and allowed to fetch
revocation data over the network. It refuses the library only when a certificate is definitely
revoked; if revocation can't be determined (offline, no data), it loads. A host whose network
silently drops traffic, rather than refusing it, may stall once, on the first load, until that
lookup times out. On macOS revocation isn't checked: the defences are the Developer ID and Team ID
pins, the admin-only system install, and the minimum library version. A compromised signing
identity is answered by a new release and a raised minimum version.

```go
wrapper, err := nativev1.New("com.example.orders") // service must be provisioned first
```

It also reads key files through the native library's `hkdfguard_open_file` (`KeyWrapper.ReadKeyFile`,
which `dek.Build` uses), so the bytes come back still wrapped after the native checks: the file's
size and format; that it doesn't hold what looks like an *unwrapped* key (32 raw bytes, optionally
followed by one line ending (LF or CRLF), or its hex or base64 - treat that as a key exposure); and that no account other than an administrator or the
reader could have written or replaced it, nor redirected its path through a link, junction, 8.3
short name or network path. A refusal is a `*nativev1.KeyFileError` naming the file, the status
and its meaning, matchable with `errors.Is` against `fs.ErrNotExist`, `fs.ErrPermission` or
`hkdfguard.ErrInvalidKeyFile`.

Every platform's native library returns the same status codes (the header's `HKDFGUARD_ERR_*`
table: -17 no KEK, -18 access denied, -10..-12 a malformed, altered or unsupported payload, -13 a
payload version this host's policy doesn't use, -16 a
payload wrapped under another KEK, -32..-39 key-file refusals, and so on); a `*nativev1.StatusError`
or `*nativev1.KeyFileError` carries the code and what it means on this platform. The installed
files are `%ProgramFiles%\HkdfGuard\v1\HkdfGuard.dll` and `hkdfguard.exe` on Windows,
`libhkdfguard.so.1` and `/usr/bin/hkdfguard` on Linux, and `libhkdfguard.dylib` and
`hkdfguard` on macOS.

#### Process hardening

DEKs pass through your process's memory, so a crash dump, or another process of the same user
attaching a debugger or reading that memory, could recover them. `nativev1.HardenProcess()` calls
the native library's `hkdfguard_harden_process_with_flags` to close that off, on every platform:

| Platform | What it does |
|---|---|
| Windows | Crash reports leave out the heap, and the process's and its threads' access lists are replaced so only SYSTEM can read or write its memory, inject threads or duplicate its handles. Its own account keeps only query, synchronize and terminate. |
| Linux | Core dumps off (hard limit included), and the process marked non-dumpable, which also stops ptrace and `/proc/<pid>/mem` access by the same user. |
| macOS | Core dumps off and debugger attachment denied. Whether code can be injected depends on the host executable's code signature, which the library checks but can't change. |

Neither the native library nor any machine policy does this for you: it changes process-wide
state your application owns, so it is opt-in. Call it once, early in startup - the first thing in
`main` on Windows, and after any privilege drop on Linux:

```go
if err := nativev1.HardenProcess(); err != nil {
    log.Fatal(err) // a *nativev1.StatusError if the hardening failed: don't start
}
```

Debuggers, crash dumps and core dumps stop working for the process. It is a same-user barrier: it
does not stop administrators, root, SYSTEM, `SeDebugPrivilege`, `CAP_SYS_PTRACE` or the kernel,
and it does not keep memory out of swap, the page file or hibernation files.

`nativev1.HardenProcessWithOptions(nativev1.RequireProtectedSignature)` is the strict form the
native command-line tools use: it fails unless no other process of the same user can debug or
inject into this one. `HardenProcessOptions` is a bitmask; a bit this package doesn't define is
refused before any native call.

- **Windows:** it also closes threads started later, and everything else the process creates
  afterwards without its own security descriptor (child processes, named pipes, named events), to
  its own account. Use it in a service that shares no objects with other processes by name.
- **macOS:** it fails unless the host executable is signed with the Hardened Runtime and without
  the `get-task-allow` or `DYLD_*` entitlements, so unsigned or ad-hoc signed binaries (`go run`,
  `go test`, a plain `go build`) can't use it. Without it, a weak signature is only logged.
- **Linux:** it adds nothing; the plain call already guarantees it.

**Go on Windows:** the plain call closes the threads that exist when it runs, and threads started
later keep the default access, which lets other processes of the same user read and change their
registers. A Go program can't call it "before starting threads": the runtime starts OS threads
before `main` (even before `init` functions run), and keeps starting more whenever it needs them -
a goroutine blocked in a system call, more runnable goroutines, the garbage collector. Calling it
first thing in `main` covers the threads that exist then, not the ones the runtime adds later, so
**use `RequireProtectedSignature` for a Windows service**: it closes later threads too.

It is its own module (`github.com/runsecure/hkdfguard-go/keywrapping/nativev1`) because macOS and
Linux builds need cgo (`CGO_ENABLED=1` and a C toolchain); Windows needs neither. See
[Testing](#testing) for its native integration tests.

### `keywrapping/awskms` (separate module)

Go port of `HkdfGuard.KeyWrapping.AwsKms`: a `hkdfguard.KeyWrapper` over one symmetric AWS KMS key,
through the AWS SDK for Go v2. DEKs are wrapped with `Encrypt`, revealed with `Decrypt` (the key and
`SYMMETRIC_DEFAULT` pinned, so a key file wrapped under any other key is refused) and generated with
`GenerateDataKeyWithoutPlaintext`, so on that path the plaintext DEK never leaves KMS. An optional
encryption context is bound into every wrapped DEK. Wrapped DEKs are byte-compatible with the .NET,
Java, Python and Node wrappers under the same key and context.

```go
cfg, err := config.LoadDefaultConfig(ctx) // the application's: credentials, region, retries
wrapper, err := awskms.New(kms.NewFromConfig(cfg), keyARN,
	awskms.Options{EncryptionContext: map[string]string{"purpose": "com.example.myapp"}})
```

A wrapped DEK out of range (empty, or over `hkdfguard.MaxWrappedKeyBytes`) is refused before KMS is
called; the wrapper's copy of a key sent to `Encrypt`, and the SDK's decoded `Decrypt` plaintext,
are zeroed once used, and a failed unwrap zeroes the caller's buffer. Every KMS failure is an
`*awskms.Error` (`errors.Is(err, awskms.ErrKMS)`) naming the operation, the key, KMS's error code
and the HTTP status, unwrapping to the SDK's error. The SDK is reached through the small
`awskms.Client` interface, which `*kms.Client` satisfies, so tests can use a fake.

Key files are read with `securefile` (below), refusing one another account could have written or
replaced: anyone who may call `kms:Encrypt` could otherwise choose the DEK new data is encrypted
under. `Options.KeyFileTrust` names who besides administrators may write them.

It is its own module so that only applications that use it depend on the AWS SDK. See
[Wrap keys with AWS KMS](docs/how-to/use-aws-kms.md), and
[Run the AWS KMS integration tests](docs/how-to/run-aws-kms-integration-tests.md) for its real-KMS
tests, which skip unless `HKDFGUARD_TEST_AWS_KMS_KEY_ID` names a key.

### `keywrapping/azurekeyvault` (separate module)

Go port of `HkdfGuard.KeyWrapping.AzureKeyVault`: a `hkdfguard.KeyWrapper` over two Azure Key Vault
keys, through the Azure SDK for Go (`azkeys`). DEKs are wrapped and unwrapped under an RSA key
(RSA-OAEP-256), and every wrapped DEK is signed by a separate EC P-256 key (ES256) and verified
before it is unwrapped: RSA wrapping needs only the public key, so without the signature anyone
could make a key file holding a DEK of their choosing. A wrapped DEK records the two key versions
it was made with - the vault and key names always come from `New` - so both keys can be rotated in
Key Vault with no change here. An optional context is bound into the signature. Wrapped DEKs are
byte-compatible with the .NET, Java, Python and Node wrappers under the same keys and context.

```go
credential, err := azidentity.NewDefaultAzureCredential(nil) // a managed identity, deployed
wrapper, err := azurekeyvault.New(
	"https://myvault.vault.azure.net/keys/myapp-wrap",
	"https://myvault.vault.azure.net/keys/myapp-sign",
	credential, azurekeyvault.Options{Context: "com.example.myapp"})
```

Every operation is a Key Vault call; none reads a key, so no identity needs `get`. Key Vault has no
"generate data key", so `GenerateAndWrap` generates the DEK in the process. The wrapper's copy of a
key it wraps, and the SDK's decoded `unwrapKey` result, are zeroed once used, and a failed unwrap
zeroes the caller's buffer. Every Key Vault failure is an `*azurekeyvault.Error`
(`errors.Is(err, azurekeyvault.ErrKeyVault)`) naming the operation, the key, Key Vault's error code
and the HTTP status, unwrapping to the SDK's error. `Options.ClientOptions` configures the Key Vault
clients the wrapper creates - its transport too, so tests can answer in-process.

Key files are read with `securefile`, as for AWS KMS. It is its own module so that only
applications that use it depend on the Azure SDK. See
[Wrap keys with Azure Key Vault](docs/how-to/use-azure-key-vault.md), and
[Run the Azure Key Vault integration tests](docs/how-to/run-azure-key-vault-integration-tests.md)
for its real-Key Vault tests, which skip unless both keys are named.

### `keywrapping/googlekms` (separate module)

Go port of `HkdfGuard.KeyWrapping.GoogleKms`: a `hkdfguard.KeyWrapper` over one symmetric Google
Cloud KMS key (purpose `ENCRYPT_DECRYPT`), through `cloud.google.com/go/kms`. DEKs are wrapped with
`Encrypt` and revealed with `Decrypt`, the key pinned, so a key file wrapped under any other key is
refused. A ciphertext names the key version that made it, so Cloud KMS's key rotation needs no
change here. Every wrapped DEK is bound, as additional authenticated data, to a fixed HkdfGuard
label and an optional context, and every request and response carries a CRC32C checksum, so data
corrupted in transit is refused. Wrapped DEKs are byte-compatible with the .NET, Java, Python and
Node wrappers under the same key and context.

```go
client, err := kms.NewKeyManagementClient(ctx) // the application's: credentials, transport, retries
wrapper, err := googlekms.New(client,
	"projects/my-project/locations/us-east1/keyRings/myapp/cryptoKeys/myapp-wrap",
	googlekms.Options{Context: "com.example.myapp"})
```

Cloud KMS has no "generate data key", so `GenerateAndWrap` generates the DEK in the process. A
wrapped DEK out of range is refused before Cloud KMS is called; the wrapper's copy of a key it
wraps, and the client's decoded `Decrypt` plaintext, are zeroed once used, and a failed unwrap
zeroes the caller's buffer. Every Cloud KMS failure is a `*googlekms.Error`
(`errors.Is(err, googlekms.ErrCloudKMS)`) naming the operation, the key, and for a refusal the gRPC
status and Google's description, unwrapping to the client's error. The client is reached through
the small `googlekms.Client` interface, which `*kms.KeyManagementClient` satisfies over gRPC or
REST, so tests can use a fake; the wrapper never creates or closes one.

Key files are read with `securefile`, as for AWS KMS: anyone allowed
`cloudkms.cryptoKeyVersions.useToEncrypt` could otherwise choose the DEK new data is encrypted
under. It is its own module so that only applications that use it depend on the Google Cloud
client libraries. See [Wrap keys with Google Cloud KMS](docs/how-to/use-google-kms.md), and
[Run the Google Cloud KMS integration tests](docs/how-to/run-google-kms-integration-tests.md) for
its real-Cloud KMS tests, which skip unless the key is named.

### `keywrapping/hashicorpvault` (separate module)

Go port of `HkdfGuard.KeyWrapping.HashiCorpVault`: a `hkdfguard.KeyWrapper` over one key in a
HashiCorp Vault transit secrets engine, through HashiCorp's own Go client,
`github.com/hashicorp/vault/api`. DEKs are wrapped with `encrypt`, revealed with `decrypt`, and
generated with `datakey/wrapped` - so without a context the plaintext DEK never leaves Vault. A
context is bound in as `associated_data`. Wrapped DEKs are Vault's `vault:v<n>:<base64>`
ciphertext, byte-compatible with the .NET wrapper under the same key and context.

```go
config := api.DefaultConfig()  // VAULT_ADDR, VAULT_CACERT, VAULT_NAMESPACE, ...
config.DisableRedirects = true // a redirect would carry the token and the DEK elsewhere
client, err := api.NewClient(config)
client.SetToken(token)         // or an auth method with a LifetimeWatcher, or Vault Agent
wrapper, err := hashicorpvault.New(client, "myapp-kek", hashicorpvault.Options{Context: "com.example.myapp"})
```

The client is the application's: address, TLS, namespace, token and its renewal, timeout and
retries are all `api.Config`/`*api.Client` settings, replacing the .NET options and
`IVaultTokenSource`. `New` refuses a client that would follow redirects (unless
`Options.AllowRedirects`), or whose address isn't https (http and `unix://` only on the local
host). Request bodies holding a DEK and Vault's answers are read through buffers the wrapper zeroes;
the token, held by `*api.Client` as a Go string, can't be zeroed. Key files are read with
`securefile`. See [Wrap keys with HashiCorp Vault transit](docs/how-to/use-hashicorp-vault-transit.md)
and [Run the HashiCorp Vault transit integration tests](docs/how-to/run-hashicorp-vault-transit-integration-tests.md).

### Secret caches: `cache/awssecretsmanager`, `cache/azurekeyvault`, `cache/googlesecretmanager`, `cache/hashicorpvault` (separate modules)

Go ports of `HkdfGuard.Cache.AwsSecretsManager`, `.AzureKeyVault`, `.GoogleSecretManager` and
`.HashiCorpVault`: each `New` returns a `*cache.RemoteCache` over one secret store, reading one
secret per miss (never listing), encrypting it under the key ring, and serving it from memory after
that. A secret holding a JSON object is cached whole and by key (`"db-login#password"`); Vault's KV
secrets, which are sets of keys, read `Options.DefaultKey` (`"value"`) for a name without one.

| Module | `New` | Names | How the secret is kept out of Go strings |
|---|---|---|---|
| `cache/awssecretsmanager` | `New(client, ring, options)` - the application's `*secretsmanager.Client` | exact | a per-call middleware below the SDK's deserializer captures `SecretString`/`SecretBinary` from the raw body and hands the SDK a redacted copy; response-body logging is forced off for the call |
| `cache/azurekeyvault` | `New(vaultURL, credential, ring, options)` - builds its own `azsecrets.Client` from a copy of `Options.ClientOptions` | ignoring ASCII case | a per-retry pipeline policy reads the unbuffered body and hands the SDK a redacted copy; options that log bodies are refused |
| `cache/googlesecretmanager` | `New(client, projectID, ring, options)` - the application's `*secretmanager.Client` | exact | the payload is `[]byte`, zeroed once encrypted; a per-call gRPC codec zeroes gRPC's pooled receive buffers; CRC32C and the secret's name are checked |
| `cache/hashicorpvault` | `New(client, ring, options)` - the application's `*api.Client` from `github.com/hashicorp/vault/api` | exact | raw reads (`ReadRawWithContext`) parsed straight into zeroed buffers; https only (http and `unix://` on the local host), and the client must set `DisableRedirects` unless `Options.AllowRedirects` - a read has no body for `keywrapping/hashicorpvault`'s per-request redirect refusal to hook |

Each is its own module so that only applications that use it depend on that SDK. What stays beyond
reach is below the SDK - TLS and socket buffers - plus, for Vault, the token the client holds. See
[Cache AWS Secrets Manager secrets](docs/how-to/use-aws-secrets-manager-cache.md),
[Cache Azure Key Vault secrets](docs/how-to/use-azure-key-vault-secret-cache.md),
[Cache Google Cloud Secret Manager secrets](docs/how-to/use-google-secret-manager-cache.md) and
[Cache HashiCorp Vault secrets](docs/how-to/use-hashicorp-vault-secret-cache.md); each covers its
real-store integration tests, which skip unless a secret is named.

### `cache/filepersecret` (separate module): reading secrets from a folder, one file per secret

Go port of the .NET `FilePerSecretCache`: `filepersecret.New` returns a `*filepersecret.Cache`, a
`hkdfguard.ProtectedReadOnlyCache` over a local folder holding one file per secret - the file named
`Db-Password` holds that secret's value, already encrypted and formatted (`enc::v3::...`). Nothing
is read up front: the first lookup of a name reads that one file, checks its value authenticates,
and caches it in memory still encrypted, exactly as the file holds it. Every later lookup is served
from memory:

```go
deployers := securefile.NewKeyFileTrust(securefile.KeyFileTrustOptions{
	WindowsPrincipals: []string{"S-1-5-21-...-1005"}, // the account that deploys secrets
})
secrets, err := filepersecret.New(`C:\HkdfGuardSecrets\myapp`, deployers, ring, dek.NewDefaultFormatProvider(), filepersecret.Options{})
if err != nil { ... }

buffer := make([]byte, 256)
n, err := secrets.Decrypt(ctx, "Db-Password", buffer) // 0 if there's no such file
```

Each file must be encrypted for its own name, with the purpose `hkdfguard.ConfigurationPurpose(name)`.
That is what a `hkdfguard.PipelineDataProtector` writes for the secret identifier `name`, and what
`ring.CreateProtector(hkdfguard.ConfigurationPurpose(name))` writes. A file copied under another
name fails with `hkdfguard.ErrAuthenticationFailed` when it is loaded, and isn't cached, so a
corrected file is read on the next lookup.

Every file is read through `securefile.ReadTrustedFile`, so it is refused - with a
`*securefile.KeyFileError` matching `securefile.ErrUntrusted` and `fs.ErrPermission` - unless it and
every folder above it are owned and modifiable only by the operating system's administrators and the
principals the `securefile.KeyFileTrust` adds. Add the account that deploys secrets, never the one
the application runs as: one that can rewrite its own secrets can be made to roll one back.

A name is a file name: 1-255 ASCII letters, digits, `-`, `_` and `.`, not starting with `.`
(`filepersecret.IsValidName`), so it can't reach outside the folder. Any other name (for example
`ConnectionStrings:Admin`), a missing or empty file and a missing folder all return 0, so the cache
can sit in a `cache.Collection` beside other sources; a missing secret isn't remembered, so a file
added later is found. A file over 64 KiB (`filepersecret.MaxFileLength`) fails with
`securefile.ErrTooLarge`, a value under a key version the ring doesn't hold with
`hkdfguard.ErrKeyNotFound`, one not in the format with `dek.ErrInvalidFormat`; any other read
failure is returned as `securefile` reports it. A cached value isn't refreshed: a changed file is
picked up by a new cache. It is its own module because it reads through `securefile`, which depends
on the root module the `cache` package is in.

### Pipeline writers: `pipeline`, `pipeline/awssecretsmanager`, `pipeline/azurekeyvault`, `pipeline/googlesecretmanager`, `pipeline/hashicorpvault` (separate modules)

Go ports of `HkdfGuard.Pipeline` and its four store writers: the end of a provisioning pipeline,
before a durable KEK exists. A writer pulls a fixed list of secrets from a secret store, encrypts
each at once with a `hkdfguard.PipelineDataProtector` (`aesgcm256.NewPipelineDataProtector`) bound
to its file name, keeps only the ciphertext, and writes one file per secret - the folder layout
`cache/filepersecret` reads at runtime. No key ring is involved: once the files are written, the
protector's key (`KeyBase64`) goes to the native platform's wrap process.

```go
protector, err := aesgcm256.NewPipelineDataProtector(dek.NewDefaultFormatProvider(), 3)
if err != nil { ... }
defer protector.Close()
writer, err := awssecretsmanager.New(secretsmanager.NewFromConfig(cfg), protector,
	[]string{"prod/app#username", "prod/app#password", "prod/api-key"})
if err != nil { ... }
defer writer.Close()
if err := writer.PullSecrets(ctx); err != nil { ... }
if err := writer.WriteProtectedSecretFiles(`C:\HkdfGuardSecrets\myapp`); err != nil { ... }
// Then hand protector.KeyBase64() to the wrap tool, and register the key at version 3.
```

| Module | Purpose |
|---|---|
| `pipeline` | `pipeline.New` returns a `*pipeline.Writer` (a `hkdfguard.SecretPipelineWriter`) over a `pipeline.SecretStore`: it takes secret names - `name` or `name#key` - reads each secret once however many of its keys are listed, encrypts every value bound to its file name (`/` and `#` become `__`, and the name must be one `filepersecret.IsValidName` accepts; two differing only in case are refused), reports every missing value in one `*pipeline.MissingSecretsError` (`pipeline.ErrSecretNotFound`) after keeping the rest, keeps nothing when a read fails otherwise, and writes UTF-8 files without a BOM, replacing only its own. A key's value is a string's text, or a number's, `true`'s or `false`'s JSON text; a JSON object holding a key twice, or a value that isn't UTF-8 text, is refused (`pipeline.ErrInvalidSecretData`). A store supplies only `IsValidName` and `ReadSecret`; `pipeline.ReadBody` reads a response body into a buffer zeroed by the caller. Depends on the root module and `cache/filepersecret` (for its file-name rule). |
| `pipeline/hashicorpvault` | `New(client, protector, names, options)` over one KV engine, version 1 or 2, through the application's `*api.Client`: `path` or `path#key`, a name without a key reading `Options.DefaultKey` (`"value"`); raw reads parsed straight into zeroed buffers; https only (http and `unix://` on the local host), and the client must set `DisableRedirects` unless `Options.AllowRedirects`. Failures are `*hashicorpvault.Error` (`ErrVault`). |
| `pipeline/awssecretsmanager` | `New(client, protector, names)` through the application's `*secretsmanager.Client`: `name` for the whole `SecretString`, `name#key` for a member of a key/value secret; a per-call middleware below the deserializer takes the body and hands the SDK `{}`, with response-body logging forced off; a `SecretBinary` is refused. |
| `pipeline/azurekeyvault` | `New(vaultURL, credential, protector, names, options)` - its own `azsecrets.Client` from a copy of `Options.ClientOptions`: `name` or `name#key`; a per-retry policy reads the unbuffered body and hands the SDK `{}`; options that log bodies are refused. |
| `pipeline/googlesecretmanager` | `New(client, projectID, protector, names)` through the application's `*secretmanager.Client`: each secret's latest version, its CRC32C and name checked (`ErrInvalidResponse`), the payload encrypted straight from the decoded `[]byte` and zeroed, as are gRPC's receive buffers. |

The store writers never depend on the runtime caches (`cache/...`), and each is its own module so
that only pipelines that use it depend on that SDK. Missing secrets - not found, an absent key, an
empty or non-scalar value - are reported, never written; the protector is the caller's and is never
closed by a writer.

### `integration/configurationresolver` (separate module): templates resolved from the caches

Go port of the .NET `HkdfGuard.Integration.ConfigurationResolver`, together with the parts of
[ConfigurationResolver](https://github.com/runsecure/configurationresolver-dotnet) it uses - the
token, the reader, the resolver and the value-provider contract - in one package, depending only
on the root module. It fills the `${name}` items in a template, such as a connection string, with
secrets from any `ProtectedReadOnlyCache`:

```go
token := configurationresolver.NewDefaultToken() // "${", "}", and "$" escapes: "$${x}" is "${x}"
reader, _ := configurationresolver.NewConfigurationItemReader(token)
reader.ReadKeysString(template) // only the keys of this trusted template may be resolved

resolver, err := configurationresolver.NewConfigurationResolverBuilder().
	WithToken(token).
	WithReader(reader).
	AddProtectedCache(secrets). // a cache.Cache, a cache.Collection, a remote cache, ...
	Build()
n, err := resolver.Resolve(ctx, []byte(template), destination) // destination wiped on failure
```

Each value is decrypted straight into the destination, or through a scratch buffer that is wiped,
and never becomes a Go string. `configurationresolver.NewResolvingProtectedCacheCollection` is a
`ProtectedReadOnlyCache` over several sources that resolves a value holding items on its first
lookup, from those same sources, and keeps the result encrypted under the key ring until
`Invalidate` or `Clear`. See
[Resolve configuration templates from protected caches](docs/how-to/resolve-configuration-templates.md).

### `options/certificate` (separate module): a certificate and its key from configuration

Go port of `HkdfGuard.Options.Certificate`: `certificate.Options` is a plain-data description of
where one certificate and its private key are opened from - exactly one of a Windows certificate
store or a macOS keychain (a `StoreLocation`, a `StoreName` and the certificate's subject
distinguished name), an OpenSSL 3 provider on Linux (kept for configuration parity; see below), or
a PKCS#12 or PEM file. Its JSON names are the .NET configuration keys, so the same configuration
binds. A file's key must be password-protected, and the password is never in the options:
`PasswordSecretName` names the secret it is read from, unless `AllowUnprotectedPrivateKey` is set
for development. `certificate.Validator` refuses a native source on another operating system, a
subject that isn't a distinguished name, a relative path and an unprotected key file, listing every
failure in one `*certificate.ValidationError` (`certificate.ErrInvalidOptions`).

```go
loader := certificate.NewLoader(secrets, certificate.LoaderOptions{}) // secrets: any hkdfguard.ProtectedReadOnlyCache
cert, err := loader.LoadContext(ctx, &certificate.Options{
	Windows: &certificate.StoreOptions{StoreLocation: certificate.LocalMachine, Subject: "CN=api.example.com"},
}, "tls")
if err != nil { ... }
defer cert.Close()
tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert.TLSCertificate()}}
```

`Loader.Load`/`LoadContext` validate the options and open a `*certificate.Certificate`: `Leaf()`,
the DER chain its source gave, and a `crypto.Signer` (a `crypto.Decrypter` too, for RSA) that
fails with `certificate.ErrClosed` once the certificate is closed; `TLSCertificate()` is all three
as `crypto/tls` takes them. From a store, the certificate with that subject - compared whole and
decoded, ignoring case, never as a substring - that is valid now (with its private key, when
required) and expires last; every other is released. A certificate that isn't valid now, or lacks a
required key, is refused (`ErrNotValidNow`, `ErrNoPrivateKey`, `ErrNotFound` for a store). The
clock is `LoaderOptions.Now`.

- **Windows store:** `CertOpenStore` (system store, read-only, existing only) and
  `CryptAcquireCertificatePrivateKey` with CNG alone, through `golang.org/x/sys/windows`, with no
  cgo. The key is never exported: every signature is an `NCryptSignHash` call (RSA PKCS #1 v1.5 and
  PSS, ECDSA, its IEEE P1363 signature converted to ASN.1) and every decryption an `NCryptDecrypt`
  call (PKCS #1 v1.5, OAEP), through a lazily loaded `ncrypt.dll`; `Close` frees the key and
  certificate handles. A key only a legacy CryptoAPI provider holds is refused.
- **macOS keychain:** the Security framework through cgo, as `keywrapping/nativev1` reaches native
  code on darwin: `SecItemCopyMatching` for `kSecClassIdentity` (and certificates without keys),
  restricted to one keychain - CurrentUser the login keychain, LocalMachine the System keychain -
  and `SecKeyCreateSignature` behind the `crypto.Signer` (RSA PKCS #1 v1.5 and PSS with a salt the
  hash's length, ECDSA). Only `StoreName` My is a keychain. Without cgo the macOS store is refused
  (`ErrUnsupported`).
- **Linux OpenSSL provider:** Go has no OpenSSL binding, so a provider key can't be opened: the
  validator refuses `Linux` with a required key, saying so, and with `RequirePrivateKey` false only
  the certificate file is read. Use a `File` source, or a store on Windows or macOS, for a key.
- **Files:** a PKCS#12 file or a PEM certificate with an encrypted PKCS#8 key. The password is
  decrypted from the `hkdfguard.ProtectedReadOnlyCache` into a `[]byte` wiped as soon as the key is
  read. The PKCS#12 and PBES2 decryption is the module's own, on the standard library - the
  libraries take the password as a string, which can't be wiped: PBES2 (PBKDF2 with HMAC-SHA-1/2,
  AES-CBC or 3DES-CBC), PKCS#12's own 3DES, HMAC-SHA-1/2 integrity MACs, and BER as well as DER -
  what OpenSSL 3, .NET and Windows write. Legacy RC2/RC4 files (`openssl -legacy`), public-key
  PKCS#12 contents and the PBMAC1 MAC are refused with `ErrUnsupported`. A file key is wiped on
  `Close` as far as Go lets it be reached: `crypto/rsa` and `crypto/ecdsa` keep precomputed copies
  of their own until the garbage collector frees them.

The real-store tests run on Windows against CurrentUser\My - read-only always, and, with
`HKDFGUARD_TEST_WINDOWS_CERT_STORE=1`, round trips through throwaway certificates
`New-SelfSignedCertificate` makes (with non-exportable CNG keys) and removes. On macOS,
`HKDFGUARD_TEST_MACOS_KEYCHAIN=1` imports and deletes throwaway identities in the login keychain.
Depends on the root module and `golang.org/x/sys`.

### `systemdcredentials` (separate module): Linux credentials through systemd

Go port of `HkdfGuard.SystemdCredentials`. Linux only: `systemdcredentials.New` refuses anywhere
else (`ErrUnsupportedPlatform`). `Credentials` runs `systemd-creds` by absolute path, with its
arguments as an argument list, never through a shell: `Encrypt` writes the plaintext to its stdin
and has it write the encrypted credential file, bound to its name and to the host key, the TPM or
both (`systemdcredentials.Key`); `Decrypt` reads the value from its stdout into a `*Credential` -
a buffer that grows as it is read, wiping each smaller one it drops, up to systemd's 1 MiB limit,
and wiped on `Close`. A run that outlasts `Options.Timeout` (30 seconds by default), or whose
context is cancelled, is killed with its whole process group. `ReadLoadedCredential` reads a
credential systemd decrypted for the service (`LoadCredentialEncrypted=`) from its in-memory
credentials directory under /run. `systemdcredentials.Source` is a
`hkdfguard.ProtectedReadOnlyCache` over both - loaded credentials first, then encrypted files - for
`options/certificate`'s password, say:

```go
credentials, err := systemdcredentials.New(systemdcredentials.Options{})
passwords, err := systemdcredentials.NewSource(credentials,
	map[string]string{"tls-password": "/etc/credstore.encrypted/tls-password.cred"}, "")
loader := certificate.NewLoader(passwords, certificate.LoaderOptions{})
```

A name is 1-255 ASCII letters, digits, `.`, `_` and `-`, not `.` or `..` and not starting with `-`
(`systemdcredentials.IsValidName`). Decrypting a system credential directly needs root (the host
key) or TPM access; an unprivileged service uses `LoadCredentialEncrypted=` or `--user` credentials
(`Options.UserScope`, systemd 256+). The unit tests run a fake `systemd-creds`, and the process
runner against the test binary itself, on any OS; the real `systemd-creds` round trip runs on Linux
when `HKDFGUARD_TEST_SYSTEMD_CREDS` is 1. Depends on the root module only.

### `securefile` (separate module)

Go port of `HkdfGuard.SecureFile`: `securefile.ReadTrustedKeyFile` reads a wrapped-key file only
from where no untrusted account could have written or replaced it - the native library's
`hkdfguard_open_file` checks, made in Go - for a key wrapper with no native library to read
through, such as `keywrapping/awskms`, `keywrapping/azurekeyvault` and `keywrapping/googlekms`.
`securefile.ReadTrustedFile` (and `securefile.ParseTrustedFile`, which hands the contents to a
parser and zeroes them once it returns, for contents that are themselves secret) applies the same
location checks to any other file - secret files, certificates - with only a caller-chosen size
limit, read at most one byte past whatever the file reports: the port of the .NET `TrustedFile`.

- **Windows:** the file must be on a local fixed drive, reached through real folders (no symbolic
  link, junction, mount point or substituted drive; 8.3 short names are expanded first), and it
  and every folder above it must be owned by, and modifiable only by, SYSTEM, Administrators,
  TrustedInstaller or a trusted principal. Owner and DACL are read with `golang.org/x/sys/windows`
  (no cgo); the file's own through the handle it is read from, opened with read sharing only.
- **Linux and Apple silicon macOS:** it and every directory above it must be owned by root or a
  trusted user and writable by nobody else (by its group only if that group is trusted); only
  symbolic links a trusted user owns are followed, and the resolved path is opened with
  `O_NOFOLLOW` and must still be a regular file.
- **Everywhere, for a key file:** 1 to `hkdfguard.MaxWrappedKeyBytes` bytes, and not what looks
  like an unwrapped key (32 raw bytes, optionally followed by one line ending (LF or CRLF), or its
  hex or base64). A trusted file is held only to its caller's limit, and may be empty.

`securefile.KeyFileTrust` names who besides administrators is trusted (Windows SIDs, Unix uids and
gids); its zero value, `securefile.AdministratorsOnly()`, trusts no one else. A refusal is a
`*securefile.KeyFileError`, matchable with `errors.Is` against `fs.ErrNotExist`, `fs.ErrPermission`
(`securefile.ErrUntrusted` for a location that isn't trusted), `hkdfguard.ErrInvalidKeyFile` (a key
file's contents), `securefile.ErrTooLarge` (a trusted file over its limit) or `securefile.ErrBusy`. It is its own module, like `keywrapping/nativev1`, because it depends on
`golang.org/x/sys` and holds platform-specific code; it does not load the native library.

### `integration` (test-only module)

The end-to-end tests that cross module boundaries - a pipeline encrypting configuration, the
native KEK wrapping its key, an application reading it back - the port of the .NET
`NativeEndToEndTests`, and the same paths through `keywrapping/awskms`, `keywrapping/azurekeyvault`
and `keywrapping/googlekms` against in-process stand-ins for AWS KMS, Key Vault and Cloud KMS. It is
a module of its own so the published modules never depend on each other; it is never tagged.
`integration/configurationresolver`, inside its folder, is a separate, published module.

## Testing

Every package has tests beside it. `scripts/check.sh` runs what CI runs - formatting, tidy module
files, vet, build, every module's tests under the race detector, govulncheck, and a type-check of
`keywrapping/nativev1`, `securefile`, `options/certificate` and `systemdcredentials` for every
platform - from any host:

```sh
scripts/check.sh                       # every module
scripts/check.sh keywrapping/nativev1  # one module
```

### Platform native integration suites

Each platform has its own suite against the real native library, alongside the cross-platform
round trips in `keywrapping/nativev1/native_test.go` and the end-to-end tests in `integration`. All
of them skip (with the reason) rather than pass where what they need is missing:

| Platform | Files | Gated on |
|---|---|---|
| Linux | `kms_linux_test.go`, `kms_linux_cgo_test.go` (`TestLinuxSystem_*`, `TestLinuxNative_*`) | `linux`, and `cgo` for the dynamic-linker checks and native calls. The loader's system checks run on any Linux host (libc stands in for the library); installed-library checks skip without the `libhkdfguard1` package (and one checks that, without it, loading reports it not installed); the native contract needs `HKDFGUARD_TEST_SERVICE` (and `HKDFGUARD_TEST_SERVICE_OTHER`) |
| macOS | `kms_darwin_test.go` (`TestDarwin_*`) | `darwin && cgo`; skips without the installed library or the provisioning tool, and the round trips without the provisioned test service |
| Windows | `kms_windows_test.go` (`TestWindows_*`), `keyfile_windows_test.go` (`TestWindowsKeyFile_*`), `harden_windows_test.go` (`TestWindowsNative_*`) | `windows`; the loader's refusals of planted, unsigned, junctioned and non-PE files always run; installed-library checks skip without `%ProgramFiles%\HkdfGuard\v1\HkdfGuard.dll`; key-file refusals need only the library; real key files and round trips need the provisioned test KEK |

The process-hardening tests (Linux and Windows) also need `HKDFGUARD_TEST_PROCESS_HARDENING=1` (below).

The native key wrapper's tests make real calls against a provisioned service. They are reported
as skipped, never passed, unless the test service exists: on Windows and macOS the tests find it
by themselves (through the library's `hkdfguard_kek_exists` export, and the provisioning tool's
`status` command, respectively); on Linux, and for any other service, set `HKDFGUARD_TEST_SERVICE`.
`HKDFGUARD_TEST_SERVICE_OTHER` names a second provisioned service for the cross-service isolation
tests. On Windows the key-file tests (`keyfile_windows_test.go`) also run against the installed
library: its refusals need no KEK, and reading back a real key file uses the test service. To provision a test host, run from `keywrapping/nativev1`:

- Linux: `sudo scripts/provision-linux-test-key.sh` (the TPM-backed test KEK and policy; `--remove` undoes it)
- macOS: `scripts/provision-macos-test-key.sh` as the account that runs the tests (`--remove` retires the KEK)
- Windows: `./scripts/provision-windows-test-key.ps1` from an elevated PowerShell (`-Remove` retires
  the KEK; a provisioning run also retires the legacy `com.hkdfguard.native.windows.test`, after
  asking - `-KeepLegacyKey` keeps it)

Each checks the installed `hkdfguard` tool against the same pins the loader applies before
running it, and prints the `go test` command to run next. They provision the same KEKs as the .NET
port's copies, so one host serves both ports' tests.

```sh
cd keywrapping/nativev1 && CGO_ENABLED=1 go test ./...   # the wrapper, loader and native contract
cd integration && CGO_ENABLED=1 go test ./...            # end to end across the modules
```

With a service, the Linux run also checks the exact Linux status codes, the native library's own
service-name and length checks, that a failed unwrap zeroes the caller's buffer, that tampering
anywhere in a payload is refused, and that a key file written by `hkdfguard wrap`
unwraps through the wrapper.

`HKDFGUARD_TEST_PROCESS_HARDENING=1` adds the tests that harden the test process itself, on Linux
(the dumpable flag and core dump limit) and Windows (the process is no longer open to its own
account for memory reads; in strict mode neither are threads started afterwards). Run each in a
test binary of its own, since what one does to the process outlives it:

```sh
HKDFGUARD_TEST_PROCESS_HARDENING=1 go test -run 'HardenProcess_ClosesTheProcessToItsOwnAccount$|DisablesCoreDumps' -v
HKDFGUARD_TEST_PROCESS_HARDENING=1 go test -run 'HardenProcess_WithRequireProtectedSignature' -v   # Windows
```

**macOS:** in the native library's legacy keychain mode the KEK's access list names the binary
that created it, so the first native call from each freshly built test binary is answered with a
keychain dialog in a logged-in session - click "Always Allow" - and with status -18 where there is
no UI. The tests fail with a message saying so after 60 seconds rather than hang; this is a
property of the native library, shared with the .NET port.

## Continuous integration and releases

The **CI** workflow (`.github/workflows/ci.yml`) runs on every push to `main` or `develop`, every
pull request, and on demand. It calls the reusable `build.yml`, which runs `scripts/check.sh` on
Ubuntu, macOS (Apple silicon) and Windows. GitHub's runners have no HkdfGuard native library, so
the native round trips are reported as skipped there; a self-hosted runner with a provisioned test
service runs them too. The real-KMS tests in `keywrapping/awskms`, the real-Key Vault tests in
`keywrapping/azurekeyvault` and the real-Cloud KMS tests in `keywrapping/googlekms` are skipped
there as well: CI names no test keys and holds no AWS, Azure or Google credentials. So are
`options/certificate`'s real-store and real-keychain round trips and `systemdcredentials`' real
`systemd-creds` round trip, which would change the runner's certificate store, keychain or
credentials: each runs only when its `HKDFGUARD_TEST_*` variable asks. No secrets, no write
permissions.

A Go module is released by its tag alone: the Go module proxy serves the tagged source, so there
is nothing to pack, sign or push to a feed. The twenty-one published modules share one version and are
tagged together, at the same commit. Before tagging, set every nested module's requirement on the
root module and on `securefile` to that version (each `go.mod` and `integration/go.mod`), then:

```sh
version=v0.9.1
tags=("${version}")
for module in securefile cryptoprovider/aesgcm256 keywrapping/nativev1 keywrapping/awskms \
    keywrapping/azurekeyvault keywrapping/googlekms keywrapping/hashicorpvault \
    cache/awssecretsmanager cache/azurekeyvault cache/googlesecretmanager cache/hashicorpvault \
    cache/filepersecret pipeline pipeline/awssecretsmanager pipeline/azurekeyvault \
    pipeline/googlesecretmanager pipeline/hashicorpvault integration/configurationresolver \
    options/certificate systemdcredentials; do
  tags+=("${module}/${version}")
done
for tag in "${tags[@]}"; do git tag "${tag}"; done
git push origin "${tags[@]}"
```

The nested modules keep `replace` directives pointing the root module and `securefile` at their
directories in this repository, so they build against this commit's code in development and CI. Go
ignores a `replace` in a dependency, so a consumer gets the tagged versions instead - the same
commit, because every module is tagged there.

The **Release** workflow (`release.yml`) runs for each tag:

1. **version**: turns the tag into the module it releases (`scripts/release-tag.sh`). A nested
   module is refused while its `go.mod` requires a placeholder version of the root module or
   `securefile`, or has a `replace` other than one of this repository's modules by its own
   directory.
2. **build**: the same `build.yml` CI runs, on every OS.
3. **publish**: archives the module's source at the tagged commit, attests its build provenance
   (`gh attestation verify <file> --repo runsecure/hkdfguard-go`), and creates the GitHub Release.
   Versions `0.x`, and any with a pre-release suffix (`v1.2.0-rc.1`), are published as GitHub
   pre-releases.

Unlike the .NET port there is no Azure sign-in and no `release` environment: Go modules are
source, with nothing to Authenticode-sign. Third-party actions are pinned to full commit SHAs.
