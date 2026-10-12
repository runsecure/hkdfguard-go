# hkdfguard-go
HkdfGuard KeyWrapping and Secrets Protection Library for GoLang

## Packages

### `hkdfguard` (module root)

Go port of `HkdfGuard.Abstractions`: the interfaces every implementation satisfies
(`KeyWrapper`, `CryptoProviderFactory`/`CryptoProvider`, `DataEncryptionKey`, `KeyRing`,
`EncryptedFormatProvider`, `DataProtector`, `PipelineDataProtector`, `ProtectedCache`), the shared
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
- `cache.NewReadOnly(ring, source)` - filled on demand from a `cache.Source`. A Vault or Azure Key
  Vault backend implements only `Source`; encryption, name binding and telemetry stay here.
- `cache.NewCollection(a, b, ...)` - several caches behind one lookup, first match wins.

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

A `Reader` is a `ProtectedReadOnlyCache`, so it can join a `cache.Collection`.

### `cryptoprovider/aesgcm256` (separate module)

Go port of `HkdfGuard.CryptoProvider.AesGcm256`: the AES-256-GCM `CryptoProviderFactory` (keys
re-revealed in the background, fail-closed refresh policy, per-key encryption budget) and the
`PipelineDataProtector`. Ciphertext is byte-compatible with the .NET port. Failures callers act on
use the cipher-neutral errors in `hkdfguard` (`ErrAuthenticationFailed`, `ErrKeyAccessSuspended`,
`ErrEncryptionLimitReached`, `ErrClosed`), so another cipher module can replace it unchanged.

### `keywrapping/nativev1` (separate module)

Go port of `HkdfGuard.KeyWrapping.V1`: a `hkdfguard.KeyWrapper` over the OS's native HkdfGuard KMS
library (TPM2 on Linux, Secure Enclave on macOS, Platform Crypto Provider on Windows). The library
is loaded only from its fixed install location, after verifying path ownership and permissions,
the code signature (Authenticode / Developer ID) or pinned SHA-256 (Linux), and the dynamic
linker's environment.

```go
wrapper, err := nativev1.New("com.example.orders") // service must be provisioned first
```

It is its own module (`github.com/runsecure/hkdfguard-go/keywrapping/nativev1`) because macOS and
Linux builds need cgo (`CGO_ENABLED=1` and a C toolchain); Windows needs neither. Run its tests from
its own directory; set `HKDFGUARD_TEST_SERVICE` to a provisioned service to include real
wrap/unwrap round trips. To provision a test host, run from `keywrapping/nativev1`:

- Linux: `sudo scripts/provision-linux-test-key.sh` (TPM-backed test KEKs and policy; `--remove` undoes it)
- Windows: `./scripts/provision-windows-test-key.ps1` from an elevated PowerShell

Each checks the installed `hkdfguard-v1-initialize` before running it, and prints the `go test`
command to run next. They provision the same KEKs as the .NET port's copies, so one host serves both.

Until the root module has a tagged release, `keywrapping/nativev1/go.mod` and
`cryptoprovider/aesgcm256/go.mod` point at it with
`replace github.com/runsecure/hkdfguard-go => ../..`; remove that line and require a real version
before tagging either module.
