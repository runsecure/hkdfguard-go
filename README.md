# hkdfguard-go
HkdfGuard KeyWrapping and Secrets Protection Library for GoLang

The Go port of the HkdfGuard .NET libraries: application code works against a `KeyRing` to
encrypt and decrypt byte payloads under AES-256-GCM data encryption keys (DEKs) that only ever
exist on disk wrapped under a platform-held key-encryption key (KEK): a TPM2 key on Linux, a
Secure Enclave key on macOS, a Platform Crypto Provider key on Windows. Values, key files, purposes
and names are byte-identical between the ports, so one deployment serves both.

**Documentation:** [docs/](docs/README.md) - a [getting-started tutorial](docs/getting-started.md)
and the [`hkdfguard-v1-initialize` reference](docs/reference/cli.md).

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
Linux builds need cgo (`CGO_ENABLED=1` and a C toolchain); Windows needs neither. See
[Testing](#testing) for its native integration tests.

### `integration` (test-only module)

The end-to-end tests that cross module boundaries - a pipeline encrypting configuration, the
native KEK wrapping its key, an application reading it back - the port of the .NET
`NativeEndToEndTests`. It is a module of its own so the published modules never depend on each
other; it is never tagged.

## Testing

Every package has tests beside it. `scripts/check.sh` runs what CI runs - formatting, tidy module
files, vet, build, every module's tests under the race detector, govulncheck, and a type-check of
`keywrapping/nativev1` for every platform - from any host:

```sh
scripts/check.sh                       # every module
scripts/check.sh keywrapping/nativev1  # one module
```

The native key wrapper's tests make real calls against a provisioned service. They are reported
as skipped, never passed, unless the test service exists: on Windows and macOS the tests find it
by themselves (through the library's `hkdfguard_kek_exists` export, and the provisioning tool's
`status` command, respectively); on Linux, and for any other service, set `HKDFGUARD_TEST_SERVICE`.
`HKDFGUARD_TEST_SERVICE_OTHER` names a second provisioned service for the cross-service isolation
tests. To provision a test host, run from `keywrapping/nativev1`:

- Linux: `sudo scripts/provision-linux-test-key.sh` (TPM-backed test KEKs and policy; `--remove` undoes it)
- macOS: `scripts/provision-macos-test-key.sh` as the account that runs the tests (`--remove` retires the KEK)
- Windows: `./scripts/provision-windows-test-key.ps1` from an elevated PowerShell

Each checks the installed `hkdfguard-v1-initialize` against the same pins the loader applies before
running it, and prints the `go test` command to run next. They provision the same KEKs as the .NET
port's copies, so one host serves both ports' tests.

```sh
cd keywrapping/nativev1 && CGO_ENABLED=1 go test ./...   # the wrapper, loader and native contract
cd integration && CGO_ENABLED=1 go test ./...            # end to end across the modules
```

With a service, the Linux run also checks the exact Linux status codes, the native library's own
service-name and length checks, that a failed unwrap zeroes the caller's buffer, that tampering
anywhere in a payload is refused, and that a key file written by `hkdfguard-v1-initialize wrap`
unwraps through the wrapper; `HKDFGUARD_TEST_PROCESS_HARDENING=1` adds the test that hardens the
test process itself (`HardenProcess`).

**macOS:** in the native library's legacy keychain mode the KEK's access list names the binary
that created it, so the first native call from each freshly built test binary is answered with a
keychain dialog in a logged-in session - click "Always Allow" - and with status -17 where there is
no UI. The tests fail with a message saying so after 60 seconds rather than hang; this is a
property of the native library, shared with the .NET port.

## Continuous integration and releases

The **CI** workflow (`.github/workflows/ci.yml`) runs on every push to `main` or `develop`, every
pull request, and on demand. It calls the reusable `build.yml`, which runs `scripts/check.sh` on
Ubuntu, macOS (Apple silicon) and Windows. GitHub's runners have no HkdfGuard native library, so
the native round trips are reported as skipped there; a self-hosted runner with a provisioned test
service runs them too. No secrets, no write permissions.

A Go module is released by its tag alone: the Go module proxy serves the tagged source, so there
is nothing to pack, sign or push to a feed. The three published modules are tagged separately:

```sh
git tag v0.1.0 && git push origin v0.1.0                                             # the root module
git tag cryptoprovider/aesgcm256/v0.1.0 && git push origin cryptoprovider/aesgcm256/v0.1.0
git tag keywrapping/nativev1/v0.1.0 && git push origin keywrapping/nativev1/v0.1.0
```

The **Release** workflow (`release.yml`) then:

1. **version**: turns the tag into the module it releases (`scripts/release-tag.sh`). A nested
   module is refused while its `go.mod` still points at the root module with a `replace`
   directive, or requires its placeholder version: remove the `replace` and require a tagged root
   version first, then tag.
2. **build**: the same `build.yml` CI runs, on every OS.
3. **publish**: archives the module's source at the tagged commit, attests its build provenance
   (`gh attestation verify <file> --repo runsecure/hkdfguard-go`), and creates the GitHub Release.
   Versions `0.x`, and any with a pre-release suffix (`v1.2.0-rc.1`), are published as GitHub
   pre-releases.

Unlike the .NET port there is no Azure sign-in and no `release` environment: Go modules are
source, with nothing to Authenticode-sign. Third-party actions are pinned to full commit SHAs.

Until the root module has a tagged release, `keywrapping/nativev1/go.mod`,
`cryptoprovider/aesgcm256/go.mod` and `integration/go.mod` point at it with `replace` directives.
