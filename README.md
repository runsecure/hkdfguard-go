# hkdfguard-go
HkdfGuard KeyWrapping and Secrets Protection Library for GoLang

The Go port of the HkdfGuard .NET libraries: application code works against a `KeyRing` to
encrypt and decrypt byte payloads under AES-256-GCM data encryption keys (DEKs) that only ever
exist on disk wrapped under a platform-held key-encryption key (KEK): a TPM2 key on Linux, a
Secure Enclave key on macOS, a Platform Crypto Provider key on Windows - or a symmetric AWS KMS
key. Values, key files, purposes and names are byte-identical between the ports, so one deployment
serves both.

**Documentation:** [docs/](docs/README.md) - a [getting-started tutorial](docs/getting-started.md),
the [`hkdfguard` tool reference](docs/reference/cli.md), and how to
[wrap keys with AWS KMS](docs/how-to/use-aws-kms.md).

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
deploying a new key file at a higher version regularly.

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
size and format; that it doesn't hold what looks like an *unwrapped* key (32 raw bytes, or its hex
or base64 - treat that as a key exposure); and that no account other than an administrator or the
reader could have written or replaced it, nor redirected its path through a link, junction, 8.3
short name or network path. A refusal is a `*nativev1.KeyFileError` naming the file, the status
and its meaning, matchable with `errors.Is` against `fs.ErrNotExist`, `fs.ErrPermission` or
`hkdfguard.ErrInvalidKeyFile`.

Every platform's native library returns the same status codes (the header's `HKDFGUARD_ERR_*`
table: -17 no KEK, -18 access denied, -10..-12 a malformed, altered or unsupported payload, -16 a
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

### `securefile` (separate module)

Go port of `HkdfGuard.SecureFile`: `securefile.ReadTrustedKeyFile` reads a wrapped-key file only
from where no untrusted account could have written or replaced it - the native library's
`hkdfguard_open_file` checks, made in Go - for a key wrapper with no native library to read
through, such as `keywrapping/awskms`.

- **Windows:** the file must be on a local fixed drive, reached through real folders (no symbolic
  link, junction, mount point or substituted drive; 8.3 short names are expanded first), and it
  and every folder above it must be owned by, and modifiable only by, SYSTEM, Administrators,
  TrustedInstaller or a trusted principal. Owner and DACL are read with `golang.org/x/sys/windows`
  (no cgo); the file's own through the handle it is read from, opened with read sharing only.
- **Linux and Apple silicon macOS:** it and every directory above it must be owned by root or a
  trusted user and writable by nobody else (by its group only if that group is trusted); only
  symbolic links a trusted user owns are followed, and the resolved path is opened with
  `O_NOFOLLOW` and must still be a regular file.
- **Everywhere:** 1 to `hkdfguard.MaxWrappedKeyBytes` bytes, and not what looks like an unwrapped
  key (32 raw bytes, or its hex or base64).

`securefile.KeyFileTrust` names who besides administrators is trusted (Windows SIDs, Unix uids and
gids); its zero value, `securefile.AdministratorsOnly()`, trusts no one else. A refusal is a
`*securefile.KeyFileError`, matchable with `errors.Is` against `fs.ErrNotExist`, `fs.ErrPermission`
(`securefile.ErrUntrusted` for a location that isn't trusted), `hkdfguard.ErrInvalidKeyFile` or
`securefile.ErrBusy`. It is its own module, like `keywrapping/nativev1`, because it depends on
`golang.org/x/sys` and holds platform-specific code; it does not load the native library.

### `integration` (test-only module)

The end-to-end tests that cross module boundaries - a pipeline encrypting configuration, the
native KEK wrapping its key, an application reading it back - the port of the .NET
`NativeEndToEndTests`, and the same paths through `keywrapping/awskms` against an in-process
stand-in for KMS. It is a module of its own so the published modules never depend on each other;
it is never tagged.

## Testing

Every package has tests beside it. `scripts/check.sh` runs what CI runs - formatting, tidy module
files, vet, build, every module's tests under the race detector, govulncheck, and a type-check of
`keywrapping/nativev1` and `securefile` for every platform - from any host:

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
service runs them too. The real-KMS tests in `keywrapping/awskms` are skipped there as well: CI
sets no `HKDFGUARD_TEST_AWS_KMS_KEY_ID` and holds no AWS credentials. No secrets, no write
permissions.

A Go module is released by its tag alone: the Go module proxy serves the tagged source, so there
is nothing to pack, sign or push to a feed. The five published modules are tagged separately:

```sh
git tag v0.1.0 && git push origin v0.1.0                                             # the root module
git tag securefile/v0.1.0 && git push origin securefile/v0.1.0
git tag cryptoprovider/aesgcm256/v0.1.0 && git push origin cryptoprovider/aesgcm256/v0.1.0
git tag keywrapping/nativev1/v0.1.0 && git push origin keywrapping/nativev1/v0.1.0
git tag keywrapping/awskms/v0.1.0 && git push origin keywrapping/awskms/v0.1.0       # after securefile
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
`cryptoprovider/aesgcm256/go.mod`, `securefile/go.mod`, `keywrapping/awskms/go.mod` and
`integration/go.mod` point at it with `replace` directives; `keywrapping/awskms` and `integration`
point at `securefile` the same way until it is tagged.
