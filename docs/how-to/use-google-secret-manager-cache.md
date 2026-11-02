# Cache Google Cloud Secret Manager secrets

This page reads secrets from one Google Cloud project's Secret Manager into HkdfGuard's protected
cache with `googlesecretmanager.New`, so your application holds each secret encrypted under its key
ring and never as a Go string.

Use it when your application's secrets live in Secret Manager and you want them to stay encrypted
in memory between uses, rather than sit in plain strings for the life of the process.

## How it works

The cache is a `hkdfguard.ProtectedReadOnlyCache` (a `*cache.RemoteCache`). Nothing is fetched up
front:

- The first `Decrypt` or `MaxDecryptedLength` of a name calls `AccessSecretVersion` for that one
  secret's `latest` version, checks the response, encrypts the payload under the ring's current
  key, bound to its name, and caches only the ciphertext.
- Every later lookup is served from the cache. Secret Manager isn't called again for that name.
- Concurrent lookups of the same uncached secret share one call.

It never lists secrets or versions, so the application needs only `secretmanager.versions.access`
(the **Secret Manager Secret Accessor** role) on the secrets it reads, never
`secretmanager.secrets.list`.

| | Behavior |
|---|---|
| Names | Matched exactly, as Secret Manager matches secret IDs: `Db` and `db` are two secrets and two entries |
| A name Secret Manager can't hold | Anything but 1-255 ASCII letters, digits, hyphens and underscores (such as `ConnectionStrings:Admin`, `prod/db` or a resource name) is reported missing without a call |
| The payload | Cached as its bytes; a JSON object's members also as `name#key` (see [Secrets holding several keys](#secrets-holding-several-keys)) |
| A secret that doesn't exist, has no versions, or is empty | Reported missing (`Decrypt` returns 0, `MaxDecryptedLength` returns `ok == false`) and looked up again next time |
| A response naming another secret, or whose payload doesn't match its CRC32C | Refused with `googlesecretmanager.ErrInvalidResponse`, and nothing is cached |
| Any other failure | Returned with the client's error wrapped, and nothing is cached |
| A new secret version | Not picked up: a cached value is kept for the life of the cache. Create a new cache to read it |

## 1. Grant the application read access

Enable the API, then grant the application's service account the Secret Manager Secret Accessor
role on each secret it reads:

```bash
gcloud services enable secretmanager.googleapis.com --project my-project

gcloud secrets add-iam-policy-binding Db-Password --project my-project \
  --member "serviceAccount:myapp@my-project.iam.gserviceaccount.com" \
  --role roles/secretmanager.secretAccessor
```

> **Security:** grant the role on the secrets the application reads, not the project. The cache
> never lists, so it doesn't need `secretmanager.secrets.list` or the Viewer role either.

Without permission on a secret, Secret Manager answers `PERMISSION_DENIED` even when the secret
doesn't exist, so a missing secret the identity may not access is an error, not a miss.

## 2. Give the process a credential

The client signs in with Application Default Credentials (ADC): the attached service account
deployed (Compute Engine, Cloud Run, GKE Workload Identity), Workload Identity Federation outside
Google Cloud, `gcloud auth application-default login` on a developer machine. See
[Wrap keys with Google Cloud KMS](use-google-kms.md#3-give-the-process-a-credential).

## 3. Create the cache

Add the modules, and the Secret Manager client:

```sh
go get github.com/runsecure/hkdfguard-go github.com/runsecure/hkdfguard-go/cache/googlesecretmanager \
  cloud.google.com/go/secretmanager
```

> **TODO (maintainer):** confirm these module paths resolve once the modules are tagged. Until
> then, add `replace` directives pointing at a checkout of `hkdfguard-go` (the root and
> `cache/googlesecretmanager`).

Build the key ring as usual (see [Wrap keys with Google Cloud KMS](use-google-kms.md), or the
native wrapper), then:

```go
client, err := secretmanager.NewClient(ctx) // Application Default Credentials, over gRPC
if err != nil {
	log.Fatal(err)
}
defer client.Close()
secrets, err := googlesecretmanager.New(client, "my-project", ring, googlesecretmanager.Options{})
if err != nil {
	log.Fatal(err)
}

n, ok, err := secrets.MaxDecryptedLength(ctx, "Db-Password")
if err != nil {
	log.Fatal(err)
}
if !ok {
	log.Fatal("no such secret")
}
password := make([]byte, n)
defer hkdfguard.Wipe(password)
written, err := secrets.Decrypt(ctx, "Db-Password", password)
if err != nil {
	log.Fatal(err)
}
// use password[:written]
```

- **The project** is its ID (`my-project`), its number, or a legacy domain-scoped ID
  (`example.com:my-project`). It is spliced into every resource name, so anything but ASCII
  letters, digits, `-`, `.` and `:` is refused with `googlesecretmanager.ErrInvalidArgument`.
- **The client is yours.** `New` takes any value with `AccessSecretVersion`
  (`googlesecretmanager.Client`, which `*secretmanager.Client` satisfies) and never configures or
  closes it. Credentials, the endpoint, the transport and retries are set on the client you pass.
  Close it once nothing uses the cache any more.
- **Prefer gRPC.** `secretmanager.NewClient` (gRPC) lets the cache zero the buffer the response was
  received into; `secretmanager.NewRESTClient` works, but its response copies are out of reach (see
  [A secret never becomes a Go string](#a-secret-never-becomes-a-go-string)).
- **Retries and timeouts are the client's.** By default the client retries `UNAVAILABLE` and
  `RESOURCE_EXHAUSTED` for up to 60 seconds before the lookup returns an error. Every lookup also
  takes a `context.Context`, whose cancellation and deadline the client honours.
- **Keep the client's debug logging off.** Setting `GOOGLE_SDK_GO_LOGGING_LEVEL=debug`, or giving
  the client a logger, makes it log every response in full - secret payloads included.
- **The ring is yours.** The cache never closes keys. Keep the ring open for as long as the cache
  is used. A secret cached before the ring rotates still decrypts afterwards.
- **Logging.** Pass `Options{Logger: ...}` to get an error record for each failed fetch and, while
  sensitive logging is on (`diagnostics.Cache.SetSensitiveLogging(true)`), a debug record naming
  each fetched secret. A value is never logged.

### Behind other sources

A name the cache can't hold is a miss without a call, so the cache can go last in a
`cache.Collection` behind sources with other naming rules:

```go
secrets := cache.NewCollection(localCache, googleCache)
written, err := secrets.Decrypt(ctx, "ConnectionStrings:Admin", buffer) // never reaches Google
```

## Secrets holding several keys

A secret whose payload is a JSON object can be read one key at a time, as `secret#key`:

```go
// The secret "App-Credentials" holds {"api-credential-21":"...","test-credential-1":"...","port":5432}.
written, err := secrets.Decrypt(ctx, "App-Credentials#api-credential-21", buffer)
written, err = secrets.Decrypt(ctx, "App-Credentials#port", buffer) // "5432"
written, err = secrets.Decrypt(ctx, "App-Credentials", buffer)      // the whole JSON text
```

The first lookup of any of a secret's keys calls `AccessSecretVersion` once and caches the whole
value and every key it holds, each encrypted on its own and bound to its own name:

- A string member is cached as its UTF-8 bytes; a number, `true` or `false` as its JSON text.
- `null`, an object, an array, an empty string, or a member whose name isn't a key (1-256 printable
  ASCII characters other than space, `!` and `#`) is left out.
- A payload that isn't exactly one JSON object (plain text, binary, an array, malformed JSON) is
  cached whole only. An object naming a member twice is refused with `cache.ErrInvalidSecretData`.
- Keys match exactly. A key the secret doesn't hold is a miss, and costs a call each time it is
  asked for.

## A secret never becomes a Go string

Secret Manager returns the payload as protobuf `bytes`, which the client decodes into a `[]byte`
of the response's own. The cache:

1. **Checks the response** before using it: it must name a version of the secret asked for (Google
   answers with the project's number, so only the secret ID is compared), and its payload must match
   the CRC32C Google returns with it.
2. **Encrypts the payload and zeroes it**, refused or not.
3. **Over gRPC, zeroes the buffer the response was received into.** grpc-go reads each message into
   buffers from its pool (or, for a message under 1 KiB, the heap), decodes it, and returns them to
   the pool uncleared, so the secret would stay in a buffer the next message on any connection is
   read into. Every call the cache makes carries a per-call option (`grpc.ForceCodecV2` through
   `gax.WithGRPCOptions`) with a codec that decodes the response as gRPC's protobuf codec does
   (`proto.Unmarshal` copies the payload out), then zeroes the buffers. Your client, and every
   other call it makes, is left as it is.

A `Client` that wraps a `*secretmanager.Client` should hand the cache's call options on unchanged;
one that drops them still works, but the receive buffer is left uncleared.

## Limitations

- **Copies the cache can't zero.** Below the codec: the connection's read buffer and TLS's
  decryption buffers, and - if a gRPC compressor such as `google.golang.org/grpc/encoding/gzip` is
  registered in the process, so that Google may compress responses - the compressed bytes gRPC
  frees itself. Over REST: the JSON response body the client reads into a buffer of its own, and the
  base64 text it decodes from. Those live until garbage-collected. `nativev1.HardenProcess()` keeps
  a debugger or crash dump away from them; nothing keeps them out of the process's heap.
- **No refresh.** A cached value is kept for the life of the cache, always the version that was
  `latest` when it was fetched. A new version is picked up by a new cache.
- **Latest version only.** A name can't pin a version or alias.
- **One project per cache.** For secrets in several projects, create a cache per project and put
  them in a `cache.Collection`.

## If something goes wrong

A failed call is returned with the client's error wrapped: `errors.As` reaches the
`*apierror.APIError`, and `status.Code(err)` reads the gRPC status (over REST too, mapped from the
HTTP status). The message names the secret. When the lookup's own `context.Context` was cancelled
or timed out, `errors.Is(err, context.Canceled)` (or `context.DeadlineExceeded`) holds.

| The error | Cause | Fix |
|---|---|---|
| `PERMISSION_DENIED` | The identity lacks `secretmanager.versions.access` on the secret, or the API isn't enabled. Also returned for a secret that doesn't exist, if the identity may not access it | Step 1 |
| `FAILED_PRECONDITION` | The latest version is disabled or destroyed | Enable it, or add a new version |
| `googlesecretmanager.ErrInvalidResponse` ... `corrupted in transit` | The payload didn't match its CRC32C | Retry; if it persists, check proxies between the process and Google |
| `googlesecretmanager.ErrInvalidResponse` ... `answered a request for secret` | The response named another secret | Check anything between the process and Google that rewrites responses |
| `cache.ErrInvalidSecretData` | The payload is a JSON object naming a member twice | Fix the secret's value |
| `credentials: could not find default credentials`, from `secretmanager.NewClient` | No credential could be found | Step 2 |
| `UNAUTHENTICATED` | A credential was found but couldn't get a token | Step 2 |
| `UNAVAILABLE`, or `DEADLINE_EXCEEDED` | Secret Manager couldn't be reached, even after the client's retries | Check the network path to `secretmanager.googleapis.com` |
| `RESOURCE_EXHAUSTED` | Too many `AccessSecretVersion` calls for the project's quota | Reuse one cache for the life of the process |

A secret that doesn't exist or has no versions (`NOT_FOUND`) isn't an error: the lookup returns 0,
or `ok == false`.

## Run the integration tests

The module's integration tests read a real secret. Without `HKDFGUARD_TEST_GOOGLE_SECRET_NAME`
every one of them is reported as skipped - never as passed. They are the same variables the .NET
integration tests read, taken from the environment or from `google.test.properties` at the
repository root (the file the Google Cloud KMS integration tests read; ignored by git):

| Variable | Holds |
|---|---|
| `HKDFGUARD_TEST_GOOGLE_SECRET_NAME` | The secret's resource name, `projects/{project}/secrets/{secret}` |
| `HKDFGUARD_TEST_GOOGLE_SECRET_JSON` | Optional: the JSON object its latest version holds - test values, not credentials. The whole value and each key are then compared with it |

```properties
HKDFGUARD_TEST_GOOGLE_SECRET_NAME=projects/my-project/secrets/hkdfguard-integration-config
HKDFGUARD_TEST_GOOGLE_SECRET_JSON={"test-credential-1":"This is my first credential","port":5432}
```

```sh
gcloud auth application-default login
cd cache/googlesecretmanager
go test -run TestGoogleSecretManagerIntegration -v ./...
```

The principal needs only `secretmanager.versions.access` on that secret; the missing-secret test
reads a random name in the same project, which is `NOT_FOUND` only if the principal may access
secrets there (grant the role on the project for the test identity, or expect that test to fail
with `PERMISSION_DENIED`). The tests never list, create, alter or delete a secret.
