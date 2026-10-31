# Cache AWS Secrets Manager secrets

This page reads secrets from AWS Secrets Manager into HkdfGuard's protected cache with
`awssecretsmanager.New`, so your application holds each secret encrypted under its key ring and
never as a Go string.

Use it when your application's secrets live in Secrets Manager and you want them to stay encrypted
in memory between uses, rather than sit in plain strings for the life of the process.

## How it works

The cache is a `hkdfguard.ProtectedReadOnlyCache` (a `*cache.RemoteCache`). Nothing is fetched up
front:

- The first `Decrypt` or `MaxDecryptedLength` of a name calls `GetSecretValue` for that one secret
  (its `AWSCURRENT` version), encrypts the value under the ring's current key, bound to its name,
  and caches only the ciphertext.
- Every later lookup is served from the cache. Secrets Manager isn't called again for that name.
- Concurrent lookups of the same uncached secret share one call.

It never calls `ListSecrets` or `BatchGetSecretValue`, so the application needs only
`secretsmanager:GetSecretValue` on the secrets it reads.

| | Behavior |
|---|---|
| Names | Matched exactly, as Secrets Manager matches them: `prod/Db` and `prod/db` are two secrets and two entries |
| A name Secrets Manager can't hold | Anything but 1-512 ASCII letters, digits and `/_+=.@-` (such as `ConnectionStrings:Admin`, or an ARN) is reported missing without a call |
| `SecretString` | Cached as its UTF-8 bytes; a JSON object's members also as `name#key` (see [Secrets holding several keys](#secrets-holding-several-keys)) |
| `SecretBinary` | Cached as its bytes, never split |
| A secret that doesn't exist, or is empty | Reported missing (`Decrypt` returns 0, `MaxDecryptedLength` returns `ok == false`) and looked up again next time |
| Any other failure | Returned as the AWS SDK's error, and nothing is cached |
| A new secret version | Not picked up: a cached value is kept for the life of the cache. Create a new cache to read it |

## 1. Grant the application read access

Attach an IAM policy like this to the application's role, naming the secrets it reads:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["secretsmanager:GetSecretValue"],
    "Resource": "arn:aws:secretsmanager:us-east-2:111122223333:secret:prod/myapp/*"
  }]
}
```

If a secret is encrypted under a customer managed KMS key rather than the AWS managed
`aws/secretsmanager` key, the role also needs `kms:Decrypt` on that key.

> **Security:** grant `GetSecretValue` on the secrets the application reads, not `*`. The cache
> never lists, so it doesn't need `secretsmanager:ListSecrets` either.

Without permission on a name, Secrets Manager answers `AccessDeniedException` even when the secret
doesn't exist, so a missing secret outside the policy's `Resource` is an error, not a miss.

## 2. Give the process credentials

`config.LoadDefaultConfig` finds credentials and a region through the AWS SDK for Go's default
chain: a task role on ECS or Fargate, EKS Pod Identity, an instance profile on EC2, a Lambda
execution role, IAM Roles Anywhere outside AWS, or a profile in `~/.aws/credentials` on a developer
machine. See [Wrap keys with AWS KMS](use-aws-kms.md#3-give-the-process-credentials) for the same
choices in detail. The client's region must be the secrets' region.

## 3. Create the cache

Add the modules, and the AWS SDK's Secrets Manager client:

```sh
go get github.com/runsecure/hkdfguard-go github.com/runsecure/hkdfguard-go/cache/awssecretsmanager \
  github.com/aws/aws-sdk-go-v2/config github.com/aws/aws-sdk-go-v2/service/secretsmanager
```

> **TODO (maintainer):** confirm these module paths resolve once the modules are tagged. Until
> then, add `replace` directives pointing at a checkout of `hkdfguard-go` (the root and
> `cache/awssecretsmanager`).

Build the key ring as usual (see [Wrap keys with AWS KMS](use-aws-kms.md), or the native wrapper),
then:

```go
cfg, err := config.LoadDefaultConfig(ctx)
if err != nil {
	log.Fatal(err)
}
secrets, err := awssecretsmanager.New(secretsmanager.NewFromConfig(cfg), ring, awssecretsmanager.Options{})
if err != nil {
	log.Fatal(err)
}

n, ok, err := secrets.MaxDecryptedLength(ctx, "prod/Db-Password")
if err != nil {
	log.Fatal(err)
}
if !ok {
	log.Fatal("no such secret")
}
password := make([]byte, n)
defer hkdfguard.Wipe(password)
written, err := secrets.Decrypt(ctx, "prod/Db-Password", password)
if err != nil {
	log.Fatal(err)
}
// use password[:written]
```

- **The client is yours.** `New` takes any value with `GetSecretValue` (`awssecretsmanager.Client`,
  which `*secretsmanager.Client` satisfies) and never configures it. Credentials, region, retries,
  timeouts and the HTTP client are set on the client you pass. A `*secretsmanager.Client` needs no
  closing.
- **Retries and timeouts are the client's.** The first lookup of a name waits for AWS. Set
  `config.WithRetryMaxAttempts`, and an HTTP client with timeouts (`config.WithHTTPClient`), when a
  lookup must not wait long for an unreachable Secrets Manager. Every lookup also takes a
  `context.Context`, whose cancellation and deadline the SDK honours.
- **The ring is yours.** The cache never closes keys. Keep the ring open for as long as the cache
  is used. A secret cached before the ring rotates still decrypts afterwards.
- **Logging.** Pass `Options{Logger: ...}` to get an error record for each failed fetch and, while
  sensitive logging is on (`diagnostics.Cache.SetSensitiveLogging(true)`), a debug record naming
  each fetched secret. A value is never logged.

### Behind other sources

A name the cache can't hold is a miss without a call, so the cache can go last in a
`cache.Collection` behind sources with other naming rules:

```go
secrets := cache.NewCollection(localCache, awsCache)
written, err := secrets.Decrypt(ctx, "ConnectionStrings:Admin", buffer) // never reaches AWS
```

## Secrets holding several keys

A key/value secret, as the Secrets Manager console stores one, is a `SecretString` holding a JSON
object. Read one key of it by name, as `secret#key`:

```go
// The secret "prod/app" holds {"api-credential-21":"...","test-credential-1":"...","port":5432}.
written, err := secrets.Decrypt(ctx, "prod/app#api-credential-21", buffer)
written, err = secrets.Decrypt(ctx, "prod/app#port", buffer) // "5432"
written, err = secrets.Decrypt(ctx, "prod/app", buffer)      // the whole JSON text
```

The first lookup of any of a secret's keys calls `GetSecretValue` once and caches the whole value
and every key it holds, each encrypted on its own and bound to its own name:

- A string member is cached as its UTF-8 bytes; a number, `true` or `false` as its JSON text.
- `null`, an object, an array, an empty string, or a member whose name isn't a key (1-256 printable
  ASCII characters other than space, `!` and `#`) is left out.
- A value that isn't exactly one JSON object (plain text, an array, malformed JSON) is cached whole
  only. An object naming a member twice is refused with `cache.ErrInvalidSecretData`.
- A `SecretBinary` is never split.
- Keys match exactly. A key the secret doesn't hold is a miss, and costs a call each time it is
  asked for.

## A secret never becomes a Go string

The AWS SDK would parse `GetSecretValue`'s response into a `SecretString *string`, which can't be
zeroed. So every call the cache makes carries a per-call option that:

1. **Adds a capture middleware at the innermost end of the SDK's Deserialize step**, after every
   middleware the SDK and your own `APIOptions` add. It is the first to see each attempt's raw HTTP
   response. On a 2xx answer it reads the body into a buffer of its own, hands `SecretString` or
   `SecretBinary` to the cache, closes the original body, and hands the SDK a copy with both values
   blanked. The `GetSecretValueOutput` the SDK builds holds `""` and an empty slice; the SDK's
   response logger, interceptors and your own Deserialize middleware see only the blanked body.
   Retries live in the earlier Finalize step, so every attempt passes through the middleware.
2. **Turns response-body logging off** (`aws.LogResponseWithBody`) for that call, whatever the
   client's `ClientLogMode` says. Request and response headers are still logged if you ask.

Every buffer that held the value is zeroed once it is encrypted.

A `Client` that wraps a `*secretsmanager.Client` must hand the cache's `optFns` on unchanged. One
that doesn't (or a stand-in that answers itself) fails every fetch with
`awssecretsmanager.ErrNotCaptured` and nothing is cached.

## Limitations

- **Copies the cache can't zero.** What no code above the HTTP client can reach is that client's own
  buffers: TLS decryption, socket reads, and any buffering a custom `HTTPClient` or transport adds.
  Those live until garbage-collected. `nativev1.HardenProcess()` keeps a debugger or crash dump
  away from them; nothing keeps them out of the process's heap.
- **An `HTTPClient` you supply sees the raw response.** The capture runs above the HTTP client, so
  a client that logs or records response bodies records the secret. Don't wrap the client with one.
- **No refresh.** A cached value is kept for the life of the cache. A rotated secret is picked up by
  a new cache.
- **No ARNs.** Look secrets up by name.
- **The response body must be under 1 MiB** (`cache.MaxJSONBodyLength`). Secrets Manager's own
  limit is 64 KiB per secret, so a real response always is.

## If something goes wrong

A failure is returned as the AWS SDK's error, so `errors.As` reaches the service's exception
(`*types.InvalidRequestException` and the like) or a `smithy.APIError`. When the lookup's own
`context.Context` was cancelled or timed out, `errors.Is(err, context.Canceled)` (or
`context.DeadlineExceeded`) holds.

| The error | Cause | Fix |
|---|---|---|
| `AccessDeniedException` | The role may not call `GetSecretValue` on this name, or `kms:Decrypt` on the secret's key. Also returned for a name that doesn't exist outside the policy's `Resource` | Step 1 |
| `InvalidRequestException` ... `marked for deletion` | The secret is scheduled for deletion | Restore it (`RestoreSecret`), or stop reading it |
| `DecryptionFailure` | Secrets Manager can't decrypt the secret under its KMS key | Check the key is enabled and the role has `kms:Decrypt` |
| `get credentials: failed to refresh cached credentials` | The SDK found no credentials | Step 2 |
| `Missing Region` | The client has no region | Set one in the profile, `AWS_REGION`, or `config.WithRegion` |
| `connection refused`, `no such host`, `i/o timeout` | Secrets Manager can't be reached | Check the network path to `secretsmanager.<region>.amazonaws.com` |
| `cache.ErrInvalidSecretData` | A 2xx response that isn't a JSON object, holds both values, holds a `SecretBinary` that isn't base64, or a JSON object naming a member twice | Check the secret's value; anything between you and AWS that rewrites responses |
| `awssecretsmanager.ErrNotCaptured` | The `Client` passed to `New` dropped the cache's `optFns` | Hand `optFns` on to the `*secretsmanager.Client` |
| `ThrottlingException` | Too many `GetSecretValue` calls for the account's quota | Reuse one cache for the life of the process |

A secret that doesn't exist (`ResourceNotFoundException`) isn't an error: the lookup returns 0, or
`ok == false`.

## Run the integration tests

The module's integration tests read a real secret. Without `HKDFGUARD_TEST_AWS_SECRET_NAME` every
one of them is reported as skipped - never as passed. They are the same variables the .NET
integration tests read:

| Variable | Holds |
|---|---|
| `HKDFGUARD_TEST_AWS_SECRET_NAME` | A secret's name (not its ARN), in the region your profile names |
| `HKDFGUARD_TEST_AWS_SECRET_JSON` | Optional: the JSON object its `SecretString` holds - test values, not credentials. The whole value and each key are then compared with it |

```sh
aws configure
cd cache/awssecretsmanager
HKDFGUARD_TEST_AWS_SECRET_NAME=test/Integration/secrets \
HKDFGUARD_TEST_AWS_SECRET_JSON='{"test-credential-1":"This is my first credential","port":5432}' \
  go test -run TestAwsSecretsManagerIntegration -v ./...
```

The principal needs only `secretsmanager:GetSecretValue` on that secret's folder (the
missing-secret test reads a random name beside it), and `kms:Decrypt` on its key if it isn't the
AWS managed one. The tests never list, create, alter or delete a secret.
