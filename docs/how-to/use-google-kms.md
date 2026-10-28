# Wrap keys with Google Cloud KMS

This page sets up a Google Cloud KMS key as HkdfGuard's KEK and uses it from Go with
`googlekms.KeyWrapper`, in place of the native TPM, Secure Enclave or Platform Crypto Provider KEK.

To run the Google Cloud KMS integration tests against a key of your own, see
[Run the Google Cloud KMS integration tests](run-google-kms-integration-tests.md).

## How it compares

Cloud KMS works like AWS KMS: one symmetric key, used through `Encrypt` and `Decrypt`, which never
leaves Cloud KMS.

| | AWS KMS | Azure Key Vault | Google Cloud KMS |
|---|---|---|---|
| Keys | One symmetric key | An RSA key to wrap, an EC P-256 key to sign | One symmetric key |
| Who can create a key file the app accepts | Principals allowed `kms:Encrypt` | Principals allowed `sign` on the EC key | Principals allowed `useToEncrypt` |
| Context binding | Encryption context (AAD) | A context string bound into the signature | A context string bound as AAD |
| New DEKs | Generated inside KMS | Generated in the process, then wrapped | Generated in the process, then wrapped |
| Client | The application's `*kms.Client` | Created by the wrapper from the application's credential | The application's `*kms.KeyManagementClient` |

`googlekms.KeyWrapper`:

- **Pins the key.** `Decrypt` is always called against the key you configure, and Cloud KMS
  refuses a ciphertext made under any other key.
- **Binds a fixed HkdfGuard label and your context** into every wrapped DEK as additional
  authenticated data (AAD). A ciphertext the same key made for anything else isn't accepted as a
  DEK.
- **Checksums every request and response with CRC32C**, as Google recommends, so data corrupted
  in transit is refused.

A key file belongs to the wrapper type that made it: a Cloud KMS key file can't be read by the AWS
or Azure wrappers. Between languages it is the same file: a key file made by the .NET
`GoogleKmsKeyWrapper`, the Java `GoogleKmsKeyWrapperImpl`, or the Python or Node
`GoogleKmsKeyWrapper` is read by this one, and the other way round, given the same key and context.

## 1. Create the key

Enable the API, then create a key ring and a key whose purpose is **encryption**
(`ENCRYPT_DECRYPT`, algorithm `GOOGLE_SYMMETRIC_ENCRYPTION`):

```bash
gcloud services enable cloudkms.googleapis.com --project my-project

gcloud kms keyrings create myapp --location us-east1 --project my-project
gcloud kms keys create myapp-wrap --keyring myapp --location us-east1 --project my-project \
  --purpose encryption --protection-level hsm \
  --rotation-period 90d --next-rotation-time 2027-01-01T00:00:00Z
```

| Setting | Choose | Why |
|---|---|---|
| Purpose | **Symmetric encrypt/decrypt** | `googlekms.KeyWrapper` calls `Encrypt` and `Decrypt`, which only this purpose accepts |
| Protection level | **HSM** (or Software) | HSM keeps the key in a FIPS 140-2 Level 3 module; both work the same here |
| Rotation | Automatic, if you like | A ciphertext names the version that made it, so rotation needs nothing here |
| Location | Where the application runs | Key rings can't be moved or deleted; the name is part of every call |

In the console: **Security**, **Key Management**, **Create key ring**, then **Create key** with
**Purpose: Symmetric encrypt/decrypt**.

> **Security:** destroying a key version makes every DEK wrapped under it, and all data encrypted
> under those DEKs, permanently unrecoverable. Cloud KMS waits before destroying a version (30 days
> by default; `--destroy-scheduled-duration` sets it when the key is created), during which it can
> be restored. Keep every version that made a key file in use enabled.

Copy the key's **resource name**, for example
`projects/my-project/locations/us-east1/keyRings/myapp/cryptoKeys/myapp-wrap`:

```bash
gcloud kms keys describe myapp-wrap --keyring myapp --location us-east1 --project my-project --format "value(name)"
```

Give the key, never a key version (`.../cryptoKeyVersions/1`): the wrapper refuses one. Encrypt
uses the key's primary version, and Decrypt finds the version from the ciphertext.

## 2. Grant each identity only what it calls

Grant roles on the **key**, not the project or key ring:

| Identity | Role on the key |
|---|---|
| Release pipeline that creates key files | Cloud KMS CryptoKey Encrypter (`roles/cloudkms.cryptoKeyEncrypter`) |
| Application | Cloud KMS CryptoKey Decrypter (`roles/cloudkms.cryptoKeyDecrypter`) |

```bash
gcloud kms keys add-iam-policy-binding myapp-wrap --keyring myapp --location us-east1 --project my-project \
  --member "serviceAccount:myapp@my-project.iam.gserviceaccount.com" \
  --role roles/cloudkms.cryptoKeyDecrypter
```

> **Security:** give the application decrypt without encrypt. Symmetric encryption needs no
> secret beyond permission to use the key, so any principal allowed `useToEncrypt` can create a key
> file the application accepts, holding a DEK of its choosing. Keep encrypt with the pipeline.

## 3. Give the process a credential

The client signs in with Application Default Credentials (ADC). Deployed, use the **attached
service account** (Compute Engine, Cloud Run, GKE Workload Identity); outside Google Cloud, use
Workload Identity Federation. On a developer machine, ADC uses
`gcloud auth application-default login`. Don't give a deployed process a service account key file.

## 4. Create the wrapper

Add the modules, and the Cloud KMS client:

```sh
go get github.com/runsecure/hkdfguard-go github.com/runsecure/hkdfguard-go/keywrapping/googlekms \
  github.com/runsecure/hkdfguard-go/cryptoprovider/aesgcm256 \
  cloud.google.com/go/kms
```

> **TODO (maintainer):** confirm these module paths resolve once the modules are tagged. Until
> then, add `replace` directives pointing at a checkout of `hkdfguard-go` (the root, `securefile`,
> `keywrapping/googlekms` and `cryptoprovider/aesgcm256`).

`keywrapping/googlekms` brings the `securefile` module, which reads key files with
`golang.org/x/sys`. Neither needs cgo or a C compiler, on any platform.

```go
client, err := kms.NewKeyManagementClient(ctx) // Application Default Credentials
if err != nil {
	log.Fatal(err)
}
defer client.Close()
wrapper, err := googlekms.New(client,
	"projects/my-project/locations/us-east1/keyRings/myapp/cryptoKeys/myapp-wrap",
	googlekms.Options{Context: "com.example.myapp"})
if err != nil {
	log.Fatal(err)
}
```

- **The context** is bound into every key file and must be given again, exactly, to reveal it.
  Use one value per application, so a key file made for one can't be used by another that shares
  the key. It isn't secret.
- **Create one client and keep it.** `*kms.KeyManagementClient` holds a gRPC connection and can be
  shared between wrappers. The wrapper never closes it: close it once nothing uses the wrapper any
  more - after the key ring is closed, since its background refresh calls the wrapper.
- **Client settings.** Credentials, the endpoint and the transport are the client's:
  `kms.NewKeyManagementClient(ctx, option.WithCredentials(...), option.WithEndpoint(...))`, or
  `kms.NewKeyManagementRESTClient` for HTTP/JSON instead of gRPC. By default the client retries
  `UNAVAILABLE` and `DEADLINE_EXCEEDED` for up to 60 seconds in all before the wrapper returns an
  error. Every wrapper call also takes a `context.Context`, whose cancellation and deadline the
  client honours.
- **Keep the client's debug logging off.** Setting `GOOGLE_SDK_GO_LOGGING_LEVEL=debug`, or giving
  the client a logger, makes it log every request and response in full - the keys the wrapper sends
  and receives included.

The wrapper reaches the client through the small `googlekms.Client` interface (`Encrypt` and
`Decrypt`), which `*kms.KeyManagementClient` satisfies, so tests can use a fake.

## 5. Build a key ring with an ephemeral key

An ephemeral key is generated at startup and never written anywhere. Cloud KMS has no "generate data
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

An ephemeral key needs `useToEncrypt` to be made, which step 2 keeps from the application. Use key
files instead, or give an identity that only ever uses ephemeral keys its own key. Everything
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
[Wrap keys with AWS KMS](use-aws-kms.md#6-create-a-key-file). A key file is about 113 bytes.

Key files are read only from where no untrusted account could have written or replaced them,
exactly as for AWS KMS: see [Where key files can live](use-aws-kms.md#where-key-files-can-live), and
set `Options.KeyFileTrust` if the pipeline writes key files as an account of its own. Then use the
key file as in [Use the key file](use-aws-kms.md#7-use-the-key-file).

## Choosing a refresh interval

Every key in a ring re-reveals itself once per `KeyRefreshInterval`: one `Decrypt` call to Cloud
KMS. See [Choosing a refresh interval](use-aws-kms.md#choosing-a-refresh-interval) for the
trade-off, and [Cloud KMS pricing](https://cloud.google.com/kms/pricing) for what each operation and
active key version costs: HSM keys cost more than software keys.

## Limitations

- **Copies the wrapper can't zero.** The wrapper zeroes its own copy of a key it wraps once the
  call returns, and the slice the client decodes a revealed key into once it is copied into your
  `result`. But the client serializes each request into a buffer of its own (a protobuf message
  over gRPC, base64 text in JSON over REST), which the wrapper can't reach.
  `nativev1.HardenProcess` keeps a debugger or crash dump away from such copies.
- The key-file limitations are those of [Wrap keys with AWS KMS](use-aws-kms.md#limitations).

## If something goes wrong

Every Cloud KMS failure is a `*googlekms.Error` (matching `googlekms.ErrCloudKMS` with `errors.Is`)
whose message names the operation and the key, and for a refusal the gRPC status and Google's
description (over REST too, where the client maps the HTTP status to a gRPC one). It unwraps to the
client's error: `errors.As` reaches the `*apierror.APIError`, and `status.Code(err)` reads the
status. A failed unwrap zeroes the caller's buffer. A call whose `context.Context` was cancelled or
expired fails with an error matching `context.Canceled` or `context.DeadlineExceeded`. Argument
errors - a resource name that isn't one, included - wrap `googlekms.ErrInvalidArgument`. Reading a
key file fails as described for [AWS KMS](use-aws-kms.md#if-something-goes-wrong).

| The message says | Cause | Fix |
|---|---|---|
| `PERMISSION_DENIED` | The identity lacks the role on the key, or the API isn't enabled | Step 2; `gcloud services enable cloudkms.googleapis.com` |
| `NOT_FOUND` | The resource name is wrong | Step 1's `describe` command |
| `INVALID_ARGUMENT: Decryption failed.` | The key file was altered, made under another key or context, or by another tool | Restore it; use the same key and context |
| `FAILED_PRECONDITION` | The key version the key file names is disabled or destroyed | Re-enable or restore the version |
| `isn't a Cloud KMS key's resource name` (`ErrInvalidArgument`) | The name is malformed, or names a key version | Give `projects/.../cryptoKeys/{key}` |
| `corrupted in transit` | A checksum didn't match | Retry; if it persists, check proxies between the process and Cloud KMS |
| `credentials: could not find default credentials`, from `kms.NewKeyManagementClient` | No credential could be found | Step 3 |
| `UNAUTHENTICATED` | A credential was found but couldn't get a token | Step 3 |
| `UNAVAILABLE`, or `DEADLINE_EXCEEDED` | Cloud KMS couldn't be reached, even after the client's retries | Check the network path to `cloudkms.googleapis.com` |
