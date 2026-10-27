# Wrap keys with AWS KMS

This page sets up an AWS KMS key as HkdfGuard's KEK and uses it from Go with `awskms.KeyWrapper`,
in place of the native TPM, Secure Enclave or Platform Crypto Provider KEK.

Use it when your application runs on AWS, or anywhere it can reach KMS, and you want key access
controlled by IAM and recorded in CloudTrail rather than tied to one machine's TPM.

To run the AWS KMS integration tests against a key of your own, see
[Run the AWS KMS integration tests](run-aws-kms-integration-tests.md).

## How it differs from the native wrapper

| | Native (`nativev1.KeyWrapper`) | AWS KMS (`awskms.KeyWrapper`) |
|---|---|---|
| KEK | A P-256 key in the TPM, Secure Enclave or Platform Crypto Provider | A symmetric AES-256 KMS key |
| Identified by | A service name | A key ARN |
| Who may wrap and unwrap | Local accounts and groups the native library allows | IAM principals the key policy and IAM policies allow |
| Each call | Local, through the native library | A KMS request over the network, logged in CloudTrail |
| Key file reads | Through the native library, which refuses files another account could have replaced | The same rules, checked in Go by the `securefile` module; who else is trusted is set with `securefile.KeyFileTrust` |
| Install | The Go modules, and the native library (and cgo on Linux and macOS) | The Go modules and the AWS SDK for Go v2; no cgo, no native library |
| Platforms | Windows, Linux, macOS | Anywhere the AWS SDK runs; key files are read on Windows, Linux and Apple silicon Macs |

Wrapped DEKs aren't interchangeable. A key file wrapped by one wrapper can't be unwrapped by the
other, so each DEK belongs to the wrapper that created it. A key file wrapped by the .NET
`AwsKmsKeyWrapper`, the Java `AwsKmsKeyWrapperImpl`, the Python `AwsKmsKeyWrapper` or the Node
`AwsKmsKeyWrapper` under the same key and encryption context unwraps here, and the reverse: all
five send KMS the same requests.

## 1. Create the KMS key

In the AWS console, open **Key Management Service**, choose **Customer managed keys**, then
**Create key**. Choose the region your application runs in; a key is used from its own region.

| Setting | Choose | Why |
|---|---|---|
| Key type | **Symmetric** | `awskms.KeyWrapper` calls `Encrypt`, `Decrypt` and `GenerateDataKeyWithoutPlaintext` with `SYMMETRIC_DEFAULT`, which only a symmetric key accepts |
| Key usage | **Encrypt and decrypt** | Not HMAC, and not key agreement |
| Key material origin | KMS | The default |
| Regionality | Single-Region | Choose multi-Region only if you need to unwrap in another region |
| Alias | Optional, e.g. `alias/myapp-kek` | For finding the key; the wrapper should still be given the ARN |

**Key administrators:** choose the people or role who manage keys, not your application's or
pipeline's role. Administrators can rewrite the key policy, and so grant themselves `Decrypt`.
If your account has no suitable role yet, choose no one: the key policy's *Enable IAM User
Permissions* statement lets IAM policies grant access later.

**Clear "Allow key administrators to delete this key".** Deleting the KMS key makes every DEK
wrapped under it, and all data encrypted under those DEKs, permanently unrecoverable. To retire a
key, disable it instead; that can be undone.

**Key usage permissions:** choose no one. The console's usage statement grants more actions than
HkdfGuard uses; grant exactly what each role needs in step 2 instead.

When the key is created, copy its **ARN** from the key's page. It looks like
`arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab`.

> **Security:** never remove the key policy's *Enable IAM User Permissions* statement (the one
> naming `arn:aws:iam::<account-id>:root`). Without it IAM policies stop working for the key, and
> if no other statement grants administration, only AWS Support can recover it.

## 2. Grant each role only what it calls

| Principal | Actions on the key |
|---|---|
| Release pipeline that creates key files | `kms:Encrypt`, `kms:GenerateDataKeyWithoutPlaintext` |
| Application that only reads key files | `kms:Decrypt` |
| Application that also uses ephemeral keys | `kms:Decrypt`, `kms:GenerateDataKeyWithoutPlaintext` |

Attach an IAM policy like this to each role, with the actions from the table and your key's ARN as
`Resource`:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["kms:Decrypt"],
    "Resource": "arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
    "Condition": {
      "StringEquals": { "kms:EncryptionContext:purpose": "com.example.myapp" }
    }
  }]
}
```

The condition requires the encryption context the wrapper is given in step 4. A role limited to
`com.example.myapp` can't reveal a DEK wrapped for another application under the same key. Leave
the condition out only if you don't pass an encryption context.

> **Security:** give the application `kms:Decrypt` without `kms:Encrypt`. `awskms.KeyWrapper` pins
> the key on every `Decrypt`, so a key file wrapped under any *other* key is refused. But anyone who
> can call `Encrypt` on *this* key, with the same encryption context, can produce a key file your
> application accepts, holding a DEK they chose. Keep `Encrypt` with the pipeline.

## 3. Give the process credentials

`config.LoadDefaultConfig` finds credentials and a region through the AWS SDK for Go's default
chain. Where it runs decides what that should be:

| Where the process runs | Use | What the process holds |
|---|---|---|
| ECS or Fargate | A task role | Nothing; the SDK fetches short-lived credentials |
| EKS | EKS Pod Identity, or IAM roles for service accounts | A token AWS rotates |
| EC2 | An instance profile (IMDSv2) | Nothing |
| Lambda | The function's execution role | Nothing |
| Outside AWS | IAM Roles Anywhere, through `credential_process` | A certificate and private key, which can be kept in a TPM or PKCS#11 token |
| A developer machine | A profile in `~/.aws/credentials` (`%USERPROFILE%\.aws\credentials` on Windows; `aws configure`) | A long-lived access key for a low-privilege IAM user |

> **Security:** don't give a deployed process a long-lived access key, whether in environment
> variables, a mounted file or configuration. Use one of the roles above. An access key is for a
> developer machine only, belongs to an IAM user that can use nothing but this key, and is never
> committed.

The client's region must be the key's region. Set it in the profile, the environment
(`AWS_REGION`), or the configuration itself (`config.WithRegion("us-east-2")`).

## 4. Create the wrapper

Add the modules, and the AWS SDK's KMS client:

```sh
go get github.com/runsecure/hkdfguard-go github.com/runsecure/hkdfguard-go/keywrapping/awskms \
  github.com/runsecure/hkdfguard-go/cryptoprovider/aesgcm256 \
  github.com/aws/aws-sdk-go-v2/config github.com/aws/aws-sdk-go-v2/service/kms
```

> **TODO (maintainer):** confirm these module paths resolve once the modules are tagged. Until
> then, add `replace` directives pointing at a checkout of `hkdfguard-go` (the root, `securefile`,
> `keywrapping/awskms` and `cryptoprovider/aesgcm256`).

`keywrapping/awskms` brings the `securefile` module, which reads key files with
`golang.org/x/sys`. Neither needs cgo or a C compiler, on any platform.

```go
cfg, err := config.LoadDefaultConfig(ctx)
if err != nil {
	log.Fatal(err)
}
wrapper, err := awskms.New(kms.NewFromConfig(cfg),
	"arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
	awskms.Options{EncryptionContext: map[string]string{"purpose": "com.example.myapp"}})
if err != nil {
	log.Fatal(err)
}
```

- **Use the key ARN, not an alias.** `Decrypt` resolves an alias when it's called, so pointing the
  alias at another key makes every DEK wrapped under the old key unreadable. KMS's automatic key
  rotation keeps the ARN, so you can turn it on without changing anything here.
- **The encryption context** is bound into every wrapped DEK and must be given again, exactly, to
  reveal it. Use the same value on every wrapper that handles one application's key files.
  CloudTrail logs it in plaintext, so it must never hold a secret. `awskms.New` copies it.
- **The client is yours.** The wrapper takes any value with the three calls it makes
  (`awskms.Client`, which `*kms.Client` satisfies) and never configures it. A `*kms.Client` needs
  no closing; keep it for as long as anything uses the wrapper, including a key ring's background
  refresh.
- **Retries and timeouts are the client's.** The SDK retries throttling and transient errors by its
  retryer; set `config.WithRetryMaxAttempts`, and an HTTP client with timeouts
  (`config.WithHTTPClient`), when startup or a refresh must not wait long for an unreachable KMS.
  Every wrapper call also takes a `context.Context`, whose cancellation and deadline the SDK
  honours.

## 5. Build a key ring with an ephemeral key

An ephemeral key is generated at startup and never written anywhere. KMS generates it with
`GenerateDataKeyWithoutPlaintext`, so the plaintext DEK isn't returned on that call:

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

Everything encrypted under an ephemeral key is lost when the process exits. Data you store needs a
key file.

## 6. Create a key file

There's no `hkdfguard wrap` for KMS: the release pipeline creates key files with the wrapper
itself, running as the pipeline role from step 2.

If the pipeline only needs a fresh key, have KMS generate it. The plaintext DEK never reaches the
pipeline:

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

If the pipeline also encrypts configuration secrets under the new key with
`aesgcm256.PipelineDataProtector`, wrap that protector's key instead. `KeyBase64` returns the key as
base64 ASCII bytes, never a string; decode it into a buffer you zero, so the key never becomes a
string either:

```go
pipeline, err := aesgcm256.NewPipelineDataProtector(dek.NewDefaultFormatProvider(), 1)
if err != nil {
	log.Fatal(err)
}
defer pipeline.Close()

// ... pipeline.Encrypt(ctx, value, "ConnectionStrings:Admin") for each configuration secret ...

key := make([]byte, aesgcm256.KeySize)
defer hkdfguard.Wipe(key)
if n, err := base64.StdEncoding.Decode(key, pipeline.KeyBase64()); err != nil || n != aesgcm256.KeySize {
	log.Fatal("the pipeline key isn't 32 bytes")
}
wrapped := make([]byte, hkdfguard.MaxWrappedKeyBytes)
n, err := wrapper.Wrap(ctx, key, wrapped)
if err != nil {
	log.Fatal(err)
}
if err := os.WriteFile(`C:\HkdfGuardKeys\myapp\v1.key`, wrapped[:n], 0o640); err != nil {
	log.Fatal(err)
}
```

A KMS-wrapped DEK is about 184 bytes, well inside `hkdfguard.MaxWrappedKeyBytes`. Unlike the
native wrapper, KMS can wrap anywhere the pipeline role has credentials; it doesn't have to run on
the host that uses the key.

### Where key files can live

Anyone who can replace a key file *and* call `Encrypt` on the key can choose your application's
DEK. Step 2 keeps `Encrypt` with the pipeline; `awskms.KeyWrapper` keeps the other half by refusing
to read a key file that anyone untrusted could have written or replaced. It applies the native
library's rules, through `securefile.ReadTrustedKeyFile`:

- **Windows:** the file is on a local fixed drive, not a UNC path or network drive, and its path
  runs through no symbolic link, junction or substituted drive (an 8.3 short name is expanded and
  the real path checked). The file and every folder above it are owned by SYSTEM, Administrators or
  TrustedInstaller, and grant no one else the right to write, delete, rename, change permissions or
  take ownership. For a folder that includes creating files in it. The drive root is held only to
  renaming and deleting what's beneath it. So nothing under `C:\ProgramData`, your user profile or
  `%TEMP%` is trusted, nor a folder made directly under `C:\` with its default permissions. The
  file's owner and permissions are read through the same handle it is read from, opened so that no
  one can write it meanwhile.
- **Linux and macOS:** the file and every directory above it, up to `/`, are owned by root and
  writable by neither their group nor others. A symbolic link is followed only if root owns it. So
  nothing under `/tmp`, `/var/tmp` or a home directory is trusted. The checked path is opened with
  `O_NOFOLLOW` and must still be a regular file. macOS is supported on Apple silicon only.
- **Everywhere:** a file that is empty, over 512 bytes, exactly 32 bytes, or a 32-byte key written
  as hex or base64 is refused. Those last ones are probably a plaintext key: treat it as exposed.

Prepare the folder once, as an administrator. On Windows, give it its own permissions, with
inheritance removed:

```powershell
New-Item -ItemType Directory -Force C:\HkdfGuardKeys\myapp | Out-Null
icacls C:\HkdfGuardKeys /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX"
icacls C:\HkdfGuardKeys /setowner "*S-1-5-32-544" /T
```

On Linux:

```bash
sudo install -d -o root -g myapp -m 0750 /etc/hkdfguard/keys/myapp
```

Then write key files as an administrator (elevated on Windows, so Administrators owns the file; as
root on Linux and macOS), and let the application's account only read them: on Linux,
`sudo install -o root -g myapp -m 0640 v1.key /etc/hkdfguard/keys/myapp/`.

If the pipeline writes key files as an account of its own instead, trust it explicitly:

```go
trusted, err := awskms.New(client, keyARN, awskms.Options{
	EncryptionContext: map[string]string{"purpose": "com.example.myapp"},
	KeyFileTrust: securefile.NewKeyFileTrust(securefile.KeyFileTrustOptions{
		// Windows: the deployer account, which owns the files it creates, and any group granted
		// Modify on the folder. SIDs, not names: Get-LocalUser deployer | Select-Object SID
		WindowsPrincipals: []string{"S-1-5-21-1111111111-2222222222-3333333333-1005"},
		// Linux and macOS: the deployer's uid, and a group allowed to write (id deployer).
		UnixUserIDs:  []uint32{1001},
		UnixGroupIDs: []uint32{2001},
	}),
})
```

> **Security:** never trust the account the application itself runs as, except on a developer
> machine. An application that can rewrite its own key files can be made to switch to an older,
> still-valid one. Everyone, Authenticated Users, Users, Interactive and Anonymous are refused if
> listed.

## 7. Use the key file

```go
ring, err := dek.Build(ctx, dek.Config{
	KeyWrapper:            wrapper,
	CryptoProviderFactory: aesgcm256.NewFactory(),
	KeyRefreshInterval:    300 * time.Second,
	KeyFiles:              map[int]string{1: `C:\HkdfGuardKeys\myapp\v1.key`},
})
if err != nil {
	log.Fatal(err)
}
defer ring.Close()
```

With the `HkdfGuard` section of an `appsettings.json` shared with the .NET port, the file describes
the ring and the application supplies the wrapper:

```go
document, err := os.ReadFile("appsettings.json")
if err != nil {
	log.Fatal(err)
}
options, err := dek.OptionsFromJSON(document, "HkdfGuard")
if err != nil {
	log.Fatal(err)
}
config, err := options.Config(wrapper, aesgcm256.NewFactory())
if err != nil {
	log.Fatal(err)
}
ring, err := dek.Build(ctx, config)
```

```json
{
  "HkdfGuard": {
    "ServiceName": "com.example.myapp",
    "KeyRefreshInterval": 300,
    "KeyFiles": [{ "Version": 1, "Path": "C:\\HkdfGuardKeys\\myapp\\v1.key" }]
  }
}
```

`dek.Build` calls KMS once per key, so the application fails to start if KMS can't be reached or
refuses the key.

## Choosing a refresh interval

Every key in the ring calls `Decrypt` once per `KeyRefreshInterval` to confirm the KEK is still
available. After three failed refreshes in a row (by default) the ring suspends encryption and
decryption until KMS answers again. So the interval trades how quickly a revoked grant stops the
process against the number of KMS requests:

| Interval | `Decrypt` calls per key, per process, per 30 days | Revocation stops the process within |
|---|---|---|
| 60 seconds | 43,200 | about 3 minutes |
| 300 seconds (the maximum) | 8,640 | about 15 minutes |

Multiply by the number of registered keys and running processes. The AWS free tier covers 20,000
KMS requests a month, and a customer managed key costs about $1 a month on top of its requests;
see [AWS KMS pricing](https://aws.amazon.com/kms/pricing/). The default of three failures also
sets how long a KMS outage is ridden out; change it with
`RefreshFailurePolicy: hkdfguard.FailClosedAfter(n)` in `dek.Config`. The interval is also each
refresh's deadline, so it must allow for KMS's round trip.

## Limitations

- **Copies the wrapper can't zero.** The wrapper zeroes its own copy of a key sent to `Encrypt`, and
  the slice the SDK decodes `Decrypt`'s plaintext into once it is copied into your `result`. But
  the SDK sends and receives that key as base64 text in a JSON body, in buffers it doesn't expose,
  which live until garbage-collected. `nativev1.HardenProcess()` keeps a debugger or crash dump away
  from them; nothing keeps them out of the process's heap.
- **Key-file checks aren't interruptible.** A key file is a few hundred bytes on a local drive, so
  `ReadKeyFile` checks its `context.Context` once, before it starts, and then makes its checks and
  the read synchronously. On Windows, naming a principal in a refusal message looks its account up,
  which for a domain SID can contact a domain controller.
- **Intel Macs** are refused, as in the other ports, though Go's own `lstat` would work there.

## If something goes wrong

Every KMS failure is an `*awskms.Error` (matching `awskms.ErrKMS` with `errors.Is`) whose message
names the operation, the key, KMS's error code and the HTTP status; it unwraps to the SDK's error,
so `errors.As` reaches a `*types.IncorrectKeyException` and the like. A failed unwrap zeroes the
caller's buffer. When the call's own `context.Context` was cancelled or timed out, the SDK's error
is returned as it is (`errors.Is(err, context.Canceled)`). An argument the wrapper refuses before
calling KMS wraps `awskms.ErrInvalidArgument`.

| The message names | Cause | Fix |
|---|---|---|
| `AccessDeniedException` | The principal has no IAM permission for this action on this key, or the encryption context doesn't satisfy the policy condition | Step 2: check the action, the `Resource` ARN and the condition |
| `NotFoundException` | The ARN is wrong, or the client is in a different region from the key | Copy the ARN again; set the client's region to the key's |
| `IncorrectKeyException` | The key file was wrapped under a different KMS key | Use the key the file was created with |
| `InvalidCiphertextException` | The key file was altered, or the encryption context differs from the one it was wrapped with | Restore the file; use the same encryption context |
| `DisabledException` | The key is disabled | Re-enable it, or restore the key that wrapped the file |
| `KMSInvalidStateException` | The key is pending deletion | Cancel the deletion right away, within its waiting period |
| `get credentials: failed to refresh cached credentials` | The SDK found no credentials | Step 3 |
| `connection refused`, `no such host`, `i/o timeout` | KMS can't be reached: no network route, a proxy, or a wrong region | Check the network path to `kms.<region>.amazonaws.com` |
| `ThrottlingException` | Too many requests for the account's KMS quota | Lengthen the key refresh interval, or ask AWS for a higher quota |

A missing region is reported by the SDK on the first call (`failed to resolve service endpoint,
... Missing Region`), as an `*awskms.Error` like any other failure on the way to KMS: set one
(step 3).

Reading a key file fails before KMS is called, with a `*securefile.KeyFileError`:

| `errors.Is` and message | Cause | Fix |
|---|---|---|
| `securefile.ErrUntrusted` (and `fs.ErrPermission`) ... `is not trusted` | The file or a folder above it is owned, or modifiable, by an account that isn't trusted; the message names it | [Where key files can live](#where-key-files-can-live): fix the folder's permissions, or trust the deployer with `securefile.KeyFileTrust` |
| `securefile.ErrUntrusted` ... `UNC or device path` or `drive` | The file isn't on a local fixed drive | Move it to a local drive |
| `securefile.ErrUntrusted` ... `it opens` | The path runs through a link, junction or substituted drive | Configure the full, real path |
| `hkdfguard.ErrInvalidKeyFile` ... `unwrapped` | The file holds what looks like a plaintext key | Treat the key as exposed: replace it, and write the file with `awskms.KeyWrapper` |
| `hkdfguard.ErrInvalidKeyFile` ... `empty` or `larger than` | It isn't a key file | Check the path |
| `fs.ErrNotExist` | The file, or a folder on its path, doesn't exist | Check the path |
| `fs.ErrPermission` without `ErrUntrusted` | This account may not read the file | Grant the application's account read access |
| `securefile.ErrBusy` | Another process has the file open for writing (Windows) | Let the deployment finish writing it |
| `securefile.ErrInvalidTrust` | A listed SID isn't valid, or is a group everyone is in | List the deployer's own account or group |
| `securefile.ErrUnsupportedPlatform` | Not Windows, Linux or an Apple silicon Mac | Read key files on a supported platform |
