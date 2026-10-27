# HkdfGuard documentation (Go)

Pick the page for what you're doing.

**New to HkdfGuard:** start with [Getting started](getting-started.md). It takes one machine, a
Windows PC or an Apple-silicon Mac, from nothing to encrypting and decrypting with a key the
platform protects (TPM or Secure Enclave), then to a durable key file.

**Running HkdfGuard in production** (installing, provisioning, creating key files): see the
[`hkdfguard` tool reference](reference/cli.md).

**Using an AWS KMS key as the KEK** instead of the TPM or Secure Enclave: see
[Wrap keys with AWS KMS](how-to/use-aws-kms.md). **Using Azure Key Vault keys:** see
[Wrap keys with Azure Key Vault](how-to/use-azure-key-vault.md).

**Porting from the .NET libraries:** the same pages exist in `hkdfguard-dotnet/docs`, with the
same structure. Everything a value or a key file is made of - the `enc::v<version>::<base64>`
format, the AES-256-GCM ciphertext, the purpose and name binding, the native key files - is
byte-identical between the ports, so one deployment serves both.

## Map

| Kind | Page | Status |
|---|---|---|
| Tutorial | [Getting started](getting-started.md) | Draft |
| How-to | [Wrap keys with AWS KMS](how-to/use-aws-kms.md) | Draft |
| How-to | [Run the AWS KMS integration tests](how-to/run-aws-kms-integration-tests.md) | Draft |
| How-to | [Wrap keys with Azure Key Vault](how-to/use-azure-key-vault.md) | Draft |
| How-to | [Run the Azure Key Vault integration tests](how-to/run-azure-key-vault-integration-tests.md) | Draft |
| How-to | Provision a service on each platform | Planned (the test-host scripts under `keywrapping/nativev1/scripts` show each platform's steps) |
| How-to | Create key files in a deployment pipeline | Planned (see [Getting started, step 5](getting-started.md#5-create-a-key-file)) |
| How-to | Rotate keys | Planned (see the README's `dek` section for now) |
| How-to | Load settings from an `appsettings.json` shared with the .NET port | Planned (see `dek.OptionsFromJSON` in the README) |
| How-to | Troubleshoot | Planned (see [If something goes wrong](getting-started.md#if-something-goes-wrong)) |
| Reference | [`hkdfguard` tool](reference/cli.md) | Draft (Windows and macOS; Linux partial) |
| Reference | Native status codes | Planned (the shared table in `keywrapping/nativev1/status.go` for now) |
| Reference | `dek.Options` / configuration schema | Planned |
| Reference | API | [pkg.go.dev](https://pkg.go.dev/github.com/runsecure/hkdfguard-go), generated from the doc comments |
| Explanation | Key hierarchy: KEK, wrapped DEK, AES-GCM | Planned (see [How the pieces fit](getting-started.md#how-the-pieces-fit)) |
| Explanation | Threat model and fail-closed behavior | Planned |
| Explanation | How the native library is verified before loading | Planned (see the package comment of `keywrapping/nativev1`) |

## Conventions

- Every code sample in these pages compiles against the current source. When you change one,
  build it before committing.
- Facts about the `hkdfguard` tool come from its own `--help` output and observed behavior.
  Anything not yet confirmed is marked **TODO (maintainer)**; search for that string before
  publishing.
- Security rules are stated as rules, at the step where they apply, in a block that starts with
  **Security:**.
