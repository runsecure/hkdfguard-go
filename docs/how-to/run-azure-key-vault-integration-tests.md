# Run the Azure Key Vault integration tests

`integration_test.go` in `keywrapping/azurekeyvault` makes real calls to Azure Key Vault through
`azurekeyvault.KeyWrapper`. This page sets up a test vault with the two keys the wrapper needs, and
runs the tests from the command line.

The module's other tests use an in-process fake vault behind the Azure SDK's own client, and run
without any of this. The integration tests are reported as **skipped**, never passed, until both
keys are configured.

They check that:

- a DEK survives a wrap and unwrap round trip;
- `GenerateAndWrap` produces a wrapped DEK that reveals to 32 non-zero bytes;
- a wrapped DEK made under one context is refused under another;
- a tampered wrapped DEK is refused.

The tests never create, change or delete a key.

If you already run the .NET, Java, Python or Node port's Azure Key Vault integration tests, you have
a vault, both keys and access: skip to [step 5](#5-fill-in-azuretestproperties) and use the same two
identifiers.

## What you need

- An Azure subscription. A free account works; a test run is about 20 Key Vault operations, a
  fraction of a cent, and software-protected keys have no monthly fee.
- The [Azure CLI](https://learn.microsoft.com/cli/azure/install-azure-cli).
- Go, at the version in `go.mod`'s toolchain line, which fetches `azidentity` for the tests.

## 1. Sign in

```bash
az login
az account show --query "{subscription:name, tenant:tenantId, user:user.name}" -o table
```

If the subscription isn't the one you want, run `az account set --subscription "<name or id>"`.

## 2. Create a test vault

Use a vault only for tests, never one that protects real data. Vault names are globally unique:
3 to 24 letters, digits and hyphens.

```bash
rg=hkdfguard-test-rg
vault=<key vault name>
loc=eastus2

az group create --name $rg --location $loc
az keyvault create --name $vault --resource-group $rg --location $loc \
  --enable-rbac-authorization true --retention-days 7
```

Purge protection is left off so the test vault can be deleted completely afterwards. A vault that
protects real data should have it on; see
[Wrap keys with Azure Key Vault](use-azure-key-vault.md#1-create-the-keys).

## 3. Give yourself access

Creating keys and running the tests both need Key Vault's crypto operations. Assign yourself
**Key Vault Crypto Officer** on the test vault:

```bash
me=$(az ad signed-in-user show --query id -o tsv)
vaultId=$(az keyvault show --name $vault --query id -o tsv)

az role assignment create --assignee $me --role "Key Vault Crypto Officer" --scope $vaultId
```

A role assignment takes a minute or two to apply.

> **Security:** Crypto Officer includes `sign`, which is fine for your own test identity on a test
> vault. A deployed application must never have `sign` on the signing key; see the role table in
> [Wrap keys with Azure Key Vault](use-azure-key-vault.md#2-grant-each-identity-only-what-it-calls).

## 4. Create the two keys

An RSA key to wrap, and an EC P-256 key to sign, each allowed only its own two operations:

```bash
az keyvault key create --vault-name $vault --name hkdfguard-test-wrap --kty RSA --size 2048 --ops wrapKey unwrapKey
az keyvault key create --vault-name $vault --name hkdfguard-test-sign --kty EC --curve P-256 --ops sign verify
```

If either fails with `Forbidden`, the role from step 3 hasn't applied yet; wait a minute and run it
again.

Check the identifiers before running the tests:

```bash
az keyvault key show --id "https://$vault.vault.azure.net/keys/hkdfguard-test-wrap" --query "key.kty" -o tsv
az keyvault key show --id "https://$vault.vault.azure.net/keys/hkdfguard-test-sign" --query "key.crv" -o tsv
```

The first must print `RSA`, the second `P-256`.

## 5. Fill in azure.test.properties

The tests read the two key identifiers as `HKDFGUARD_TEST_AZURE_WRAP_KEY_ID` and
`HKDFGUARD_TEST_AZURE_SIGN_KEY_ID`. Rather than set them for every command, create
`azure.test.properties` in the repository root, next to the root `go.mod` - this repository's
counterpart of hkdfguard-dotnet's `azure.runsettings`, and the same file hkdfguard-java,
hkdfguard-python and hkdfguard-node read:

```properties
# The RSA key that wraps DEKs: its key identifier without a version.
HKDFGUARD_TEST_AZURE_WRAP_KEY_ID=https://<key vault name>.vault.azure.net/keys/hkdfguard-test-wrap

# The EC P-256 key that signs wrapped DEKs: its key identifier without a version.
HKDFGUARD_TEST_AZURE_SIGN_KEY_ID=https://<key vault name>.vault.azure.net/keys/hkdfguard-test-sign
```

Replace `<key vault name>`, brackets included, with the name from step 2. If you already have
another port's `azure.test.properties`, copy it as it is.

- **Leave the version off.** The wrapper then uses each key's current version, as it would in
  production.
- **No credentials go in the file.** `DefaultAzureCredential` signs in with your `az login`.
- **The file stays on your machine.** `.gitignore` excludes `*.test.properties`.
- **An environment variable of the same name wins.** Set one for a single command, or on a CI runner,
  to override the file, or to run the tests without it.

## 6. Run the tests

From `keywrapping/azurekeyvault`:

```bash
go test -count=1 -run TestAzureKeyVaultIntegration -v ./...
```

Leave out `-run TestAzureKeyVaultIntegration` to run the module's whole suite, the integration tests
included; `scripts/check.sh` runs them too when the keys are configured.

Without the file, set both variables for the one command instead, in Git Bash, macOS or Linux:

```bash
HKDFGUARD_TEST_AZURE_WRAP_KEY_ID=https://$vault.vault.azure.net/keys/hkdfguard-test-wrap \
HKDFGUARD_TEST_AZURE_SIGN_KEY_ID=https://$vault.vault.azure.net/keys/hkdfguard-test-sign \
go test -count=1 -run TestAzureKeyVaultIntegration -v ./...
```

Every test should pass with none skipped:

```text
--- PASS: TestAzureKeyVaultIntegration_RoundTripsA32ByteDEKThroughWrapAndUnwrap
--- PASS: TestAzureKeyVaultIntegration_GeneratesAWrappedDEKThatReveals
--- PASS: TestAzureKeyVaultIntegration_RefusesToUnwrapUnderAnotherContext
--- PASS: TestAzureKeyVaultIntegration_RefusesToUnwrapATamperedDEK
```

Without the keys, each is reported as skipped, with the reason:

```text
--- SKIP: TestAzureKeyVaultIntegration_RoundTripsA32ByteDEKThroughWrapAndUnwrap (0.00s)
```

`go test` runs a package's tests in its own directory, so the tests find `azure.test.properties` two
directories up, in the repository root. `DefaultAzureCredential` may sign in with an environment or
managed-identity credential before `az login`'s: make sure it signs in to the same account.

On a CI runner, set the two variables in the job and sign in with a federated identity (for
example GitHub's OIDC provider and `azure/login`) rather than storing a client secret.

## If something goes wrong

| You see | Cause | Fix |
|---|---|---|
| Every test reported as skipped | Neither `azure.test.properties` nor the environment names both keys | Step 5: the file must be in the repository root, next to the root `go.mod` |
| `... isn't a key identifier` | A placeholder is still in the file or a variable | Step 5 |
| `Forbidden (HTTP 403)` | The role assignment hasn't applied, or is on another vault | Wait; check with `az role assignment list --assignee $me --scope $vaultId -o table` |
| `KeyNotFound (HTTP 404)` | A vault or key name is wrong | Step 4's check commands |
| `DefaultAzureCredential: failed to acquire a token`, or a tenant error | `DefaultAzureCredential` found no sign-in, or picked an account in another tenant | `az login` again, or set `AZURE_TENANT_ID` for the command |
| `The signing key must be an EC P-256 key`, or `Forbidden (HTTP 403)` on a freshly granted role | The two identifiers are swapped, or the signing key is another curve | Step 4's check commands |

## When you're done

Delete the resource group, then purge the vault so its name can be reused:

```bash
az group delete --name $rg --yes
az keyvault purge --name $vault --location $loc
```

Until it's purged, a deleted vault is kept for its 7-day retention period, at no cost.
