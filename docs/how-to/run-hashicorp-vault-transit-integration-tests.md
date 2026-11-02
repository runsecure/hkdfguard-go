# Run the HashiCorp Vault transit integration tests

`integration_test.go` in `keywrapping/hashicorpvault` makes real calls to a Vault transit secrets
engine through `hashicorpvault.KeyWrapper`. This page runs a Vault dev server in Docker, provisions
two transit keys and a token that may use only them, and runs the tests from the command line.

The module's other tests use a fake transit engine, an HTTP server on the loopback address called
through a real `*api.Client`, and run without any of this. The integration tests are reported as
**skipped**, never passed, until a key is configured.

They check that:

- a DEK survives a wrap and unwrap round trip;
- `GenerateAndWrap` produces a wrapped DEK that reveals to 32 non-zero bytes, both generated in
  Vault (no context) and generated locally and encrypted (with one);
- a DEK wrapped under one context is refused under another, and under none;
- a DEK wrapped under one key is refused by another;
- a tampered wrapped DEK, and an invalid token, are refused.

The tests never create, rotate, read or delete a key.

If you already run hkdfguard-dotnet's Vault transit integration tests, you have a server, keys and a
token: skip to [step 3](#3-point-the-tests-at-the-key) and use the same values.

## What you need

- Docker.
- Git Bash (on Windows) or any bash with `curl`, for the provisioning script.
- The Go toolchain named in `go.mod`.

## 1. Start a Vault dev server

```bash
docker run -d --name hkdfguard-vault --cap-add=IPC_LOCK -p 127.0.0.1:8200:8200 hashicorp/vault:1.19.0
```

The image's default command is `server -dev`: unsealed, in memory, listening on plain http. Bind it
to `127.0.0.1` as above, never to every interface. The wrapper allows http only on a loopback
address.

Read the root token the server printed:

```bash
docker logs hkdfguard-vault 2>&1 | grep 'Root Token:'
```

A dev server keeps everything in memory, so a restarted container starts empty, with a new root
token. Repeat step 2 after every restart.

> The Vault cache's integration tests can use the same server; they read the same
> `HKDFGUARD_TEST_VAULT_ADDR`, `HKDFGUARD_TEST_VAULT_TOKEN` and `HKDFGUARD_TEST_VAULT_CACERT`, but
> need a token that can read their KV secret.

## 2. Provision the keys and a token

From the repository root:

```bash
VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=<root token> scripts/provision-vault-transit-test-key.sh
```

The script uses the root token only to provision. It:

1. enables a transit engine at `transit` if nothing is mounted there;
2. creates two `aes256-gcm96` keys, `hkdfguard-test` and `hkdfguard-test-other`;
3. writes the policy `hkdfguard-transit-test`, granting `update` (not `create`) on `encrypt`,
   `decrypt` and `datakey/wrapped` for those two keys only;
4. creates a 24-hour token with only that policy, and prints it.

So the tests run with what a real application would get, not root: they can't create a key by
naming one that doesn't exist, list keys, or touch anything else. Re-running the script is safe; it
keeps the keys and prints a new token.

Point the script only at a dev server. If yours was started with `-dev-tls`, set `VAULT_CACERT` to
its CA first, and use https below.

## 3. Point the tests at the key

The tests read these variables from the environment. All but the token can instead go in
`vault.test.properties` in the repository root, next to the root `go.mod` - this repository's
counterpart of hkdfguard-dotnet's `vault.runsettings`:

```properties
# The dev server and the transit keys scripts/provision-vault-transit-test-key.sh created.
HKDFGUARD_TEST_VAULT_ADDR=http://127.0.0.1:8200
HKDFGUARD_TEST_VAULT_TRANSIT_KEY=hkdfguard-test
HKDFGUARD_TEST_VAULT_TRANSIT_OTHER_KEY=hkdfguard-test-other
```

| Variable | Needed | Meaning |
|---|---|---|
| `HKDFGUARD_TEST_VAULT_TRANSIT_KEY` | Yes | The transit key to wrap under; without it every test is skipped |
| `HKDFGUARD_TEST_VAULT_TOKEN` | Yes | A token allowed `update` on that key's `encrypt`, `decrypt` and `datakey/wrapped`. **Environment only**: never read from the file |
| `HKDFGUARD_TEST_VAULT_ADDR` | No | Vault's address; default `http://127.0.0.1:8200` |
| `HKDFGUARD_TEST_VAULT_TRANSIT_OTHER_KEY` | No | A second key, for the cross-key test; that test is skipped without it |
| `HKDFGUARD_TEST_VAULT_TRANSIT_MOUNT` | No | The transit mount; default `transit` |
| `HKDFGUARD_TEST_VAULT_CACERT` | No | The full path of a CA to trust, for a server started with TLS |

- **The token stays out of the file**, which names the server and keys only. Set it for the one
  command, as below.
- **The file stays on your machine.** `.gitignore` excludes `*.test.properties`.
- **An environment variable of the same name wins** over the file.
- **The client's own variables also apply.** The tests make their client with `api.DefaultConfig()`,
  as an application would, so `VAULT_NAMESPACE`, `VAULT_CLIENT_TIMEOUT` and the like in your shell
  change it; the address, CA and token above override `VAULT_ADDR`, `VAULT_CACERT` and
  `VAULT_TOKEN`.

## 4. Run the tests

From `keywrapping/hashicorpvault`, in Git Bash, macOS or Linux:

```bash
HKDFGUARD_TEST_VAULT_TOKEN=<token the script printed> go test -run TestVaultTransitIntegration -v ./...
```

Without the file, set every variable for the one command instead:

```bash
HKDFGUARD_TEST_VAULT_ADDR=http://127.0.0.1:8200 HKDFGUARD_TEST_VAULT_TOKEN=<token the script printed> \
HKDFGUARD_TEST_VAULT_TRANSIT_KEY=hkdfguard-test HKDFGUARD_TEST_VAULT_TRANSIT_OTHER_KEY=hkdfguard-test-other \
go test -run TestVaultTransitIntegration -v ./...
```

In PowerShell, set the token for the session, then run:

```powershell
$env:HKDFGUARD_TEST_VAULT_TOKEN = '<token the script printed>'
go test -run TestVaultTransitIntegration -v ./...
```

Every test should pass with none skipped:

```text
--- PASS: TestVaultTransitIntegration_RoundTripsA32ByteDEKThroughWrapAndUnwrap
--- PASS: TestVaultTransitIntegration_GeneratesInVaultAWrappedDEKThatReveals
--- PASS: TestVaultTransitIntegration_GeneratesWithAContextAWrappedDEKThatReveals
--- PASS: TestVaultTransitIntegration_RefusesToUnwrapUnderAnotherContextOrNone
--- PASS: TestVaultTransitIntegration_RefusesToUnwrapATamperedDEK
--- PASS: TestVaultTransitIntegration_RefusesToUnwrapUnderAnotherKey
--- PASS: TestVaultTransitIntegration_RefusesAnInvalidTokenWith403
```

`go test` runs each package in its own directory, so the tests find `vault.test.properties` two
directories above `keywrapping/hashicorpvault`.

On a CI runner, start the same container as a service, run the provisioning script with the root
token you gave it (`-e VAULT_DEV_ROOT_TOKEN_ID=...`), and pass the printed token to the test step
as `HKDFGUARD_TEST_VAULT_TOKEN`.

## If something goes wrong

| You see | Cause | Fix |
|---|---|---|
| `--- SKIP` with `Set HKDFGUARD_TEST_VAULT_TRANSIT_KEY ...` | Neither the environment nor `vault.test.properties` names the key | Step 3: the file must be in the repository root, next to the root `go.mod` |
| `--- SKIP` with `Set HKDFGUARD_TEST_VAULT_TRANSIT_OTHER_KEY ...` | The second key isn't named | Set it to `hkdfguard-test-other` |
| `HKDFGUARD_TEST_VAULT_TRANSIT_KEY is set, but HKDFGUARD_TEST_VAULT_TOKEN isn't` | The token isn't in the environment (it is never read from the file) | Step 4 |
| `403 Forbidden` ... `permission denied` | The token expired (24 hours), or the container restarted and the token is gone | Step 2 again, with the new token |
| `400 Bad Request` ... `encryption key not found` | The container restarted and the keys are gone, or the key name is wrong | Step 2 again |
| `connection refused`, or `no answer within the client's timeout` | The container isn't running, or isn't on `127.0.0.1:8200` | `docker ps`; `docker start hkdfguard-vault`, then step 2 |
| `must be https` | The address isn't loopback and isn't https | Use `127.0.0.1`, or https with `HKDFGUARD_TEST_VAULT_CACERT` |

## When you're done

```bash
docker rm -f hkdfguard-vault
```

Nothing survives: the server kept its keys, policy and tokens in memory.
