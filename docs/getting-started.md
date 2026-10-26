# Getting started

This tutorial takes one machine from nothing to encrypting and decrypting with a key protected by
the platform: the TPM on Windows, the Secure Enclave on a Mac. It then replaces that in-memory key
with a durable key file, which is what a real deployment uses.

It takes about 20 minutes. You need one of:

- Windows 10 or 11, or Windows Server 2019 or later, with administrator rights for one step.
- macOS 13 or later on Apple silicon, with the Xcode Command Line Tools (`xcode-select --install`):
  the native key wrapper is loaded through cgo, so a C compiler is needed to build it.

And, on either:

- Go 1.25 or later. The modules name Go 1.27.2 in their `toolchain` directive, so `go` downloads
  it on first use.
- The HkdfGuard native package for your platform.

Linux works the same way with its own paths and a TPM-backed KEK; see the
[CLI reference](reference/cli.md#linux) for what is published so far.

## How the pieces fit

HkdfGuard never holds your master key. There are two keys:

- The **KEK** (key-encryption key) lives in the TPM, or in the Secure Enclave on a Mac. It never
  leaves it. Each KEK is identified by a **service name**, such as `com.example.myapp`.
- A **DEK** (data encryption key) is what actually encrypts your data, with AES-256-GCM. On disk
  it exists only *wrapped*, encrypted under the KEK. Your process asks the native library to unwrap
  it at startup and holds it in a buffer that is zeroed when you're done. Go's AES implementation
  keeps its own expanded copy of the key, which can't be zeroed (see the `aesgcm256` package
  documentation).

Two separate things are installed:

| Part | Where it comes from | What it does |
|---|---|---|
| The Go modules | `go get github.com/runsecure/hkdfguard-go`, `.../cryptoprovider/aesgcm256` and `.../keywrapping/nativev1` | Everything your code calls |
| The native library and its `hkdfguard` tool | The HkdfGuard native package: `%ProgramFiles%\HkdfGuard\v1` on Windows, `/Library/Application Support/HkdfGuard/v1` (or `~/.hkdfguard/v1`) on macOS | Hold and use the KEK |

The Go library loads the native library only from that location, and only after checking the
folder's ownership and permissions and the library's code signature. It never searches `PATH`,
`LD_LIBRARY_PATH`, `DYLD_LIBRARY_PATH` or your application folder.

## 1. Install the native package

**Windows:** run the HkdfGuard installer as an administrator.

> **TODO (maintainer):** give the installer's file name and where to download it, and say whether
> it creates the `HkdfGuardUsers` group.

Check that it installed:

```powershell
Get-AuthenticodeSignature "$env:ProgramFiles\HkdfGuard\v1\HkdfGuard.dll" | Select-Object Status, SignerCertificate
```

`Status` must be `Valid`. When it loads the library, `nativev1` also checks whether the signing
certificate has been revoked, fetching revocation data if the host can reach it. Only a definite
revocation stops the load; an offline host still starts.

**macOS:** install the native package system-wide, to `/Library/Application Support/HkdfGuard/v1`.
(A per-user install at `~/.hkdfguard/v1` is also loaded, but only when there is no system-wide
one. Its home folder is your account's, from the account database; setting `$HOME` doesn't move
it. Either install must be version 0.9.0 or later.)

> **TODO (maintainer):** give the package's file name and where to download it.

Check that it installed, with the same requirement the library applies when it loads:

```sh
codesign --verify --strict \
  -R='identifier "libhkdfguard" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = "MFW3T8R8J3"' \
  "/Library/Application Support/HkdfGuard/v1/libhkdfguard.dylib" && echo OK
```

## 2. Provision a KEK for your service

Choose a service name. It is 1 to 128 ASCII letters, digits or dots, doesn't start with a dot,
and never contains `..`. Reverse-DNS style works well: `com.example.myapp`. Hyphens are not
allowed.

**Windows:** open PowerShell **as administrator** and run:

```powershell
& "$env:ProgramFiles\HkdfGuard\v1\hkdfguard.exe" provision --service-name com.example.myapp
```

This creates the KEK in the TPM. Running it again is safe: if the KEK already exists, the command
only checks that its properties and access list are still correct.

Then let the account your application runs as use the KEK by adding it to the `HkdfGuardUsers`
group:

```powershell
Add-LocalGroupMember -Group HkdfGuardUsers -Member "$env:USERDOMAIN\$env:USERNAME"
```

Sign out and back in, so your session picks up the new group.

> **Security:** add only the accounts that run your application. Any member of the group can use
> every KEK the group is allowed to use.

**macOS:** run, as the account your application will run as (not with `sudo`):

```sh
"/Library/Application Support/HkdfGuard/v1/hkdfguard" provision --service-name com.example.myapp
```

This creates the KEK in the Secure Enclave and prints its **fingerprint**: record it, `wrap` and
`retire` can be told to insist on it. Running it again is safe. The KEK's keychain item is created
in that account's login keychain, so provision as the account that will use it.

> **Security:** in this mode the keychain item's access list names the binary that created it, the
> tool. The first time any other binary - your application, after each rebuild - uses the KEK in a
> logged-in session, macOS asks whether to allow it; choose **Always Allow**. In a session with no
> UI (ssh, a launch daemon outside a login session), the library reports status -17 instead. Run
> unattended consumers as a LaunchAgent inside a logged-in session.

## 3. Encrypt and decrypt with an in-memory key

Create a program and add the modules:

```sh
mkdir hkdfguarddemo && cd hkdfguarddemo
go mod init hkdfguarddemo
go get github.com/runsecure/hkdfguard-go github.com/runsecure/hkdfguard-go/cryptoprovider/aesgcm256 github.com/runsecure/hkdfguard-go/keywrapping/nativev1
```

> **TODO (maintainer):** confirm these module paths resolve once the modules are tagged. Until
> then, add `replace` directives pointing at a checkout of `hkdfguard-go` (the root, and the two
> nested module directories).

Write `main.go`:

```go
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/cryptoprovider/aesgcm256"
	"github.com/runsecure/hkdfguard-go/dek"
	"github.com/runsecure/hkdfguard-go/keywrapping/nativev1"
)

func main() {
	ctx := context.Background()

	wrapper, err := nativev1.New("com.example.myapp")
	if err != nil {
		log.Fatal(err)
	}
	ring, err := dek.Build(ctx, dek.Config{
		KeyWrapper:            wrapper,
		CryptoProviderFactory: aesgcm256.NewFactory(),
		KeyRefreshInterval:    60 * time.Second,
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
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(encrypted)

	size, err := protector.MaxDecryptedLength(ctx, encrypted)
	if err != nil {
		log.Fatal(err)
	}
	buffer := make([]byte, size)
	defer hkdfguard.Wipe(buffer)
	n, err := protector.Decrypt(ctx, encrypted, buffer)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", buffer[:n])
}
```

Run it with `go run .` on Windows, or `CGO_ENABLED=1 go run .` on macOS. You should see something
like:

```text
enc::v1::35zt4fIdLUCinFy3S6/8N1yf53CaMBiU+eRmC2PyVVIJV+LwFzm7Q3xf2sU/JmatNCgp
The launch code is 0000
```

What happened:

- `dek.Build` asked the native library to generate a fresh DEK and wrap it under your KEK. It then
  unwrapped it into a buffer the library zeroes when the ring is closed, apart from the expanded
  copy Go's AES implementation keeps. The plaintext DEK was never
  on disk.
- `enc::v1::...` is the stored form: `v1` is the key version, and the rest is the AES-GCM
  ciphertext in base64. It is the same format the .NET libraries write and read.
- `"customer-notes"` is the protector's **purpose**. It is bound into every value, so a value
  encrypted by one protector never decrypts under a protector with another name.
- `KeyRefreshInterval: 60 * time.Second` makes the library re-check the KEK every 60 seconds. If
  the KEK stops being available (it was deleted, or your account lost access), encryption and
  decryption stop after three failed checks, about three minutes, until access returns. That is
  the default `RefreshFailurePolicy`; `hkdfguard.FailOpen()` keeps the last good key instead.
  The interval is also each check's deadline: a check that takes longer counts as failed, so
  don't go below about 10 seconds on a TPM, which can be slow to answer when it is busy.
- Plaintext travels as `[]byte`, never as a `string`, so it can be zeroed: `hkdfguard.Wipe`
  clears the buffer when you are done, and `Encrypt` zeroes what it was given.

**The catch:** an ephemeral key exists only in this process. Run the program again and the first
value can't be decrypted, because that key is gone. That's right for short-lived data such as
session tokens. Data you store needs a key file.

## 4. Understand key files

A **key file** holds one wrapped DEK. It is useless without the KEK, so it is not a secret in the
usual sense, but its permissions still matter. Anyone who can replace it controls the key your
application encrypts new data with. So the Go library reads every key file through the native
library (`hkdfguard_open_file`), which refuses:

- a file, or a folder above it, that an untrusted account could write or replace. Trusted are
  root or SYSTEM, Administrators and TrustedInstaller, and the deployers (Windows and Linux) or the
  reading account (macOS); under the developer security model, the reading account everywhere. and a path through a
  symbolic link, junction or other reparse point, an 8.3 short name (`PROGRA~1`), or a network,
  mapped or SUBST drive - a folder created directly under `C:\` inherits "Authenticated Users:
  Modify" and is refused until its permissions are narrowed;
- a file holding what looks like an *unwrapped* key - 32 raw bytes, or 64 hex digits, or base64,
  with or without surrounding whitespace. Treat that as a key exposure: the key is compromised;
- a file of the wrong size, or the right size but not a valid wrapped key.

Each refusal is a `*nativev1.KeyFileError` naming the file, the status and what it means. The file
comes back still wrapped: reading it opens no KEK.

You create a key file once per release, or per key rotation, with the tool's `wrap` command
(`hkdfguard wrap`).
The tool reads the DEK on standard input, wraps it under the service's KEK, and writes the file
with restricted permissions. On Windows its `--group` option names the local group whose members
can read the file.

> **TODO (maintainer):** describe the exact permissions `wrap` puts on the key file on each
> platform, and whether `wrap` must run elevated on Windows.

Where does the DEK come from? In a deployment pipeline, use `aesgcm256.PipelineDataProtector`. It
generates a key in memory and can encrypt your configuration secrets under it. At the end of the
pipeline you pass that same key to `wrap`. This tutorial skips the configuration secrets and only
creates the file.

## 5. Create a key file

Add this function to your program. It generates a DEK, passes it to `wrap` on standard input, and
zeroes every copy it controls:

```go
import (
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/runsecure/hkdfguard-go/cryptoprovider/aesgcm256"
	"github.com/runsecure/hkdfguard-go/dek"
)

// createKeyFile generates a DEK, passes it to the tool's wrap command on standard input, and
// zeroes every copy it controls. group is the local group allowed to read the key file (Windows
// requires it; leave it empty elsewhere).
func createKeyFile(toolPath, serviceName, keyFilePath, group string) error {
	// The pipeline protector generates the DEK in memory; Close zeroes it and its base64 form.
	protector, err := aesgcm256.NewPipelineDataProtector(dek.NewDefaultFormatProvider(), 1)
	if err != nil {
		return err
	}
	defer protector.Close()

	args := []string{"wrap", "--service-name", serviceName, "--key-file-path", keyFilePath, "--dek-stdin"}
	if group != "" {
		args = append(args, "--group", group)
	}
	tool := exec.Command(toolPath, args...)
	tool.Stdout, tool.Stderr = os.Stdout, os.Stderr
	stdin, err := tool.StdinPipe()
	if err != nil {
		return err
	}
	if err := tool.Start(); err != nil {
		return err
	}

	// The key crosses to the tool as bytes from the protector's own buffer, never through a string.
	_, writeErr := stdin.Write(protector.KeyBase64())
	closeErr := stdin.Close()
	if err := tool.Wait(); err != nil {
		return fmt.Errorf("hkdfguard wrap: %w", err)
	}
	return errors.Join(writeErr, closeErr)
}
```

Before you call it on Windows, prepare the folder it writes to. The native library refuses a key
file anywhere under `C:\ProgramData`, where every user may create entries, and in a folder created
directly under `C:\` with its default permissions. From an elevated PowerShell, give the key files
a folder of their own, with inherited permissions removed:

```powershell
New-Item -ItemType Directory -Force C:\HkdfGuardKeys\myapp | Out-Null
icacls C:\HkdfGuardKeys /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX" "HkdfGuardDeployers:(OI)(CI)M"
icacls C:\HkdfGuardKeys /setowner "*S-1-5-32-544" /T
```

Then make the call from an elevated prompt, or as a member of `HkdfGuardDeployers`. Under the
production security model, the Windows default, `wrap` refuses any other account, and the library
doesn't trust a key file that the application's own account wrote. The native library's
[administration guide](https://github.com/runsecure/hkdfguard-native-windows/blob/main/docs/admin-guide.md#where-to-keep-key-files)
explains both rules.

Call it once. On Windows:

```go
err := createKeyFile(
	filepath.Join(os.Getenv("ProgramFiles"), `HkdfGuard\v1\hkdfguard.exe`),
	"com.example.myapp",
	`C:\HkdfGuardKeys\myapp\v1.key`,
	"HkdfGuardUsers")
```

On macOS, as the account that provisioned the KEK, after creating the folder with
`mkdir -p -m 0700 ~/Library/Application\ Support/MyApp/keys` (the native library trusts a key
file in a folder owned by you or root that no one else can write):

```go
err := createKeyFile(
	"/Library/Application Support/HkdfGuard/v1/hkdfguard",
	"com.example.myapp",
	filepath.Join(os.Getenv("HOME"), "Library/Application Support/MyApp/keys/v1.key"),
	"")
```

> **Security:** pass the DEK on standard input, as above. Never pass it as a command-line argument
> or an environment variable: process listings, shell history, CI logs and crash dumps record
> those. Don't build it in a PowerShell or Bash variable either, and never convert
> `KeyBase64()` to a Go `string`. Those can't be cleared from memory.

## 6. Use the key file

Replace `EphemeralKeys` with `KeyFiles`:

```go
ring, err := dek.Build(ctx, dek.Config{
	KeyWrapper:            wrapper,
	CryptoProviderFactory: aesgcm256.NewFactory(),
	KeyRefreshInterval:    60 * time.Second,
	KeyFiles:              map[int]string{1: keyFilePath},
})
```

Now values survive a restart: encrypt, run the program again, and decrypt the earlier value.

The map key you give `KeyFiles` is the version that appears as `v1` in every value. When you
rotate, add a `v2.key` as `KeyFiles: map[int]string{1: v1Path, 2: v2Path}`. New values use the
highest version, and older values still decrypt as long as their key file stays registered.

> This step makes the key file the key your program encrypts with, so you can watch a value survive
> a restart. In an application, key files hold what your deployment pipeline encrypted, and are
> read at runtime to decrypt it. For values the application encrypts while it runs, add an
> ephemeral key at a higher version (`EphemeralKeys: []int{2}`): its encryption budget is counted exactly, in the one
> process that holds it. See the README's encryption budget section.

The same settings can come from a file shared with the .NET port: `dek.OptionsFromJSON` reads the
`HkdfGuard` section of an `appsettings.json`, with the same field names (`ServiceName`,
`KeyRefreshInterval`, `KeyFiles`, `EphemeralKeys`, ...), and `Options.Config` turns it into the
`dek.Config` above.

## If something goes wrong

Every error wraps a sentinel you can test with `errors.Is`, and a failed native call is a
`*nativev1.StatusError` (`errors.As`) whose message includes the status code and its meaning. A
key file the native library refused is a `*nativev1.KeyFileError` instead. The status codes are
the same on Windows, Linux and macOS.

| You see | Cause | Fix |
|---|---|---|
| `nativev1.ErrNotInstalled` | The native package isn't installed at its fixed location | Step 1 |
| `nativev1.ErrUntrusted` | The installed library, or a folder above it, failed verification: wrong signature, writable by non-administrators, or (macOS) a `DYLD_LIBRARY_PATH` entry shadows it, or `DYLD_INSERT_LIBRARIES` or another dyld variable that injects or substitutes code is set | Reinstall the native package; don't change that folder's permissions; clear the linker variables |
| `nativev1.ErrUnsupportedPlatform` | Built with `CGO_ENABLED=0` on macOS or Linux, or an Intel Mac / an amd64 binary under Rosetta | Build with `CGO_ENABLED=1` for `darwin/arm64` |
| `StatusError` `-17` | No KEK is provisioned for this service name | Step 2, with the same service name |
| `StatusError` `-18` (Windows) | The KEK exists, but this account may not use it | Add the account to `HkdfGuardUsers`, then sign out and in |
| `StatusError` `-18` (macOS) | The keychain would not answer: locked, no UI session for the access prompt, or the prompt was declined | Run from a logged-in session and choose Always Allow |
| `StatusError` `-16` | The key file was wrapped under a different service's KEK | Use the service name the file was created with |
| `StatusError` `-10`, `-11` or `-12` | The key file was altered (malformed, failed authentication, or an unknown version) | Restore it from your deployment artifacts |
| `hkdfguard.ErrInvalidServiceName` | The name breaks the rule in step 2 | Use letters, digits and dots only |
| `KeyFileError` `-32`, `fs.ErrNotExist` | The key file, or a folder in its path, does not exist | Check the path in `KeyFiles` |
| `KeyFileError` `-33` or `-39`, `fs.ErrPermission` | This account may not read the key file, or the native library doesn't trust its location (a link or junction, a short or network path, or a file or folder another account could replace) | Grant read access; use a real local path in a folder only administrators (and the reading account) can change |
| `KeyFileError` `-37`, `hkdfguard.ErrInvalidKeyFile` | The file holds what looks like an **unwrapped** key | Treat the key as exposed: rotate it, delete the file, and create a key file with `wrap` |
| `KeyFileError` `-35`, `-36` or `-38`, `hkdfguard.ErrInvalidKeyFile` | The key file is the wrong size, or not a valid wrapped key | Recreate it with `wrap` |
| `hkdfguard.ErrKeyAccessSuspended` | The KEK stopped answering for three refreshes in a row | Restore access to the KEK; operations resume on the next successful refresh |

## Next steps

- [`hkdfguard` tool reference](reference/cli.md): every command and option.
- The README's `dek`, `encryptedconfig` and `cache` sections, until their how-to pages are written.
