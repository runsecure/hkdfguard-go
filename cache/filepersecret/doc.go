// Package filepersecret implements a hkdfguard.ProtectedReadOnlyCache over a folder on the local
// filesystem holding one file per secret - the Go port of the .NET FilePerSecretCache. The file
// named name holds that secret's value, already encrypted under the key ring and formatted
// (enc::v{version}::{base64}). Nothing is read up front: the first lookup of a name reads that one
// file, authenticates its value, and caches it - still encrypted, exactly as the file holds it - so
// every later lookup is served from memory without touching the disk. Surrounding whitespace in a
// file, such as a trailing newline, is ignored.
//
//	deployers := securefile.NewKeyFileTrust(securefile.KeyFileTrustOptions{WindowsPrincipals: []string{"S-1-5-21-...-1005"}})
//	secrets, err := filepersecret.New(`C:\HkdfGuardSecrets\myapp`, deployers, ring, dek.NewDefaultFormatProvider(), filepersecret.Options{})
//	if err != nil { ... }
//	n, err := secrets.Decrypt(ctx, "Db-Password", buffer) // 0 if there's no such file
//
// # Every file is read through securefile
//
// Each file is read with securefile.ReadTrustedFile, and refused - with a *securefile.KeyFileError
// matching securefile.ErrUntrusted and fs.ErrPermission, and not cached - unless it and every
// folder above it are owned, and modifiable, only by the operating system's administrators and the
// principals the securefile.KeyFileTrust adds, with no untrusted symbolic link on the way. Add the
// account that deploys secrets, never the one the application runs as: one that can rewrite its own
// secrets can be made to roll one back.
//
// # Every value is bound to its name
//
// A file's value must be encrypted for the purpose hkdfguard.ConfigurationPurpose(name) - as a
// hkdfguard.PipelineDataProtector's Encrypt(ctx, value, name), or
// ring.CreateProtector(hkdfguard.ConfigurationPurpose(name)), writes it - and a file copied under any
// other name fails authentication (hkdfguard.ErrAuthenticationFailed) when it is loaded, rather than
// decrypting as that name's value. A file that fails is not cached, so it is read again on the next
// lookup.
//
// # Names, missing secrets and failures
//
// A name is a file name: 1-MaxNameLength ASCII letters, digits, '-', '_' and '.', neither starting
// nor ending with '.', and not a name Windows reserves for a device such as NUL or COM1 (see
// IsValidName), so it can never reach outside the folder or name a file Windows would open as
// another. Any other name, a missing file, a missing folder and an empty file are all reported
// missing - Decrypt returns 0 - so the cache can sit in a cache.Collection beside sources with other
// naming rules. A missing secret isn't remembered: its file is looked for again on the next lookup.
// Names are matched exactly in the cache, and files are found as the filesystem finds them: exactly
// on Linux, ignoring case on Windows and, by default, macOS. A file longer than MaxFileLength bytes
// is refused with an error
// matching securefile.ErrTooLarge, reading no more than one byte past that; a value that isn't in
// the format provider's form fails with the provider's error (dek.ErrInvalidFormat), and one under
// a key version the ring doesn't hold with hkdfguard.ErrKeyNotFound. Any other failure to read a
// file is returned as securefile reports it, and nothing is cached.
//
// A cached value is kept for the life of the cache: a file changed after its secret was loaded is
// picked up by a new cache. Each value decrypts with the key version it names, so it keeps
// decrypting after a key rotation for as long as the ring holds that version.
//
// # Telemetry
//
// Each file load is a diagnostics.SpanCachePopulate span on diagnostics.Cache, counted in
// diagnostics.CacheOperations as ResultSuccess, ResultNotFound or ResultError; with sensitive
// logging on, the secret's name (never a value) is logged.
//
// It is a module of its own (github.com/runsecure/hkdfguard-go/cache/filepersecret) because it reads
// through securefile, which is a module that depends on the root module the cache package is in.
package filepersecret
