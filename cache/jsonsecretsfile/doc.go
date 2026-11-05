// Package jsonsecretsfile implements a hkdfguard.ProtectedReadOnlyCache over one JSON file holding
// every secret - the Go port of the .NET JsonSecretsFileReadOnlyCache. The file is what a
// pipeline's hkdfguard.SecretPipelineWriter writes with WriteJSONSecrets (or WriteJSONSecretsTo): a
// single object whose members map each secret's name to its value, already encrypted under the key
// ring and formatted (enc::v{version}::{base64}). Nothing is read up front: the first lookup reads
// the whole file, authenticates every value in it, and keeps them - still encrypted, exactly as the
// file holds them - so every later lookup is served from memory without touching the disk.
//
//	deployers := securefile.NewKeyFileTrust(securefile.KeyFileTrustOptions{UnixUserIDs: []uint32{1005}})
//	secrets, err := jsonsecretsfile.New("/etc/myapp/secrets.json", deployers, ring, dek.NewDefaultFormatProvider(), jsonsecretsfile.Options{})
//	if err != nil { ... }
//	n, err := secrets.Decrypt(ctx, "Db-Password", buffer) // 0 if the file holds no such secret
//
// # The file is read through securefile
//
// The file is read with securefile.ReadTrustedFile, and refused - with a *securefile.KeyFileError
// matching securefile.ErrUntrusted and fs.ErrPermission, and nothing kept - unless it and every
// folder above it are owned, and modifiable, only by the operating system's administrators and the
// principals the securefile.KeyFileTrust adds, with no untrusted symbolic link on the way. Add the
// account that deploys secrets, never the one the application runs as.
//
// # Every value is bound to its name
//
// A member's value must be encrypted for the purpose hkdfguard.ConfigurationPurpose(name) - as a
// hkdfguard.PipelineDataProtector's Encrypt(ctx, value, name) writes it - and a value moved under
// any other name fails authentication. The file is delivered as one, so it is loaded as one: a
// value that fails authentication (hkdfguard.ErrAuthenticationFailed), names a key version the ring
// doesn't hold (hkdfguard.ErrKeyNotFound) or isn't in the format provider's form (the provider's
// error, dek.ErrInvalidFormat) fails the whole load, and nothing is kept, so the file is read again
// on the next lookup.
//
// # The file, names and missing secrets
//
// The file must be exactly that object - one member per secret, each name a valid
// cache/filepersecret name (filepersecret.IsValidName), no name twice ignoring case, each value a
// non-empty string - or it is refused with an error matching ErrInvalidData. Names are looked up
// ignoring ASCII case, as the values are bound; any name that couldn't be one is reported missing -
// Decrypt returns 0 - so the cache can sit in a cache.Collection beside sources with other naming
// rules. A missing file, or a missing folder above it, reports every secret missing, and isn't
// remembered: it is looked for again on the next lookup. A file longer than Options.MaxFileLength
// is refused with an error matching securefile.ErrTooLarge, reading no more than one byte past it;
// any other failure to read it is returned as securefile reports it. One load runs at a time: a
// lookup made while the file is loaded waits for it, or for its ctx to end.
//
// The values loaded are kept for the life of the cache: a file changed after it was loaded is
// picked up by a new cache. Each value decrypts with the key version it names, so it keeps
// decrypting after a key rotation for as long as the ring holds that version.
//
// # Telemetry
//
// Each load of the file is a diagnostics.SpanCachePopulate span on diagnostics.Cache, counted in
// diagnostics.CacheOperations as ResultSuccess, ResultNotFound or ResultError; with sensitive
// logging on, the file's path and each looked-up name (never a value) are logged.
//
// It is a module of its own (github.com/runsecure/hkdfguard-go/cache/jsonsecretsfile) because it
// reads through securefile, and follows cache/filepersecret's name rule - modules of their own that
// depend on the root module.
package jsonsecretsfile
