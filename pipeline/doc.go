// Package pipeline is the shared plumbing of the secret stores' hkdfguard.SecretPipelineWriter
// implementations - the Go port of the .NET HkdfGuard.Pipeline library. A provisioning pipeline
// pulls a fixed list of secrets from a secret store, encrypts each at once with a
// hkdfguard.PipelineDataProtector bound to its file name, keeps only the ciphertext, and writes one
// file per secret - the folder layout cache/filepersecret reads at runtime - or one JSON file of them
// all, the file cache/jsonsecretsfile reads. Either can instead be written to an io.Writer, such as a
// remote command's stdin over ssh: a tar archive of the files, or the JSON. No key ring is involved:
// the protector's key is the only one, handed to the native platform's wrap process once the files
// are written.
//
// A store's writer supplies only a SecretStore - IsValidName and ReadSecret, which reads one secret
// and hands its values to the Secret's Protect methods; New returns the Writer that does everything
// else. The modules pipeline/hashicorpvault, pipeline/awssecretsmanager, pipeline/azurekeyvault and
// pipeline/googlesecretmanager are the stores HkdfGuard ships, and never depend on the runtime
// caches (cache/...):
//
//	protector, err := aesgcm256.NewPipelineDataProtector(dek.NewDefaultFormatProvider(), 3)
//	if err != nil { ... }
//	defer protector.Close()
//	writer, err := awssecretsmanager.New(secretsmanager.NewFromConfig(cfg), protector,
//		[]string{"prod/app#username", "prod/app#password", "prod/api-key"})
//	if err != nil { ... }
//	defer writer.Close()
//	if err := writer.PullSecrets(ctx); err != nil { ... }
//	if err := writer.WriteProtectedSecretFiles(`C:\HkdfGuardSecrets\myapp`); err != nil { ... }
//	// Then write the key to the wrap tool's stdin - protector.WriteDEK(ctx, stdin) - and register
//	// it at version 3.
//
// # Names and files
//
// A secret name is the store's name for a secret, optionally followed by KeySeparator and a key it
// holds: "prod/app#password" is the password key of the secret prod/app. A name without one reads
// the store's default key (Options.DefaultKey), if it has one, or else the secret's whole value. The
// secrets named are grouped by the store's name, so each is read once however many of its keys are
// listed.
//
// A secret's file name is its name with every '/' and '#' replaced by FileNameSeparator (see
// FileName): "prod/app#password" is written as prod__app__password. A name whose file name
// cache/filepersecret couldn't read (filepersecret.IsValidName) is refused, and so are two whose
// file names differ only in case, since Windows and macOS find files ignoring case. Each value is
// encrypted bound to its file name - Encrypt(ctx, value, fileName) - which is the name
// cache/filepersecret decrypts it under, so a renamed file fails authentication.
//
// # Values
//
// A key's value is read from a secret that is exactly one JSON object: a string as its text, a
// number, true or false as its JSON text. A null, object, array or empty value, a secret that isn't
// one JSON object, and an empty secret all hold nothing, and the name is reported missing. A JSON
// object holding a key more than once is refused (ErrInvalidSecretData), and so is a value that
// isn't UTF-8 text, since the protector encrypts text.
//
// PullSecrets reads every secret before reporting the missing ones, all in one *MissingSecretsError
// (ErrSecretNotFound), keeping every other value; a read that fails otherwise keeps nothing, and
// WriteProtectedSecretFiles then fails with ErrNotPulled until a pull completes.
// WriteProtectedSecretFiles creates the folder and replaces only its own files, each its value as
// UTF-8 without a byte order mark.
//
// # One JSON file, and streams
//
// WriteJSONSecrets writes one JSON object instead - a member per file name, mapped to its encrypted
// value, in ordinal order - replacing the file and creating its folder. Its bytes are the .NET
// port's: indented by two spaces, nothing escaped that needn't be ('+', '<', '>' and '&' as they
// are), no final line ending, and lines ending as .NET's Environment.NewLine does - CRLF on
// Windows, LF elsewhere - so the two ports' files differ only in their encrypted values.
//
// WriteProtectedSecretFilesTo writes the files WriteProtectedSecretFiles would write as a PAX tar
// archive - one regular file per secret, ordinal order, mode 0644, modified now, which GNU tar and
// bsdtar both unpack - and WriteJSONSecretsTo writes the JSON, each to an io.Writer: for
//
//	ssh -T host sudo -n tar -x --no-same-owner -f - -C /etc/myapp/secrets
//	ssh -T host sudo -n tee /etc/myapp/secrets.json
//
// Each refuses a nil writer (ErrInvalidArgument) and a writer that hasn't pulled (ErrNotPulled),
// checks ctx before every write, flushes the writer when it has a Flush() error method, and never
// closes it: close it afterwards, so the remote command sees the end of its input.
//
// # What is zeroed
//
// A secret's plaintext never becomes a Go string: a store's writer reads each response body into a
// buffer of its own (ReadBody), every value is unescaped into another and encrypted from there, and
// each is zeroed once encrypted. Go has no pinned memory, so this is best-effort, as for every
// buffer in hkdfguard-go (see hkdfguard.Wipe). The protector is the caller's and is never closed, so
// its key can be handed to the wrap process once the files are written.
//
// It is a module of its own (github.com/runsecure/hkdfguard-go/pipeline) because it depends on
// cache/filepersecret for the file-name rule, a module of its own that depends on the root module.
package pipeline
