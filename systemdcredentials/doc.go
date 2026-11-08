// Package systemdcredentials encrypts, decrypts and reads Linux credentials with systemd - the Go
// port of the .NET HkdfGuard.SystemdCredentials (SystemdCredentials, SystemdCredential,
// SystemdCredentialSource, SystemdCredentialsOptions, SystemdCredsRunner).
//
// Credentials runs systemd-creds by absolute path, with its arguments as an argument list and
// never through a shell: Encrypt writes the plaintext to its standard input and has it write the
// encrypted credential file, bound to its name and to the host key, the TPM or both (Key); Decrypt
// reads the value from its standard output straight into a Credential, in a buffer that grows as it
// is read and wipes each smaller one it drops, up to systemd's 1 MiB limit (MaxLength). A run that
// outlasts Options.Timeout, or whose context is cancelled, is killed with its whole process group.
// The plaintext never touches a file or a command line. systemd-creds inherits none of this
// process's environment - only a PATH of the system directories - so no variable set for the
// application, such as SYSTEMD_CREDENTIAL_SECRET, can redirect it, and no secret in one reaches it.
//
//	// At deploy, on the machine itself (as root, for system credentials):
//	credentials, err := systemdcredentials.New(systemdcredentials.Options{})
//	err = credentials.Encrypt(ctx, "tls-password", password, "/etc/credstore.encrypted/tls-password.cred")
//
//	// In the service: LoadCredentialEncrypted=tls-password:/etc/credstore.encrypted/tls-password.cred
//	// in its unit has systemd decrypt it into memory under /run, which ReadLoadedCredential reads -
//	// or, with the privilege to, decrypt it directly:
//	value, err := credentials.Decrypt(ctx, "tls-password", "/etc/credstore.encrypted/tls-password.cred")
//	defer value.Close()
//
// Decrypting a system credential directly needs what encrypting it used: root, for the host key,
// and access to the TPM (the tss group, say) for a TPM-bound one. An unprivileged service reads it
// through LoadCredentialEncrypted= instead, which systemd decrypts for it into the service's own
// unswappable in-memory credentials directory (ReadLoadedCredential), or uses Options.UserScope
// credentials (systemd 256 or later).
//
// Source is a hkdfguard.ProtectedReadOnlyCache over both - loaded credentials first, then encrypted
// files - for the certificate loader's password, say (options/certificate). Nothing is cached:
// every lookup reads the credential again, and the copy read is wiped once copied out.
//
// New refuses to run anywhere but Linux (ErrUnsupportedPlatform); ReadLoadedCredential and a
// Source over loaded credentials alone read files, and work anywhere. It is a module of its own
// (github.com/runsecure/hkdfguard-go/systemdcredentials), like every integration.
package systemdcredentials
