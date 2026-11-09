package systemdcredentials

import "time"

// Key is which key systemd-creds encrypts a credential under - its --with-key.
type Key int

const (
	// KeyAuto is the host key and the TPM when the machine has a TPM, the host key alone when it
	// doesn't ("auto"); the default.
	KeyAuto Key = iota

	// KeyHost is the host key, /var/lib/systemd/credential.secret, readable only by root ("host").
	KeyHost

	// KeyTPM2 is the TPM alone, so the credential decrypts only on this machine's TPM ("tpm2").
	KeyTPM2

	// KeyHostAndTPM2 is both: decrypting needs the host key and this machine's TPM ("host+tpm2").
	KeyHostAndTPM2
)

// argument is the key as --with-key names it; ok is false for a Key that isn't one.
func (k Key) argument() (string, bool) {
	switch k {
	case KeyAuto:
		return "auto", true
	case KeyHost:
		return "host", true
	case KeyTPM2:
		return "tpm2", true
	case KeyHostAndTPM2:
		return "host+tpm2", true
	}
	return "", false
}

// DefaultExecutablePath is where systemd-creds is run from when Options.ExecutablePath is empty.
const DefaultExecutablePath = "/usr/bin/systemd-creds"

// DefaultTimeout is how long one systemd-creds run may take when Options.Timeout is zero.
const DefaultTimeout = 30 * time.Second

// Options are how Credentials runs systemd-creds; the zero value is the defaults.
type Options struct {
	// ExecutablePath is the systemd-creds executable, by absolute path, so no directory on PATH can
	// stand in for it; empty for DefaultExecutablePath.
	ExecutablePath string

	// Key is the key new credentials are encrypted under; KeyAuto by default.
	Key Key

	// UserScope encrypts and decrypts credentials scoped to the calling user (--user; systemd 256 or
	// later), which an unprivileged account can do through systemd's credential service. Default
	// false: system credentials, which need root - or, for KeyTPM2, access to the TPM - to encrypt
	// or decrypt directly.
	UserScope bool

	// Timeout is how long one systemd-creds run may take before it, and every process it started,
	// is killed; zero for DefaultTimeout. A negative timeout is refused.
	Timeout time.Duration
}
