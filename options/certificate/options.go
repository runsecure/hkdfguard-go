package certificate

// Options is a plain-data description of where one certificate - with its private key - is opened
// from: exactly one of the operating system's own protected key storage (Windows, MacOS, Linux) or
// a key file on the filesystem (File). It carries no behavior and never a password: a file's
// password is named here, and read at load time from a protected secret source, so it is never
// plaintext on disk or in configuration. Validate it with a Validator; Loader.Load validates it
// too. The JSON names are the .NET port's configuration keys, so the same configuration binds
// (encoding/json matches them ignoring case):
//
//	"Certificate": { "Windows": { "StoreLocation": "LocalMachine", "StoreName": "My", "Subject": "CN=api.example.com" } }
//	"Certificate": { "MacOS": { "StoreLocation": "LocalMachine", "Subject": "CN=api.example.com" } }
//	"Certificate": { "Linux": { "Provider": "tpm2", "KeyUri": "handle:0x81000001", "CertificateFile": "/etc/myapp/tls.crt" } }
//	"Certificate": { "File": { "Path": "/etc/myapp/tls.pfx", "PasswordSecretName": "tls-pfx-password" } }
type Options struct {
	// Windows is a certificate in a Windows certificate store, its key held by CNG.
	Windows *StoreOptions `json:"Windows,omitempty"`

	// MacOS is a certificate in a macOS keychain, its key held by the keychain.
	MacOS *StoreOptions `json:"MacOS,omitempty"`

	// Linux is a certificate whose key is held by an OpenSSL 3 provider on Linux - the TPM, say.
	// The Go port has no OpenSSL binding, so it can open only the certificate itself
	// (RequirePrivateKey false); the Validator refuses it when the key is required.
	Linux *LinuxOpenSSLProviderOptions `json:"Linux,omitempty"`

	// File is a certificate and key read from files, the key protected by a password.
	File *FileOptions `json:"File,omitempty"`

	// RequirePrivateKey is whether the certificate must come with its private key: true - the
	// default, which nil means - for one presented as a TLS server or client certificate, or used
	// to sign; false for one only to be trusted. Set it with Bool(false).
	RequirePrivateKey *bool `json:"RequirePrivateKey,omitempty"`
}

// RequiresPrivateKey reports whether the certificate must come with its private key:
// RequirePrivateKey, or true when it is nil.
func (o *Options) RequiresPrivateKey() bool {
	return o.RequirePrivateKey == nil || *o.RequirePrivateKey
}

// Bool returns a pointer to v, for Options.RequirePrivateKey.
func Bool(v bool) *bool { return &v }

// StoreLocation is which certificate store location a StoreOptions opens.
type StoreLocation string

const (
	// CurrentUser is the store of the account the process runs as: on macOS, its login keychain.
	CurrentUser StoreLocation = "CurrentUser"

	// LocalMachine is the machine's store, the default: on macOS, the System keychain.
	LocalMachine StoreLocation = "LocalMachine"
)

// StoreName is which store at a StoreLocation a StoreOptions opens - the names of .NET's
// System.Security.Cryptography.X509Certificates.StoreName.
type StoreName string

const (
	StoreAddressBook          StoreName = "AddressBook"          // other users' certificates
	StoreAuthRoot             StoreName = "AuthRoot"             // third-party certification authorities
	StoreCertificateAuthority StoreName = "CertificateAuthority" // intermediate certification authorities (Windows' "CA")
	StoreDisallowed           StoreName = "Disallowed"           // revoked certificates
	StoreMy                   StoreName = "My"                   // personal certificates, the default
	StoreRoot                 StoreName = "Root"                 // trusted root certification authorities
	StoreTrustedPeople        StoreName = "TrustedPeople"        // directly trusted people and resources
	StoreTrustedPublisher     StoreName = "TrustedPublisher"     // directly trusted publishers
)

// storeNames is every StoreName, in .NET's enum order, by its Windows system store name.
var storeNames = []struct {
	name    StoreName
	windows string
}{
	{StoreAddressBook, "AddressBook"},
	{StoreAuthRoot, "AuthRoot"},
	{StoreCertificateAuthority, "CA"},
	{StoreDisallowed, "Disallowed"},
	{StoreMy, "My"},
	{StoreRoot, "Root"},
	{StoreTrustedPeople, "TrustedPeople"},
	{StoreTrustedPublisher, "TrustedPublisher"},
}

// StoreOptions is a certificate in an operating system certificate store, found by its subject,
// so a renewed certificate an administrator adds under the same subject is picked up with no
// change to configuration. Of the certificates with that subject, the one opened is the one valid
// now - and with its private key, when one is required - that expires last; an expired or
// not-yet-valid one is never chosen. Its private key stays in the store: CNG (or the TPM) on
// Windows, the keychain on macOS, where CurrentUser is the login keychain and LocalMachine the
// System keychain.
//
// Matching by subject trusts whoever can add a certificate to the store to choose it: keep it to a
// store only administrators can write, such as LocalMachine's My.
type StoreOptions struct {
	// StoreLocation is which store location to open; empty for LocalMachine. Matched ignoring case.
	StoreLocation StoreLocation `json:"StoreLocation,omitempty"`

	// StoreName is which store to open; empty for My (Personal). Matched ignoring case. On macOS
	// only My - the keychain itself - can be read.
	StoreName StoreName `json:"StoreName,omitempty"`

	// Subject is the certificate's subject distinguished name, as the certificate states it:
	// "CN=api.example.com, O=Contoso". Compared to each certificate's whole subject, decoded,
	// ignoring case - never as a substring, so "CN=api" doesn't match "CN=api.example.com".
	Subject string `json:"Subject,omitempty"`
}

// location is the store location, LocalMachine when unset, matched ignoring case; ok is false for
// one that isn't a location.
func (s *StoreOptions) location() (StoreLocation, bool) {
	switch {
	case s.StoreLocation == "":
		return LocalMachine, true
	case equalFoldASCII(string(s.StoreLocation), string(CurrentUser)):
		return CurrentUser, true
	case equalFoldASCII(string(s.StoreLocation), string(LocalMachine)):
		return LocalMachine, true
	}
	return "", false
}

// name is the store name, My when unset, matched ignoring case; ok is false for one that isn't a
// store's name.
func (s *StoreOptions) name() (StoreName, bool) {
	if s.StoreName == "" {
		return StoreMy, true
	}
	for _, known := range storeNames {
		if equalFoldASCII(string(s.StoreName), string(known.name)) {
			return known.name, true
		}
	}
	return "", false
}

// LinuxOpenSSLProviderOptions is a certificate on Linux whose private key is opened through an
// OpenSSL 3 provider - tpm2 for a key in the TPM, or pkcs11 for a hardware token - beside the
// certificate itself as a PEM file, which holds nothing secret. It is kept for configuration
// parity with the .NET port: Go has no OpenSSL provider binding, so only the certificate is
// opened here (RequirePrivateKey false), and the Validator refuses it when the key is required.
type LinuxOpenSSLProviderOptions struct {
	// Provider is the OpenSSL provider that holds the key: "tpm2" (the default, which empty
	// means) or "pkcs11".
	Provider string `json:"Provider,omitempty"`

	// KeyURI is the key, as the provider names it: "handle:0x81000001" for a persistent TPM key, a
	// path to a TPM key blob, or a "pkcs11:" URI.
	KeyURI string `json:"KeyUri,omitempty"`

	// CertificateFile is the certificate, PEM- or DER-encoded, without its key; absolute.
	CertificateFile string `json:"CertificateFile,omitempty"`
}

// provider is the provider's name, tpm2 when unset.
func (l *LinuxOpenSSLProviderOptions) provider() string {
	if l.Provider == "" {
		return "tpm2"
	}
	return l.Provider
}

// FileFormat is the format of a certificate file.
type FileFormat string

const (
	// FormatPKCS12 is a PKCS#12 (.pfx/.p12) file holding the certificate and its key; the default.
	FormatPKCS12 FileFormat = "Pkcs12"

	// FormatPEM is a PEM certificate, with its key in FileOptions.KeyPath as encrypted PKCS#8.
	FormatPEM FileFormat = "Pem"
)

// FileOptions is a certificate and its key read from files, by absolute paths. The key must be
// protected by a password - a password-protected PKCS#12 file, or an encrypted PKCS#8 PEM key -
// and the password comes from the secret PasswordSecretName names, never from configuration. An
// unprotected key file is refused unless AllowUnprotectedPrivateKey is set.
type FileOptions struct {
	// Path is the certificate file - PKCS#12, or a PEM certificate.
	Path string `json:"Path,omitempty"`

	// Format is the file's format; empty for FormatPKCS12. Matched ignoring case.
	Format FileFormat `json:"Format,omitempty"`

	// KeyPath is the PEM private key file, for FormatPEM; ignored for PKCS#12.
	KeyPath string `json:"KeyPath,omitempty"`

	// PasswordSecretName is the name of the secret holding the key's password, as a protected
	// secret source - a filepersecret.Cache, a remote secret cache, systemd credentials - is asked
	// for it; empty for none. The password is decrypted only while the key is read, into memory
	// zeroed straight after.
	PasswordSecretName string `json:"PasswordSecretName,omitempty"`

	// AllowUnprotectedPrivateKey accepts a key file with no password - a PKCS#12 file without one,
	// or a plain PEM key - whose private key is then plaintext on disk, protected only by file
	// permissions. Default false; set it only for development.
	AllowUnprotectedPrivateKey bool `json:"AllowUnprotectedPrivateKey,omitempty"`
}

// format is the file's format, PKCS#12 when unset, matched ignoring case; ok is false for one that
// isn't a format.
func (f *FileOptions) format() (FileFormat, bool) {
	switch {
	case f.Format == "":
		return FormatPKCS12, true
	case equalFoldASCII(string(f.Format), string(FormatPKCS12)):
		return FormatPKCS12, true
	case equalFoldASCII(string(f.Format), string(FormatPEM)):
		return FormatPEM, true
	}
	return "", false
}

// equalFoldASCII reports whether a and b are equal, ignoring the case of ASCII letters only.
func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range len(a) {
		x, y := a[i], b[i]
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}
