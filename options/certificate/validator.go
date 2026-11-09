package certificate

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
)

// The platforms a Validator judges for, by GOOS.
const (
	platformWindows = "windows"
	platformMacOS   = "darwin"
	platformLinux   = "linux"
)

// Validator checks an Options before anything is opened: exactly one source set, and one this
// operating system has - the Windows store on Windows, a keychain on macOS, an OpenSSL provider's
// certificate on Linux, a file anywhere - with a store, subject, provider, key or path that is
// one. A file holding a private key must be protected by a password, named by its secret, unless
// an unprotected key is explicitly allowed. A key held by an OpenSSL provider is refused: the Go
// port has no OpenSSL binding to open it through.
type Validator struct {
	platform string
}

// NewValidator returns a Validator for the operating system the process runs on.
func NewValidator() *Validator { return newValidatorFor(runtime.GOOS) }

// newValidatorFor returns a Validator for platform, a GOOS, for tests. windows, darwin and linux
// each have their native source; any other (freebsd, android, ios...) has none, and is named as it
// is.
func newValidatorFor(platform string) *Validator { return &Validator{platform: platform} }

// Validate checks options, returning nil or a *ValidationError naming name and every failure.
func (v *Validator) Validate(name string, options *Options) error {
	if options == nil {
		return fmt.Errorf("%w: options is nil", ErrInvalidArgument)
	}
	var failures []string
	fail := func(format string, args ...any) { failures = append(failures, fmt.Sprintf(format, args...)) }

	type source struct {
		name     string
		set      bool
		platform string
	}
	sources := []source{
		{"Windows", options.Windows != nil, platformWindows},
		{"MacOS", options.MacOS != nil, platformMacOS},
		{"Linux", options.Linux != nil, platformLinux},
		{"File", options.File != nil, ""},
	}
	var set []string
	for _, s := range sources {
		if s.set {
			set = append(set, s.name)
		}
	}
	switch {
	case len(set) == 0:
		fail("One certificate source is required: Windows, MacOS, Linux or File.")
	case len(set) > 1:
		fail("Only one certificate source can be set, but %s are.", strings.Join(set, ", "))
	}
	for _, s := range sources {
		if s.set && s.platform != "" && s.platform != v.platform {
			fail("The %s certificate source can only be used on %s; this is %s.", s.name, s.name, describePlatform(v.platform))
		}
	}

	requirePrivateKey := options.RequiresPrivateKey()
	if options.Windows != nil {
		validateStore("Windows", options.Windows, fail)
	}
	if options.MacOS != nil {
		validateStore("MacOS", options.MacOS, fail)
	}
	if options.Linux != nil {
		v.validateLinux(options.Linux, requirePrivateKey, fail)
	}
	if options.File != nil {
		validateFile(options.File, requirePrivateKey, fail)
	}

	if len(failures) > 0 {
		return &ValidationError{Name: name, Failures: failures}
	}
	return nil
}

func validateStore(source string, store *StoreOptions, fail func(string, ...any)) {
	if _, ok := store.location(); !ok {
		fail("%s.StoreLocation must be CurrentUser or LocalMachine, not %s.", source, store.StoreLocation)
	}
	if _, ok := store.name(); !ok {
		fail("%s.StoreName must be a store's name - My, Root, CertificateAuthority, TrustedPeople... - not %s.", source, store.StoreName)
	}

	if strings.TrimSpace(store.Subject) == "" {
		fail(`%s.Subject is required: the certificate's subject distinguished name, e.g. "CN=api.example.com".`, source)
		return
	}
	if _, err := parseDistinguishedName(store.Subject); err != nil {
		fail(`%s.Subject must be a distinguished name, e.g. "CN=api.example.com, O=Contoso", not '%s'.`, source, store.Subject)
	}
}

func (v *Validator) validateLinux(linux *LinuxOpenSSLProviderOptions, requirePrivateKey bool, fail func(string, ...any)) {
	if !isProviderName(linux.provider()) {
		fail(`Linux.Provider must be an OpenSSL provider's name - "tpm2" or "pkcs11" - not '%s'.`, linux.Provider)
	}
	if requirePrivateKey {
		switch {
		case strings.TrimSpace(linux.KeyURI) == "":
			fail(`Linux.KeyUri is required: the key as the provider names it, e.g. "handle:0x81000001".`)
		case v.platform == platformLinux:
			// Only where the source is otherwise usable: elsewhere the platform failure says enough.
			fail("Linux.KeyUri can't be opened: the Go port has no OpenSSL binding, so a key held by an OpenSSL provider " +
				"isn't supported. Set RequirePrivateKey to false to open the certificate alone, or use a File source.")
		}
	}
	validatePath("Linux.CertificateFile", linux.CertificateFile, fail)
}

func isProviderName(provider string) bool {
	if provider == "" {
		return false
	}
	for i := range len(provider) {
		c := provider[i]
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func validateFile(file *FileOptions, requirePrivateKey bool, fail func(string, ...any)) {
	validatePath("File.Path", file.Path, fail)

	if format, ok := file.format(); !ok {
		fail("File.Format must be Pkcs12 or Pem, not %s.", file.Format)
	} else if format == FormatPEM && requirePrivateKey {
		validatePath("File.KeyPath", file.KeyPath, fail)
	}

	switch {
	case file.PasswordSecretName != "" && strings.TrimSpace(file.PasswordSecretName) == "":
		fail("File.PasswordSecretName can't be empty: name the secret holding the key's password, or leave it unset.")
	case requirePrivateKey && file.PasswordSecretName == "" && !file.AllowUnprotectedPrivateKey:
		fail("File.PasswordSecretName is required: a private key file must be protected by a password, read from a protected secret. " +
			"Set File.AllowUnprotectedPrivateKey to accept a plaintext key, for development only.")
	}
}

func validatePath(what, path string, fail func(string, ...any)) {
	switch {
	case strings.TrimSpace(path) == "":
		fail("%s is required.", what)
	case !filepath.IsAbs(path):
		fail("%s must be an absolute path, not '%s'.", what, path)
	}
}

// describePlatform names a platform as messages do.
func describePlatform(platform string) string {
	switch platform {
	case platformWindows:
		return "Windows"
	case platformMacOS:
		return "macOS"
	case platformLinux:
		return "Linux"
	}
	return platform
}
