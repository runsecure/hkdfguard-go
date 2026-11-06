package certificate

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The port of the .NET CertificateOptionsValidatorTests.

// absolutePath is an absolute path on the host the tests run on, as the validator checks it.
var absolutePath = filepath.Join(os.TempDir(), "tls.pfx")

func failures(t *testing.T, options *Options, platform string) []string {
	t.Helper()
	err := newValidatorFor(platform).Validate("", options)
	if err == nil {
		return nil
	}
	var validation *ValidationError
	if !errors.As(err, &validation) || !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("not a *ValidationError: %v", err)
	}
	return validation.Failures
}

func single(t *testing.T, failures []string) string {
	t.Helper()
	if len(failures) != 1 {
		t.Fatalf("want one failure, got %q", failures)
	}
	return failures[0]
}

func windowsStore(subject string) *Options { return &Options{Windows: &StoreOptions{Subject: subject}} }
func macOSStore(subject string) *Options   { return &Options{MacOS: &StoreOptions{Subject: subject}} }
func protectedFile() *Options {
	return &Options{File: &FileOptions{Path: absolutePath, PasswordSecretName: "tls-pfx-password"}}
}
func linuxCertificate() *Options {
	return &Options{Linux: &LinuxOpenSSLProviderOptions{CertificateFile: absolutePath}, RequirePrivateKey: Bool(false)}
}

func TestEachSource_IsValid_OnItsOwnPlatform(t *testing.T) {
	for _, c := range []struct {
		options  *Options
		platform string
	}{
		{windowsStore(testSubject), platformWindows},
		{macOSStore(testSubject), platformMacOS},
		{linuxCertificate(), platformLinux},
		{protectedFile(), platformWindows},
		{protectedFile(), platformLinux},
		{protectedFile(), platformMacOS},
		{protectedFile(), "freebsd"},
	} {
		if f := failures(t, c.options, c.platform); f != nil {
			t.Errorf("on %s: %q", c.platform, f)
		}
	}
}

func TestANativeSource_IsRefused_OnAnotherPlatform(t *testing.T) {
	for _, c := range []struct {
		source   string
		options  *Options
		platform string
	}{
		{"Windows", windowsStore(testSubject), platformLinux},
		{"MacOS", macOSStore(testSubject), platformWindows},
		{"Linux", &Options{Linux: &LinuxOpenSSLProviderOptions{KeyURI: "handle:0x81000001", CertificateFile: absolutePath}}, platformMacOS},
	} {
		failure := single(t, failures(t, c.options, c.platform))
		if want := "The " + c.source + " certificate source can only be used on " + c.source; !strings.HasPrefix(failure, want) {
			t.Errorf("%q doesn't start %q", failure, want)
		}
	}
}

func TestAnUnknownPlatform_IsNamedAsItIs(t *testing.T) {
	if f := single(t, failures(t, windowsStore(testSubject), "freebsd")); !strings.Contains(f, "this is freebsd") {
		t.Fatal(f)
	}
	if f := single(t, failures(t, macOSStore(testSubject), platformLinux)); !strings.Contains(f, "this is Linux") {
		t.Fatal(f)
	}
	if f := single(t, failures(t, windowsStore(testSubject), platformMacOS)); !strings.Contains(f, "this is macOS") {
		t.Fatal(f)
	}
}

func TestNoSource_OrMoreThanOne_IsRefused(t *testing.T) {
	if f := single(t, failures(t, &Options{}, platformWindows)); !strings.Contains(f, "One certificate source is required") {
		t.Fatal(f)
	}

	both := windowsStore(testSubject)
	both.File = protectedFile().File
	found := false
	for _, f := range failures(t, both, platformWindows) {
		found = found || strings.Contains(f, "but Windows, File are")
	}
	if !found {
		t.Fatal("two sources aren't named")
	}
}

func TestAStore_TakesASubjectDistinguishedName(t *testing.T) {
	for _, subject := range []string{"CN=api.example.com", "CN=api.example.com, O=Contoso, C=US", "cn=api.example.com",
		`CN="api, example"; O=Contoso`, "OID.2.5.4.3=api", "2.5.4.3=api + O=Contoso"} {
		if f := failures(t, windowsStore(subject), platformWindows); f != nil {
			t.Errorf("%s: %q", subject, f)
		}
		if f := failures(t, macOSStore(subject), platformMacOS); f != nil {
			t.Errorf("%s: %q", subject, f)
		}
	}
}

func TestAStore_NeedsASubjectThatIsADistinguishedName(t *testing.T) {
	for _, c := range []struct{ subject, reason string }{
		{"", "Subject is required"},
		{" ", "Subject is required"},
		{"api.example.com", "must be a distinguished name"},
		{"XX=api", "must be a distinguished name"},
		{`CN="unterminated`, "must be a distinguished name"},
	} {
		windows := single(t, failures(t, windowsStore(c.subject), platformWindows))
		macOS := single(t, failures(t, macOSStore(c.subject), platformMacOS))
		if !strings.HasPrefix(windows, "Windows.") || !strings.Contains(windows, c.reason) {
			t.Errorf("%q: %s", c.subject, windows)
		}
		if !strings.HasPrefix(macOS, "MacOS.") || !strings.Contains(macOS, c.reason) {
			t.Errorf("%q: %s", c.subject, macOS)
		}
	}
}

func TestAStore_NeedsAStoreLocationAndNameThatAreOnes(t *testing.T) {
	options := windowsStore(testSubject)
	options.Windows.StoreLocation = "Elsewhere"
	options.Windows.StoreName = "Drawer"

	f := failures(t, options, platformWindows)

	if len(f) != 2 || !strings.HasPrefix(f[0], "Windows.StoreLocation") || !strings.HasPrefix(f[1], "Windows.StoreName") {
		t.Fatalf("%q", f)
	}
}

func TestAStoreLocationAndName_AreMatchedIgnoringCase(t *testing.T) {
	store := &StoreOptions{StoreLocation: "currentuser", StoreName: "trustedPEOPLE", Subject: testSubject}
	if f := failures(t, &Options{Windows: store}, platformWindows); f != nil {
		t.Fatal(f)
	}
	if location, _ := store.location(); location != CurrentUser {
		t.Fatal(location)
	}
	if name, _ := store.name(); name != StoreTrustedPeople {
		t.Fatal(name)
	}
}

func TestALinuxProvider_MayHoldHyphensAndUnderscores(t *testing.T) {
	for _, provider := range []string{"my-provider", "my_provider"} {
		options := linuxCertificate()
		options.Linux.Provider = provider
		if f := failures(t, options, platformLinux); f != nil {
			t.Errorf("%s: %q", provider, f)
		}
	}
}

func TestALinuxProvider_MustBeAProvidersName(t *testing.T) {
	options := linuxCertificate()
	options.Linux.Provider = "tpm2;rm"
	if f := single(t, failures(t, options, platformLinux)); !strings.HasPrefix(f, "Linux.Provider") {
		t.Fatal(f)
	}
}

// The Go port has no OpenSSL binding: a provider key is refused on Linux, with a message saying so.
func TestALinuxProviderKey_IsRefused_AsTheGoPortCantOpenIt(t *testing.T) {
	options := &Options{Linux: &LinuxOpenSSLProviderOptions{Provider: "pkcs11", KeyURI: "pkcs11:token=t", CertificateFile: absolutePath}}
	f := single(t, failures(t, options, platformLinux))
	if !strings.HasPrefix(f, "Linux.KeyUri can't be opened") || !strings.Contains(f, "no OpenSSL binding") {
		t.Fatal(f)
	}
}

func TestALinuxKey_IsRequired_OnlyWithAPrivateKey(t *testing.T) {
	options := &Options{Linux: &LinuxOpenSSLProviderOptions{Provider: "pkcs11", CertificateFile: absolutePath}}
	if f := single(t, failures(t, options, platformLinux)); !strings.HasPrefix(f, "Linux.KeyUri is required") {
		t.Fatal(f)
	}

	options.RequirePrivateKey = Bool(false)
	if f := failures(t, options, platformLinux); f != nil {
		t.Fatal(f)
	}
}

func TestAFilePath_MustBeAbsolute(t *testing.T) {
	for _, c := range []struct{ path, reason string }{
		{"", "is required"},
		{" ", "is required"},
		{"relative/tls.crt", "must be an absolute path"},
	} {
		linux := linuxCertificate()
		linux.Linux.CertificateFile = c.path
		file := &Options{File: &FileOptions{Path: c.path, PasswordSecretName: "p"}}
		if f := single(t, failures(t, linux, platformLinux)); !strings.Contains(f, c.reason) {
			t.Errorf("%q: %s", c.path, f)
		}
		if f := single(t, failures(t, file, platformWindows)); !strings.Contains(f, c.reason) {
			t.Errorf("%q: %s", c.path, f)
		}
	}
}

func TestAPemFile_NeedsAKeyPath_OnlyWithAPrivateKey(t *testing.T) {
	options := protectedFile()
	options.File.Format = FormatPEM
	if f := single(t, failures(t, options, platformWindows)); !strings.HasPrefix(f, "File.KeyPath") {
		t.Fatal(f)
	}

	options.File.KeyPath = absolutePath
	if f := failures(t, options, platformWindows); f != nil {
		t.Fatal(f)
	}

	options.File.KeyPath = ""
	options.RequirePrivateKey = Bool(false)
	if f := failures(t, options, platformWindows); f != nil {
		t.Fatal(f)
	}
}

func TestAFileFormat_MustBeOne(t *testing.T) {
	options := protectedFile()
	options.File.Format = "Jks"
	if f := single(t, failures(t, options, platformWindows)); !strings.HasPrefix(f, "File.Format") {
		t.Fatal(f)
	}
	options.File.Format = "pem"
	options.File.KeyPath = absolutePath
	if f := failures(t, options, platformWindows); f != nil {
		t.Fatal(f)
	}
}

func TestAKeyFile_NeedsAPassword_UnlessAnUnprotectedKeyIsAllowed(t *testing.T) {
	options := protectedFile()
	options.File.PasswordSecretName = ""
	if f := single(t, failures(t, options, platformWindows)); !strings.Contains(f, "File.AllowUnprotectedPrivateKey") {
		t.Fatal(f)
	}

	options.File.AllowUnprotectedPrivateKey = true
	if f := failures(t, options, platformWindows); f != nil {
		t.Fatal(f)
	}

	options.File.AllowUnprotectedPrivateKey = false
	options.RequirePrivateKey = Bool(false)
	if f := failures(t, options, platformWindows); f != nil {
		t.Fatal(f)
	}
}

func TestAnEmptyPasswordSecretName_IsRefused(t *testing.T) {
	options := protectedFile()
	options.File.PasswordSecretName = " "
	if f := single(t, failures(t, options, platformWindows)); !strings.HasPrefix(f, "File.PasswordSecretName can't be empty") {
		t.Fatal(f)
	}
}

func TestTheValidator_ChecksForTheRunningPlatform_AndNilOptions(t *testing.T) {
	validator := NewValidator()

	if err := validator.Validate("", protectedFile()); err != nil {
		t.Fatal(err)
	}
	if err := validator.Validate("", windowsStore(testSubject)); (err == nil) != (runtime.GOOS == "windows") {
		t.Fatalf("the Windows store on %s: %v", runtime.GOOS, err)
	}
	if err := validator.Validate("", nil); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("nil options: %v", err)
	}
}

func TestTheValidationError_NamesTheOptions_AndJoinsItsFailures(t *testing.T) {
	err := newValidatorFor(platformWindows).Validate("tls", &Options{Windows: &StoreOptions{StoreLocation: "x"}})
	var validation *ValidationError
	if !errors.As(err, &validation) || validation.Name != "tls" || len(validation.Failures) != 2 ||
		err.Error() != validation.Failures[0]+"; "+validation.Failures[1] {
		t.Fatalf("%#v", err)
	}
}

// The configuration shapes the .NET port documents unmarshal into Options, by the same names.
func TestTheDocumentedShapes_BindFromConfiguration(t *testing.T) {
	const document = `{
	  "Windows": { "Certificate": { "Windows": { "StoreLocation": "CurrentUser", "StoreName": "TrustedPeople", "Subject": "CN=api.example.com" } } },
	  "MacOS": { "Certificate": { "MacOS": { "StoreLocation": "LocalMachine", "Subject": "CN=api.example.com" } } },
	  "Linux": { "Certificate": { "Linux": { "Provider": "pkcs11", "KeyUri": "pkcs11:token=t", "CertificateFile": "/etc/myapp/tls.crt" } } },
	  "File": { "Certificate": { "RequirePrivateKey": false, "File": { "Path": "/etc/myapp/tls.pem", "Format": "Pem", "KeyPath": "/etc/myapp/tls.key", "PasswordSecretName": "tls-key-password", "AllowUnprotectedPrivateKey": true } } }
	}`
	var configuration map[string]struct{ Certificate Options }
	if err := json.Unmarshal([]byte(document), &configuration); err != nil {
		t.Fatal(err)
	}

	windows := configuration["Windows"].Certificate.Windows
	if *windows != (StoreOptions{StoreLocation: CurrentUser, StoreName: StoreTrustedPeople, Subject: "CN=api.example.com"}) {
		t.Fatalf("%+v", windows)
	}
	macOS := configuration["MacOS"].Certificate.MacOS
	if location, _ := macOS.location(); location != LocalMachine || macOS.Subject != "CN=api.example.com" {
		t.Fatalf("%+v", macOS)
	}
	if name, _ := macOS.name(); name != StoreMy {
		t.Fatal(name)
	}
	linux := configuration["Linux"].Certificate.Linux
	if *linux != (LinuxOpenSSLProviderOptions{Provider: "pkcs11", KeyURI: "pkcs11:token=t", CertificateFile: "/etc/myapp/tls.crt"}) {
		t.Fatalf("%+v", linux)
	}
	options := configuration["File"].Certificate
	if options.RequiresPrivateKey() || *options.File != (FileOptions{Path: "/etc/myapp/tls.pem", Format: FormatPEM, KeyPath: "/etc/myapp/tls.key",
		PasswordSecretName: "tls-key-password", AllowUnprotectedPrivateKey: true}) {
		t.Fatalf("%+v", options.File)
	}
}

func TestTheDefaults_AreTheSafeOnes(t *testing.T) {
	options := &Options{Windows: &StoreOptions{}, Linux: &LinuxOpenSSLProviderOptions{}, File: &FileOptions{}}

	location, _ := options.Windows.location()
	name, _ := options.Windows.name()
	format, _ := options.File.format()
	if !options.RequiresPrivateKey() || location != LocalMachine || name != StoreMy || options.Linux.provider() != "tpm2" ||
		format != FormatPKCS12 || options.File.AllowUnprotectedPrivateKey {
		t.Fatal("a default isn't the safe one")
	}
}
