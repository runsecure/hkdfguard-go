package certificate

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/runsecure/hkdfguard-go"
)

// LoaderOptions are a Loader's settings; the zero value judges validity by the system clock.
type LoaderOptions struct {
	// Now is the clock a certificate's validity is judged by; nil for time.Now.
	Now func() time.Time
}

// Loader opens the certificate a validated Options describes. The caller owns what it returns,
// and closes it.
//
//   - A store (Options.Windows, Options.MacOS) is opened read-only, and of the certificates whose
//     subject is the one named, the one valid now - with its private key, when one is required -
//     that expires last is returned; every other is released. The key stays where the store keeps
//     it, and every use of it is a call into the store: CNG's NCryptSignHash on Windows, the
//     Security framework's SecKeyCreateSignature on macOS.
//   - A Linux OpenSSL provider certificate (Options.Linux) is read from its file, without its key:
//     the Go port can't open a provider key, and the Validator refuses one.
//   - A file (Options.File) is read with its password, which is decrypted from the password source
//     into a buffer only while the key is read, and wiped at once; it is never a string.
//
// Whatever the source, a certificate that isn't valid now, or that has no private key when one is
// required, is refused. Safe for concurrent use.
type Loader struct {
	passwords hkdfguard.ProtectedReadOnlyCache
	now       func() time.Time
	validator interface {
		Validate(name string, options *Options) error
	}
	readStore storeReader
}

// NewLoader returns a Loader that reads a file's password from passwords, by
// FileOptions.PasswordSecretName - a filepersecret.Cache, a remote secret cache, systemd
// credentials. passwords may be nil when no file has a password.
func NewLoader(passwords hkdfguard.ProtectedReadOnlyCache, options LoaderOptions) *Loader {
	return newLoader(passwords, options, NewValidator(), readStore)
}

// newLoader is a Loader with its validator and store reader given, for tests.
func newLoader(passwords hkdfguard.ProtectedReadOnlyCache, options LoaderOptions, validator interface {
	Validate(string, *Options) error
}, read storeReader) *Loader {
	now := options.Now
	if now == nil {
		now = time.Now
	}
	return &Loader{passwords: passwords, now: now, validator: validator, readStore: read}
}

// Load opens the certificate options describes, as LoadContext with context.Background().
func (l *Loader) Load(options *Options, name string) (*Certificate, error) {
	return l.LoadContext(context.Background(), options, name)
}

// LoadContext opens the certificate options describes; name is the options' name, for named
// options, and is only reported in a validation failure. ctx cancels reading a file's password.
//
// It fails with a *ValidationError (ErrInvalidOptions) for options that aren't valid on this
// operating system; ErrNotFound when a store holds no certificate to give; ErrNotValidNow or
// ErrNoPrivateKey for a file's certificate that isn't valid now or lacks its required key;
// ErrNoPasswordSource or ErrPasswordNotFound when the password can't be read; ErrInvalidFile or
// ErrWrongPassword for a file that isn't a certificate or key, or that the password doesn't open;
// and ErrUnsupported for what the Go port can't open.
func (l *Loader) LoadContext(ctx context.Context, options *Options, name string) (*Certificate, error) {
	if err := l.validator.Validate(name, options); err != nil {
		return nil, err
	}
	file := options.File
	passwordName := ""
	if file != nil {
		passwordName = passwordNameOf(file, options)
	}
	if passwordName == "" {
		return l.open(options, nil, false)
	}

	if l.passwords == nil {
		return nil, fmt.Errorf("%w: the certificate's key file has a password, but the loader was given no password source to read it from",
			ErrNoPasswordSource)
	}
	maxLength, ok, err := l.passwords.MaxDecryptedLength(ctx, passwordName)
	if err != nil {
		return nil, err
	}
	if !ok || maxLength == 0 {
		return nil, fmt.Errorf("%w: the password source holds no secret named '%s'", ErrPasswordNotFound, passwordName)
	}
	password := make([]byte, maxLength)
	defer hkdfguard.Wipe(password)
	n, err := l.passwords.Decrypt(ctx, passwordName, password)
	if err != nil {
		return nil, err
	}
	return l.open(options, password[:n], true)
}

// passwordNameOf is the secret a file's password is in; empty when it has none to read. A PKCS#12
// file needs its password even for the certificate alone; a PEM certificate without its key needs
// none.
func passwordNameOf(file *FileOptions, options *Options) string {
	format, _ := file.format()
	if format == FormatPKCS12 || options.RequiresPrivateKey() {
		return file.PasswordSecretName
	}
	return ""
}

// open opens the one source options sets, which validation has made sure of, and checks the
// result.
func (l *Loader) open(options *Options, password []byte, hasPassword bool) (*Certificate, error) {
	requirePrivateKey := options.RequiresPrivateKey()
	var (
		certificate *Certificate
		err         error
	)
	switch {
	case options.Windows != nil:
		certificate, err = l.fromStore(options.Windows, requirePrivateKey)
	case options.MacOS != nil:
		certificate, err = l.fromStore(options.MacOS, requirePrivateKey)
	case options.Linux != nil:
		certificate, err = fromProvider(options.Linux, requirePrivateKey)
	default:
		certificate, err = fromFile(options.File, requirePrivateKey, password, hasPassword)
	}
	if err != nil {
		return nil, err
	}

	leaf := certificate.leaf
	switch {
	case requirePrivateKey && certificate.key == nil:
		err = fmt.Errorf("%w: the certificate '%s' has no private key", ErrNoPrivateKey, describeSubject(leaf))
	case !l.isValidNow(leaf):
		err = fmt.Errorf("%w: the certificate '%s' is valid from %s to %s, not now", ErrNotValidNow, describeSubject(leaf),
			leaf.NotBefore.UTC().Format(universalTime), leaf.NotAfter.UTC().Format(universalTime))
	}
	if err != nil {
		_ = certificate.Close()
		return nil, err
	}
	return certificate, nil
}

// universalTime is .NET's "u" format, as its messages give a validity period.
const universalTime = "2006-01-02 15:04:05Z"

func (l *Loader) isValidNow(certificate *x509.Certificate) bool {
	now := l.now()
	return !now.Before(certificate.NotBefore) && !now.After(certificate.NotAfter)
}

func (l *Loader) fromStore(store *StoreOptions, requirePrivateKey bool) (*Certificate, error) {
	location, _ := store.location()
	storeName, _ := store.name()
	subject, err := parseDistinguishedName(store.Subject)
	if err != nil {
		return nil, fmt.Errorf("%w: %s isn't a distinguished name", ErrInvalidOptions, store.Subject)
	}
	found, err := l.readStore(location, storeName)
	if err != nil {
		return nil, err
	}
	var chosen storeCertificate
	defer func() {
		for _, c := range found {
			if c != chosen {
				_ = c.Close()
			}
		}
	}()

	// Compared decoded, as each certificate states its subject, so how either side spells its
	// string types doesn't matter; ignoring case, as distinguished names compare.
	named := 0
	for _, c := range found {
		name, err := subjectOf(c.Certificate())
		if err != nil || !name.equalFold(subject) {
			continue
		}
		named++
		if !l.isValidNow(c.Certificate()) || requirePrivateKey && !c.HasPrivateKey() {
			continue
		}
		if chosen == nil || c.Certificate().NotAfter.After(chosen.Certificate().NotAfter) {
			chosen = c
		}
	}
	if chosen == nil {
		if named == 0 {
			return nil, fmt.Errorf("%w: the %s %s store holds no certificate whose subject is '%s'", ErrNotFound, location, storeName, store.Subject)
		}
		unusable := "expired or not yet valid"
		if requirePrivateKey {
			unusable = "expired, not yet valid, or without a private key"
		}
		return nil, fmt.Errorf("%w: the %s %s store's %d certificate(s) whose subject is '%s' are all %s", ErrNotFound,
			location, storeName, named, store.Subject, unusable)
	}

	certificate := &Certificate{leaf: chosen.Certificate(), chain: [][]byte{chosen.Certificate().Raw}}
	certificate.release = append(certificate.release, func() { _ = chosen.Close() })
	if requirePrivateKey {
		key, err := chosen.PrivateKey()
		if err != nil {
			_ = certificate.Close()
			return nil, fmt.Errorf("the certificate '%s' in the %s %s store: %w", describeSubject(chosen.Certificate()), location, storeName, err)
		}
		certificate.key = key
	}
	return certificate, nil
}

func fromFile(file *FileOptions, requirePrivateKey bool, password []byte, hasPassword bool) (*Certificate, error) {
	format, _ := file.format()
	if format == FormatPKCS12 {
		return fromPKCS12(file.Path, password, hasPassword)
	}

	data, err := os.ReadFile(file.Path)
	if err != nil {
		return nil, err
	}
	certificates, err := parseCertificates(data)
	if err != nil {
		return nil, err
	}
	if !requirePrivateKey {
		return newCertificate(certificates, nil), nil
	}

	keyData, err := os.ReadFile(file.KeyPath)
	if err != nil {
		return nil, err
	}
	defer hkdfguard.Wipe(keyData)
	key, err := parsePEMKey(keyData, password, hasPassword)
	if err != nil {
		return nil, err
	}
	// The certificate is the first whose public key is the key's, as .NET's CreateFromPemFile
	// chooses it; the rest are its chain.
	for i, c := range certificates {
		if publicKeyMatches(c, key) {
			ordered := append([]*x509.Certificate{c}, append(certificates[:i:i], certificates[i+1:]...)...)
			return newCertificate(ordered, fileKey(key)), nil
		}
	}
	wipeKey(key)
	return nil, fmt.Errorf("%w: no certificate in %s is the key's", ErrInvalidFile, file.Path)
}

func fromPKCS12(path string, password []byte, hasPassword bool) (*Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// The file holds the key: encrypted in a shrouded key bag, or not at all in a plain one.
	defer hkdfguard.Wipe(data)
	if !hasPassword {
		password = nil
	}
	contents, err := decodePKCS12(data, password)
	if err != nil {
		return nil, err
	}
	if len(contents.certificates) == 0 {
		contents.wipe()
		return nil, fmt.Errorf("%w: the PKCS#12 file holds no certificate", ErrInvalidFile)
	}

	// The certificate is the first that has its key, as .NET chooses it, or else the first; the
	// rest are its chain. Any other key is wiped.
	for i, c := range contents.certificates {
		for j, key := range contents.keys {
			if !publicKeyMatches(c, key) {
				continue
			}
			for k, other := range contents.keys {
				if k != j {
					wipeKey(other)
				}
			}
			ordered := append([]*x509.Certificate{c}, append(contents.certificates[:i:i], contents.certificates[i+1:]...)...)
			return newCertificate(ordered, fileKey(key)), nil
		}
	}
	contents.wipe()
	return newCertificate(contents.certificates, nil), nil
}

func fromProvider(linux *LinuxOpenSSLProviderOptions, requirePrivateKey bool) (*Certificate, error) {
	if requirePrivateKey {
		return nil, fmt.Errorf("%w: an OpenSSL provider key (%s) can't be opened by the Go port, which has no OpenSSL binding",
			ErrUnsupported, linux.provider())
	}
	data, err := os.ReadFile(linux.CertificateFile)
	if err != nil {
		return nil, err
	}
	certificates, err := parseCertificates(data)
	if err != nil {
		return nil, err
	}
	return newCertificate(certificates, nil), nil
}

// Certificate is an opened certificate: the leaf, the chain its source gave with it, and - when
// it has one - its private key, as a crypto.Signer (and crypto.Decrypter, for RSA). A key read
// from a file is held in memory and wiped on Close; a store's key stays in the store, and Close
// releases the handle to it. Every use of the key after Close fails with ErrClosed. Safe for
// concurrent use.
type Certificate struct {
	leaf    *x509.Certificate
	chain   [][]byte
	key     privateKey
	release []func()

	closeOnce sync.Once
}

func newCertificate(certificates []*x509.Certificate, key privateKey) *Certificate {
	chain := make([][]byte, len(certificates))
	for i, c := range certificates {
		chain[i] = c.Raw
	}
	return &Certificate{leaf: certificates[0], chain: chain, key: key}
}

// Leaf is the certificate itself.
func (c *Certificate) Leaf() *x509.Certificate { return c.leaf }

// HasPrivateKey reports whether the certificate came with its private key.
func (c *Certificate) HasPrivateKey() bool { return c.key != nil }

// PrivateKey is the certificate's private key, nil when it came without one. It is a
// crypto.Decrypter too for an RSA key.
func (c *Certificate) PrivateKey() crypto.Signer {
	if c.key == nil {
		return nil
	}
	return c.key
}

// TLSCertificate is the certificate as crypto/tls takes it: the leaf and its chain, DER-encoded,
// the private key, and Leaf. It holds the same key: closing the Certificate stops it working.
func (c *Certificate) TLSCertificate() tls.Certificate {
	chain := make([][]byte, len(c.chain))
	copy(chain, c.chain)
	certificate := tls.Certificate{Certificate: chain, Leaf: c.leaf}
	if c.key != nil {
		certificate.PrivateKey = c.key
	}
	return certificate
}

// Close wipes a key read from a file, and releases the native handles to a store's certificate
// and key. Safe to call more than once.
func (c *Certificate) Close() error {
	var errs []error
	c.closeOnce.Do(func() {
		if c.key != nil {
			errs = append(errs, c.key.Close())
		}
		for _, release := range c.release {
			release()
		}
	})
	return errors.Join(errs...)
}
