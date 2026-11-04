package certificate

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/runsecure/hkdfguard-go"
)

// The Loader against real certificates and key files the tests make, and stores they hand it -
// the port of the .NET CertificateOptionsLoaderTests.

func storeOptions(subject string, requirePrivateKey bool) *Options {
	return &Options{Windows: &StoreOptions{Subject: subject}, RequirePrivateKey: Bool(requirePrivateKey)}
}

func pfxOptions(path, passwordSecretName string, allowUnprotected, requirePrivateKey bool) *Options {
	return &Options{
		File:              &FileOptions{Path: path, PasswordSecretName: passwordSecretName, AllowUnprotectedPrivateKey: allowUnprotected},
		RequirePrivateKey: Bool(requirePrivateKey),
	}
}

func mustLoad(t *testing.T, loader *Loader, options *Options) *Certificate {
	t.Helper()
	c, err := loader.Load(options, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func sameDay(a, b time.Time) bool {
	return a.UTC().Truncate(24 * time.Hour).Equal(b.UTC().Truncate(24 * time.Hour))
}

func TestAStore_GivesTheCertificateValidNowWithItsKey_ThatExpiresLast(t *testing.T) {
	store := &fakeStore{entries: []*fakeStoreCertificate{
		storeEntry(t, -400, -1, true, testSubject),           // expired
		storeEntry(t, 1, 900, true, testSubject),             // not yet valid
		storeEntry(t, -1, 800, false, testSubject),           // the newest, without its key
		storeEntry(t, -200, 100, true, testSubject),          // older
		storeEntry(t, -5, 400, true, testSubject),            // renewed
		storeEntry(t, -5, 700, true, "CN=other.example.com"), // another subject
	}}
	loader := loaderFor(newFakePasswords(), platformWindows, store)

	c, err := loader.Load(storeOptions(testSubject, true), "")
	if err != nil {
		t.Fatal(err)
	}

	if store.location != LocalMachine || store.name != StoreMy {
		t.Fatalf("read the %s %s store; the default is LocalMachine My", store.location, store.name)
	}
	if !sameDay(c.Leaf().NotAfter, testNow.AddDate(0, 0, 400)) || !c.HasPrivateKey() {
		t.Fatalf("chose the certificate expiring %v, with a key: %v", c.Leaf().NotAfter, c.HasPrivateKey())
	}
	assertSigns(t, c)
	closed := 0
	for _, e := range store.entries {
		if e.closed {
			closed++
		}
	}
	if closed != 5 || store.entries[4].closed {
		t.Fatalf("%d store certificates closed, the chosen one %v; want the 5 others", closed, store.entries[4].closed)
	}

	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if !store.entries[4].closed || !store.entries[4].keyClosed {
		t.Fatal("closing the certificate didn't release its store certificate and key")
	}
	if _, err := c.PrivateKey().Sign(rand.Reader, make([]byte, 32), crypto.SHA256); !errors.Is(err, ErrClosed) {
		t.Fatalf("signing after Close: %v, want ErrClosed", err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestAStore_WithoutAKeyRequired_GivesTheNewestValidOne(t *testing.T) {
	store := &fakeStore{entries: []*fakeStoreCertificate{
		storeEntry(t, -200, 100, true, testSubject),
		storeEntry(t, -1, 800, false, testSubject),
	}}
	loader := loaderFor(newFakePasswords(), platformWindows, store)

	c := mustLoad(t, loader, storeOptions(testSubject, false))
	loadedContext, err := loader.LoadContext(context.Background(), storeOptions(testSubject, false), "")
	if err != nil {
		t.Fatal(err)
	}
	defer loadedContext.Close()

	if c.HasPrivateKey() || c.PrivateKey() != nil || c.TLSCertificate().PrivateKey != nil {
		t.Fatal("a certificate without its key came with one")
	}
	if !sameDay(c.Leaf().NotAfter, testNow.AddDate(0, 0, 800)) {
		t.Fatalf("chose the certificate expiring %v", c.Leaf().NotAfter)
	}
	if !bytes.Equal(c.Leaf().Raw, loadedContext.Leaf().Raw) {
		t.Fatal("Load and LoadContext chose different certificates")
	}
}

func TestAStoresSubject_IsComparedWhole_IgnoringCase(t *testing.T) {
	loader := loaderFor(nil, platformWindows, &fakeStore{entries: []*fakeStoreCertificate{storeEntry(t, -1, 100, true, testSubject)}})

	c := mustLoad(t, loader, storeOptions("cn=API.example.com, o=contoso", true))
	if got := describeSubject(c.Leaf()); got != testSubject {
		t.Fatalf("subject %q", got)
	}

	loader = loaderFor(nil, platformWindows, &fakeStore{entries: []*fakeStoreCertificate{storeEntry(t, -1, 100, true, testSubject)}})
	if _, err := loader.Load(storeOptions("CN=api.example.com", true), ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a subject naming part of the certificate's: %v, want ErrNotFound", err)
	}
}

func TestAStoreWithoutACertificateToGive_SaysWhy(t *testing.T) {
	_, err := loaderFor(nil, platformWindows, &fakeStore{entries: []*fakeStoreCertificate{storeEntry(t, -1, 100, true, "CN=other")}}).
		Load(storeOptions(testSubject, true), "")
	if !errors.Is(err, ErrNotFound) || !strings.Contains(err.Error(), "holds no certificate whose subject is") {
		t.Fatalf("no certificate with the subject: %v", err)
	}

	_, err = loaderFor(nil, platformWindows, &fakeStore{entries: []*fakeStoreCertificate{
		storeEntry(t, -400, -1, true, testSubject), storeEntry(t, -1, 100, false, testSubject),
	}}).Load(storeOptions(testSubject, true), "")
	if !errors.Is(err, ErrNotFound) || !strings.Contains(err.Error(), "2 certificate(s)") || !strings.Contains(err.Error(), "without a private key") {
		t.Fatalf("none usable: %v", err)
	}

	_, err = loaderFor(nil, platformWindows, &fakeStore{entries: []*fakeStoreCertificate{storeEntry(t, -400, -1, true, testSubject)}}).
		Load(storeOptions(testSubject, false), "")
	if err == nil || !strings.HasSuffix(err.Error(), "expired or not yet valid") {
		t.Fatalf("expired, no key required: %v", err)
	}
}

func TestAMacOSKeychain_IsReadAsAStore(t *testing.T) {
	store := &fakeStore{entries: []*fakeStoreCertificate{storeEntry(t, -1, 100, true, testSubject)}}
	options := &Options{MacOS: &StoreOptions{StoreLocation: CurrentUser, Subject: testSubject}}

	c := mustLoad(t, loaderFor(nil, platformMacOS, store), options)

	if !c.HasPrivateKey() || store.location != CurrentUser || store.name != StoreMy {
		t.Fatalf("key %v, read the %s %s store", c.HasPrivateKey(), store.location, store.name)
	}
}

func TestAStoreKeyThatWontOpen_IsReported(t *testing.T) {
	entry := storeEntry(t, -1, 100, true, testSubject)
	entry.key = nil // HasPrivateKey says no...
	store := &fakeStore{entries: []*fakeStoreCertificate{entry}}
	failing := &failingKeyStore{fakeStore: store}

	loader := newLoader(nil, LoaderOptions{Now: func() time.Time { return testNow }}, newValidatorFor(platformWindows), failing.read)
	_, err := loader.Load(storeOptions(testSubject, true), "")

	if !errors.Is(err, ErrNoPrivateKey) || !entry.closed {
		t.Fatalf("a key that won't open: %v, closed %v", err, entry.closed)
	}
}

// failingKeyStore's certificates claim their key, which then won't open.
type failingKeyStore struct{ *fakeStore }

type claimsKey struct{ *fakeStoreCertificate }

func (claimsKey) HasPrivateKey() bool { return true }

func (s *failingKeyStore) read(location StoreLocation, name StoreName) ([]storeCertificate, error) {
	found, err := s.fakeStore.read(location, name)
	for i, c := range found {
		found[i] = claimsKey{c.(*fakeStoreCertificate)}
	}
	return found, err
}

func TestAStoreThatFailsToRead_IsReported(t *testing.T) {
	failure := errors.New("access denied")
	loader := newLoader(nil, LoaderOptions{Now: func() time.Time { return testNow }}, newValidatorFor(platformWindows),
		func(StoreLocation, StoreName) ([]storeCertificate, error) { return nil, failure })

	if _, err := loader.Load(storeOptions(testSubject, true), ""); !errors.Is(err, failure) {
		t.Fatalf("got %v", err)
	}
}

func TestAPfx_IsOpenedWithItsPassword_FromThePasswordSource(t *testing.T) {
	original := selfSigned(t, testKey(), testSubject, -10, 300)
	path := writeFile(t, "tls.pfx", encodePFX(t, testKey(), ptr(testPassword), original))
	passwords := newFakePasswords()
	loader := loaderFor(passwords, platformWindows, nil)

	loaded := mustLoad(t, loader, pfxOptions(path, "tls-password", false, true))
	loadedContext, err := loader.LoadContext(context.Background(), pfxOptions(path, "tls-password", false, true), "")
	if err != nil {
		t.Fatal(err)
	}
	defer loadedContext.Close()

	if !bytes.Equal(loaded.Leaf().Raw, original.Raw) {
		t.Fatal("loaded another certificate")
	}
	assertSigns(t, loaded)
	assertSigns(t, loadedContext)
	if passwords.reads != 2 {
		t.Fatalf("the password was read %d times, want once per load", passwords.reads)
	}
}

func TestThePassword_IsZeroed_OnceTheKeyIsRead(t *testing.T) {
	original := selfSigned(t, testKey(), testSubject, -10, 300)
	path := writeFile(t, "tls.pfx", encodePFX(t, testKey(), ptr(testPassword), original))
	passwords := newFakePasswords()

	mustLoad(t, loaderFor(passwords, platformWindows, nil), pfxOptions(path, "tls-password", false, true))

	if passwords.lastBuffer == nil || !hkdfguard.IsZero(passwords.lastBuffer) {
		t.Fatalf("the password buffer after loading: %q", passwords.lastBuffer)
	}
}

func TestAWrongPassword_IsRefused(t *testing.T) {
	original := selfSigned(t, testKey(), testSubject, -10, 300)
	path := writeFile(t, "tls.pfx", encodePFX(t, testKey(), ptr("another password"), original))
	loader := loaderFor(newFakePasswords(), platformWindows, nil)

	if _, err := loader.Load(pfxOptions(path, "tls-password", false, true), ""); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("got %v", err)
	}
	if _, err := loader.LoadContext(context.Background(), pfxOptions(path, "tls-password", false, true), ""); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("got %v", err)
	}
}

func TestAMissingPassword_OrNoPasswordSource_IsRefused(t *testing.T) {
	path := writeFile(t, "tls.pfx", encodePFX(t, testKey(), nil, selfSigned(t, testKey(), testSubject, -1, 100)))

	if _, err := loaderFor(newFakePasswords(), platformWindows, nil).Load(pfxOptions(path, "absent", false, true), ""); !errors.Is(err, ErrPasswordNotFound) ||
		!strings.Contains(err.Error(), "no secret named 'absent'") {
		t.Fatalf("got %v", err)
	}

	noSource := NewLoader(nil, LoaderOptions{Now: func() time.Time { return testNow }})
	if _, err := noSource.Load(pfxOptions(path, "tls-password", false, true), ""); !errors.Is(err, ErrNoPasswordSource) {
		t.Fatalf("got %v", err)
	}
}

func TestAPasswordSourceFailure_IsReported(t *testing.T) {
	path := writeFile(t, "tls.pfx", encodePFX(t, testKey(), ptr(testPassword), selfSigned(t, testKey(), testSubject, -1, 100)))
	failure := errors.New("vault unreachable")

	for _, source := range []*failingPasswords{{lengthErr: failure}, {decryptErr: failure}} {
		loader := newLoader(source, LoaderOptions{Now: func() time.Time { return testNow }}, newValidatorFor(platformWindows), nil)
		if _, err := loader.Load(pfxOptions(path, "tls-password", false, true), ""); !errors.Is(err, failure) {
			t.Fatalf("got %v", err)
		}
	}
}

type failingPasswords struct{ lengthErr, decryptErr error }

func (p *failingPasswords) Decrypt(context.Context, string, []byte) (int, error) {
	return 0, p.decryptErr
}
func (p *failingPasswords) MaxDecryptedLength(context.Context, string) (int, bool, error) {
	return 16, p.lengthErr == nil, p.lengthErr
}

func TestAnUnprotectedPfx_IsOpened_WhenAllowed(t *testing.T) {
	path := writeFile(t, "tls.pfx", encodePFX(t, testKey(), nil, selfSigned(t, testKey(), testSubject, -1, 100)))
	loader := NewLoader(nil, LoaderOptions{Now: func() time.Time { return testNow }})

	loaded := mustLoad(t, loader, pfxOptions(path, "", true, true))
	loadedContext, err := loader.LoadContext(context.Background(), pfxOptions(path, "", true, true), "")
	if err != nil {
		t.Fatal(err)
	}
	defer loadedContext.Close()

	assertSigns(t, loaded)
	assertSigns(t, loadedContext)
}

func TestAPfx_NeedsItsPassword_EvenForTheCertificateAlone(t *testing.T) {
	original := selfSigned(t, testKey(), testSubject, -10, 300)
	path := writeFile(t, "tls.pfx", encodePFX(t, testKey(), ptr(testPassword), original))
	passwords := newFakePasswords()

	loaded := mustLoad(t, loaderFor(passwords, platformWindows, nil), pfxOptions(path, "tls-password", false, false))

	if !bytes.Equal(loaded.Leaf().Raw, original.Raw) || passwords.reads != 1 {
		t.Fatalf("loaded the certificate %v, reading the password %d times", bytes.Equal(loaded.Leaf().Raw, original.Raw), passwords.reads)
	}
}

func TestAPfxChain_KeepsItsOtherCertificates_AfterTheOneWithTheKey(t *testing.T) {
	ca := selfSigned(t, testKeys()[1], "CN=Contoso CA", -10, 900)
	leaf := selfSigned(t, testKey(), testSubject, -10, 300)
	path := writeFile(t, "tls.pfx", encodePFX(t, testKey(), ptr(testPassword), ca, leaf))

	loaded := mustLoad(t, loaderFor(newFakePasswords(), platformWindows, nil), pfxOptions(path, "tls-password", false, true))

	chain := loaded.TLSCertificate().Certificate
	if !bytes.Equal(loaded.Leaf().Raw, leaf.Raw) || len(chain) != 2 || !bytes.Equal(chain[0], leaf.Raw) || !bytes.Equal(chain[1], ca.Raw) {
		t.Fatal("the leaf isn't first, then its chain")
	}
}

func TestAPemCertificate_WithAnEncryptedKey_IsOpenedWithItsPassword(t *testing.T) {
	original := selfSigned(t, testKey(), testSubject, -10, 300)
	options := &Options{File: &FileOptions{
		Format:             FormatPEM,
		Path:               writeFile(t, "tls.crt", certificatePEM(original)),
		KeyPath:            writeFile(t, "tls.key", encryptedPKCS8PEM(t, testKey(), testPassword, 100_000)),
		PasswordSecretName: "tls-password",
	}}
	passwords := newFakePasswords()

	loaded := mustLoad(t, loaderFor(passwords, platformWindows, nil), options)

	if !bytes.Equal(loaded.Leaf().Raw, original.Raw) {
		t.Fatal("loaded another certificate")
	}
	assertSigns(t, loaded)
	if !hkdfguard.IsZero(passwords.lastBuffer) {
		t.Fatal("the password wasn't wiped")
	}

	options.File.KeyPath = writeFile(t, "wrong.key", encryptedPKCS8PEM(t, testKey(), "another password", 1000))
	if _, err := loaderFor(passwords, platformWindows, nil).Load(options, ""); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("a key under another password: %v", err)
	}
}

func TestAPemKey_EncryptedOrNot_MustBeWhatThePasswordSays(t *testing.T) {
	original := selfSigned(t, testKey(), testSubject, -10, 300)
	certPath := writeFile(t, "tls.crt", certificatePEM(original))
	plain := writeFile(t, "plain.key", plainKeyPEM(t, testKey()))
	encrypted := writeFile(t, "encrypted.key", encryptedPKCS8PEM(t, testKey(), testPassword, 1000))
	loader := loaderFor(newFakePasswords(), platformWindows, nil)

	_, err := loader.Load(&Options{File: &FileOptions{Format: FormatPEM, Path: certPath, KeyPath: plain, PasswordSecretName: "tls-password"}}, "")
	if !errors.Is(err, ErrInvalidFile) || !strings.Contains(err.Error(), "isn't encrypted") {
		t.Fatalf("a plain key with a password: %v", err)
	}
	_, err = loader.Load(&Options{File: &FileOptions{Format: FormatPEM, Path: certPath, KeyPath: encrypted, AllowUnprotectedPrivateKey: true}}, "")
	if !errors.Is(err, ErrInvalidFile) || !strings.Contains(err.Error(), "is encrypted") {
		t.Fatalf("an encrypted key without a password: %v", err)
	}
}

func TestAPemCertificate_WithAPlainKey_IsOpened_WhenAllowed(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for name, key := range map[string]crypto.Signer{"RSA": testKey(), "ECDSA": ecKey} {
		t.Run(name, func(t *testing.T) {
			original := selfSigned(t, key, testSubject, -10, 300)
			options := &Options{File: &FileOptions{
				Format:                     FormatPEM,
				Path:                       writeFile(t, "tls.crt", certificatePEM(original)),
				KeyPath:                    writeFile(t, "tls.key", plainKeyPEM(t, key)),
				AllowUnprotectedPrivateKey: true,
			}}

			loaded := mustLoad(t, NewLoader(nil, LoaderOptions{Now: func() time.Time { return testNow }}), options)

			digest := sha256.Sum256([]byte("to sign"))
			signature, err := loaded.PrivateKey().Sign(rand.Reader, digest[:], crypto.SHA256)
			if err != nil {
				t.Fatal(err)
			}
			if err := x509VerifyDigest(loaded.Leaf(), digest[:], signature); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// x509VerifyDigest verifies a SHA-256 PKCS #1 v1.5 or ECDSA signature over digest.
func x509VerifyDigest(c *x509.Certificate, digest, signature []byte) error {
	switch public := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(public, crypto.SHA256, digest, signature)
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(public, digest, signature) {
			return errors.New("the ECDSA signature doesn't verify")
		}
		return nil
	}
	return errors.New("not RSA or ECDSA")
}

func TestAPemKey_ForNoCertificateInTheFile_IsRefused(t *testing.T) {
	options := &Options{File: &FileOptions{
		Format:                     FormatPEM,
		Path:                       writeFile(t, "tls.crt", certificatePEM(selfSigned(t, testKeys()[1], testSubject, -10, 300))),
		KeyPath:                    writeFile(t, "tls.key", plainKeyPEM(t, freshKey(t))),
		AllowUnprotectedPrivateKey: true,
	}}

	if _, err := NewLoader(nil, LoaderOptions{}).Load(options, ""); !errors.Is(err, ErrInvalidFile) {
		t.Fatalf("got %v", err)
	}
}

func TestAPemCertificate_Alone_NeedsNoKeyOrPassword(t *testing.T) {
	original := selfSigned(t, testKey(), testSubject, -10, 300)
	options := &Options{
		File:              &FileOptions{Format: FormatPEM, Path: writeFile(t, "ca.crt", certificatePEM(original)), PasswordSecretName: "tls-password"},
		RequirePrivateKey: Bool(false),
	}
	passwords := newFakePasswords()

	loaded := mustLoad(t, loaderFor(passwords, platformWindows, nil), options)

	if loaded.HasPrivateKey() || passwords.reads != 0 {
		t.Fatalf("key %v, password read %d times", loaded.HasPrivateKey(), passwords.reads)
	}
}

func TestADERCertificate_Alone_IsOpened(t *testing.T) {
	original := selfSigned(t, testKey(), testSubject, -10, 300)
	options := &Options{File: &FileOptions{Format: FormatPEM, Path: writeFile(t, "ca.cer", original.Raw)}, RequirePrivateKey: Bool(false)}

	loaded := mustLoad(t, NewLoader(nil, LoaderOptions{Now: func() time.Time { return testNow }}), options)

	if !bytes.Equal(loaded.Leaf().Raw, original.Raw) {
		t.Fatal("loaded another certificate")
	}
}

func TestAFileCertificate_NotValidNow_OrWithoutItsKey_IsRefused(t *testing.T) {
	expired := writeFile(t, "expired.pfx", encodePFX(t, testKey(), nil, selfSigned(t, testKey(), testSubject, -400, -1)))
	keyless := writeFile(t, "keyless.pfx", encodePFX(t, nil, nil, selfSigned(t, testKey(), testSubject, -1, 100)))
	loader := loaderFor(nil, platformWindows, nil)

	_, err := loader.Load(pfxOptions(expired, "", true, true), "")
	if !errors.Is(err, ErrNotValidNow) || !strings.Contains(err.Error(), "not now") {
		t.Fatalf("expired: %v", err)
	}
	_, err = loader.Load(pfxOptions(keyless, "", true, true), "")
	if !errors.Is(err, ErrNoPrivateKey) || !strings.Contains(err.Error(), "has no private key") {
		t.Fatalf("keyless: %v", err)
	}
}

func TestAMissingOrBrokenFile_IsReported(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.pfx")
	loader := loaderFor(nil, platformWindows, nil)

	if _, err := loader.Load(pfxOptions(missing, "", true, true), ""); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing: %v", err)
	}
	if _, err := loader.Load(pfxOptions(writeFile(t, "junk.pfx", []byte("not a pfx")), "", true, true), ""); !errors.Is(err, ErrInvalidFile) {
		t.Fatalf("junk: %v", err)
	}
	pem := &Options{File: &FileOptions{Format: FormatPEM, Path: writeFile(t, "junk.crt", []byte("-----BEGIN NOTHING-----\n-----END NOTHING-----\n"))},
		RequirePrivateKey: Bool(false)}
	if _, err := loader.Load(pem, ""); !errors.Is(err, ErrInvalidFile) {
		t.Fatalf("no certificate: %v", err)
	}
}

func TestALinuxCertificate_AloneIsReadFromItsFile_ItsProviderKeyRefused(t *testing.T) {
	original := selfSigned(t, testKey(), testSubject, -10, 300)
	path := writeFile(t, "tls.crt", certificatePEM(original))
	loader := loaderFor(nil, platformLinux, nil)

	alone := mustLoad(t, loader, &Options{Linux: &LinuxOpenSSLProviderOptions{CertificateFile: path}, RequirePrivateKey: Bool(false)})
	if !bytes.Equal(alone.Leaf().Raw, original.Raw) {
		t.Fatal("loaded another certificate")
	}

	_, err := loader.Load(&Options{Linux: &LinuxOpenSSLProviderOptions{CertificateFile: path, KeyURI: "handle:0x81000001"}}, "")
	if !errors.Is(err, ErrInvalidOptions) || !strings.Contains(err.Error(), "no OpenSSL binding") {
		t.Fatalf("a provider key: %v", err)
	}
	// Past the validator, the loader refuses it too.
	if _, err := fromProvider(&LinuxOpenSSLProviderOptions{CertificateFile: path, KeyURI: "k"}, true); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("got %v", err)
	}
}

func TestInvalidOptions_AreRefused_BeforeAnythingIsOpened(t *testing.T) {
	store := &fakeStore{}
	loader := loaderFor(nil, platformWindows, store)

	_, err := loader.Load(&Options{}, "tls")
	var validation *ValidationError
	if !errors.As(err, &validation) || validation.Name != "tls" || !strings.Contains(err.Error(), "One certificate source is required") {
		t.Fatalf("got %v", err)
	}
	if _, err := loader.LoadContext(context.Background(), &Options{}, ""); !errors.As(err, &validation) || validation.Name != "" {
		t.Fatalf("got %v", err)
	}
	if _, err := loader.Load(nil, ""); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("nil options: %v", err)
	}
	if store.reads != 0 {
		t.Fatal("the store was read")
	}
}

func TestAClosedFileKey_IsWiped_AndRefusesToSign(t *testing.T) {
	key := freshKey(t)
	path := writeFile(t, "tls.pfx", encodePFX(t, key, ptr(testPassword), selfSigned(t, key, testSubject, -1, 100)))
	c, err := loaderFor(newFakePasswords(), platformWindows, nil).Load(pfxOptions(path, "tls-password", false, true), "")
	if err != nil {
		t.Fatal(err)
	}
	decrypter, ok := c.PrivateKey().(crypto.Decrypter)
	if !ok {
		t.Fatal("an RSA file key isn't a crypto.Decrypter")
	}
	ciphertext, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, &key.PublicKey, []byte("secret"), nil)
	if plaintext, err := decrypter.Decrypt(rand.Reader, ciphertext, &rsa.OAEPOptions{Hash: crypto.SHA256}); err != nil || string(plaintext) != "secret" {
		t.Fatalf("decrypting: %q, %v", plaintext, err)
	}

	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.PrivateKey().Sign(rand.Reader, make([]byte, 32), crypto.SHA256); !errors.Is(err, ErrClosed) {
		t.Fatalf("signing after Close: %v", err)
	}
	if _, err := decrypter.Decrypt(rand.Reader, ciphertext, nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("decrypting after Close: %v", err)
	}
}

func TestWipeKey_ZeroesWhatItReaches(t *testing.T) {
	key := freshKey(t)
	wipeKey(key)
	if key.D.Sign() != 0 || key.Primes[0].Sign() != 0 || key.Precomputed.Dp.Sign() != 0 {
		t.Fatal("the RSA key's private values survive")
	}
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wipeKey(ecKey)
	if ecKey.D.Sign() != 0 {
		t.Fatal("the ECDSA scalar survives")
	}
}

// The loaded certificate works as crypto/tls's: a TLS 1.3 handshake, whose signature is RSA-PSS,
// against a client that trusts it.
func TestTheTLSCertificate_ServesATLSHandshake(t *testing.T) {
	original := selfSigned(t, testKey(), testSubject, -10, 300)
	path := writeFile(t, "tls.pfx", encodePFX(t, testKey(), ptr(testPassword), original))
	loaded := mustLoad(t, loaderFor(newFakePasswords(), platformWindows, nil), pfxOptions(path, "tls-password", false, true))

	assertHandshake(t, loaded)
}

// assertHandshake runs a TLS 1.3 and a TLS 1.2 handshake with c as the server's certificate. The
// client checks it is given c's leaf; crypto/tls verifies the handshake's signature with it.
func assertHandshake(t *testing.T, c *Certificate) {
	t.Helper()
	for _, version := range []uint16{tls.VersionTLS13, tls.VersionTLS12} {
		serverSide, clientSide := net.Pipe()
		server := tls.Server(serverSide, &tls.Config{Certificates: []tls.Certificate{c.TLSCertificate()}, MinVersion: version, MaxVersion: version})
		client := tls.Client(clientSide, &tls.Config{MinVersion: version, MaxVersion: version, InsecureSkipVerify: true,
			VerifyConnection: func(state tls.ConnectionState) error {
				if !bytes.Equal(state.PeerCertificates[0].Raw, c.Leaf().Raw) {
					return errors.New("the server presented another certificate")
				}
				return nil
			}})
		errs := make(chan error, 1)
		go func() { errs <- server.Handshake() }()
		if err := client.Handshake(); err != nil {
			t.Fatalf("TLS %x handshake: %v", version, err)
		}
		if err := <-errs; err != nil {
			t.Fatalf("TLS %x server: %v", version, err)
		}
		// The pipe's own ends: a TLS close_notify would wait for a reader that isn't there.
		_ = clientSide.Close()
		_ = serverSide.Close()
	}
}
