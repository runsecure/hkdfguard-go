package certificate

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Shared fixtures: real keys and certificates the tests make, stores and a password source they
// hand the Loader, and a PKCS#12 and encrypted PKCS#8 writer built on the standard library's own
// PBKDF2 and HMAC - independent of the reader's - so a round trip checks one against the other.

const (
	testSubject  = "CN=api.example.com, O=Contoso"
	testPassword = "pässwörd-123"
)

var testNow = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

// testKeys are two RSA keys, made once: generating one per certificate would make the suite slow.
var testKeys = sync.OnceValue(func() [2]*rsa.PrivateKey {
	var keys [2]*rsa.PrivateKey
	for i := range keys {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		keys[i] = key
	}
	return keys
})

func testKey() *rsa.PrivateKey { return testKeys()[0] }

// freshKey is an RSA key of its own, for a test that wipes it.
func freshKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// selfSigned is a certificate for key with subject, valid from notBeforeDays to notAfterDays after
// testNow.
func selfSigned(t *testing.T, key crypto.Signer, subject string, notBeforeDays, notAfterDays int) *x509.Certificate {
	t.Helper()
	name, err := parseDistinguishedName(subject)
	if err != nil {
		t.Fatal(err)
	}
	var sequence pkix.RDNSequence
	for i := len(name) - 1; i >= 0; i-- {
		var rdn pkix.RelativeDistinguishedNameSET
		for _, attr := range name[i] {
			rdn = append(rdn, pkix.AttributeTypeAndValue{Type: attr.oid, Value: attr.value})
		}
		sequence = append(sequence, rdn)
	}
	rawSubject, err := asn1.Marshal(sequence)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	template := &x509.Certificate{
		SerialNumber: serial,
		RawSubject:   rawSubject,
		NotBefore:    testNow.AddDate(0, 0, notBeforeDays),
		NotAfter:     testNow.AddDate(0, 0, notAfterDays),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{"api.example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

// fakeStoreCertificate is a store's certificate, with or without its key, that records being
// closed.
type fakeStoreCertificate struct {
	certificate *x509.Certificate
	key         *rsa.PrivateKey
	closed      bool
	keyClosed   bool
}

func (f *fakeStoreCertificate) Certificate() *x509.Certificate { return f.certificate }
func (f *fakeStoreCertificate) HasPrivateKey() bool            { return f.key != nil }
func (f *fakeStoreCertificate) Close() error                   { f.closed = true; return nil }

func (f *fakeStoreCertificate) PrivateKey() (privateKey, error) {
	if f.key == nil {
		return nil, ErrNoPrivateKey
	}
	// The shared test key isn't wiped: the store keeps it.
	return newPrivateKey(&closableKey{public: f.key.Public(), sign: f.key.Sign, decrypt: f.key.Decrypt,
		release: func() { f.keyClosed = true }}), nil
}

// storeEntry is a store certificate valid from notBeforeDays to notAfterDays, with the shared key
// or without it.
func storeEntry(t *testing.T, notBeforeDays, notAfterDays int, withKey bool, subject string) *fakeStoreCertificate {
	t.Helper()
	entry := &fakeStoreCertificate{certificate: selfSigned(t, testKey(), subject, notBeforeDays, notAfterDays)}
	if withKey {
		entry.key = testKey()
	}
	return entry
}

// fakeStore reads entries, recording what it was asked for.
type fakeStore struct {
	entries  []*fakeStoreCertificate
	location StoreLocation
	name     StoreName
	reads    int
}

func (s *fakeStore) read(location StoreLocation, name StoreName) ([]storeCertificate, error) {
	s.location, s.name = location, name
	s.reads++
	found := make([]storeCertificate, len(s.entries))
	for i, e := range s.entries {
		found[i] = e
	}
	return found, nil
}

// fakePasswords is a password source over plain strings, recording each read.
type fakePasswords struct {
	values     map[string]string
	reads      int
	lastBuffer []byte
}

func newFakePasswords() *fakePasswords {
	return &fakePasswords{values: map[string]string{"tls-password": testPassword}}
}

func (p *fakePasswords) Decrypt(_ context.Context, name string, result []byte) (int, error) {
	p.reads++
	p.lastBuffer = result
	value, ok := p.values[name]
	if !ok {
		return 0, nil
	}
	return copy(result, value), nil
}

func (p *fakePasswords) MaxDecryptedLength(_ context.Context, name string) (int, bool, error) {
	value, ok := p.values[name]
	return len(value), ok, nil
}

// loaderFor is a Loader that validates for platform and reads store.
func loaderFor(passwords *fakePasswords, platform string, store *fakeStore) *Loader {
	if store == nil {
		store = &fakeStore{}
	}
	var source interface {
		Decrypt(context.Context, string, []byte) (int, error)
		MaxDecryptedLength(context.Context, string) (int, bool, error)
	}
	if passwords != nil {
		source = passwords
	}
	return newLoader(source, LoaderOptions{Now: func() time.Time { return testNow }}, newValidatorFor(platform), store.read)
}

func writeFile(t *testing.T, name string, contents []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func certificatePEM(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

func plainKeyPEM(t *testing.T, key crypto.Signer) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// assertSigns checks the certificate's key signs, PKCS #1 v1.5 and PSS for RSA, and its
// certificate's public key verifies it.
func assertSigns(t *testing.T, c *Certificate) {
	t.Helper()
	digest := sha256.Sum256([]byte("to sign"))
	key := c.PrivateKey()
	if key == nil {
		t.Fatal("no private key")
	}
	public, ok := c.Leaf().PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("a %T key", c.Leaf().PublicKey)
	}
	signature, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if err := rsa.VerifyPKCS1v15(public, crypto.SHA256, digest[:], signature); err != nil {
		t.Fatal(err)
	}
	pss := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
	signature, err = key.Sign(rand.Reader, digest[:], pss)
	if err != nil {
		t.Fatal(err)
	}
	if err := rsa.VerifyPSS(public, crypto.SHA256, digest[:], signature, pss); err != nil {
		t.Fatal(err)
	}
}

// A PKCS#12 writer: PBES2 (PBKDF2-HMAC-SHA-256, AES-256-CBC) for the key and the certificates,
// and an HMAC-SHA-256 MAC, as OpenSSL 3 and .NET's Pbes2Aes256Sha256 write them - or, with no
// password, a plain key bag and certificates under a MAC keyed by the empty password, as
// openssl pkcs12 -export -passout pass: -keypbe NONE -certpbe NONE writes them.

type rawContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue
}

func explicit0(der []byte) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: der}
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	der, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// pbes2Encrypt encrypts plaintext under PBES2 with the standard library's PBKDF2, returning the
// algorithm identifier and ciphertext.
func pbes2Encrypt(t *testing.T, password string, iterations int, plaintext []byte) (pkix.AlgorithmIdentifier, []byte) {
	t.Helper()
	salt := make([]byte, 16)
	iv := make([]byte, aes.BlockSize)
	_, _ = rand.Read(salt)
	_, _ = rand.Read(iv)
	key, err := pbkdf2.Key(sha256.New, password, salt, iterations, 32)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(key)
	padding := aes.BlockSize - len(plaintext)%aes.BlockSize
	padded := append(append([]byte(nil), plaintext...), make([]byte, padding)...)
	for i := len(plaintext); i < len(padded); i++ {
		padded[i] = byte(padding)
	}
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)

	kdf := mustMarshal(t, struct {
		Salt       []byte
		Iterations int
		PRF        pkix.AlgorithmIdentifier
	}{salt, iterations, pkix.AlgorithmIdentifier{Algorithm: oidHMACWithSHA256, Parameters: asn1.NullRawValue}})
	params := mustMarshal(t, struct {
		KDF    pkix.AlgorithmIdentifier
		Scheme pkix.AlgorithmIdentifier
	}{
		pkix.AlgorithmIdentifier{Algorithm: oidPBKDF2, Parameters: asn1.RawValue{FullBytes: kdf}},
		pkix.AlgorithmIdentifier{Algorithm: oidAES256CBC, Parameters: asn1.RawValue{FullBytes: mustMarshal(t, iv)}},
	})
	return pkix.AlgorithmIdentifier{Algorithm: oidPBES2, Parameters: asn1.RawValue{FullBytes: params}}, ciphertext
}

// encryptedPKCS8PEM is key as an ENCRYPTED PRIVATE KEY, as .NET's ExportEncryptedPkcs8PrivateKeyPem
// writes it with PBES2, AES-256-CBC and SHA-256.
func encryptedPKCS8PEM(t *testing.T, key crypto.Signer, password string, iterations int) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	algorithm, ciphertext := pbes2Encrypt(t, password, iterations, der)
	info := mustMarshal(t, struct {
		Algorithm pkix.AlgorithmIdentifier
		Data      []byte
	}{algorithm, ciphertext})
	return pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: info})
}

// encodePFX writes a PKCS#12 file holding certificates and key (nil for none), protected by
// password, or by none when password is nil.
func encodePFX(t *testing.T, key crypto.Signer, password *string, certificates ...*x509.Certificate) []byte {
	t.Helper()
	bag := func(id asn1.ObjectIdentifier, value []byte) []byte {
		return mustMarshal(t, struct {
			ID    asn1.ObjectIdentifier
			Value asn1.RawValue
		}{id, explicit0(value)})
	}
	data := func(der []byte) rawContentInfo {
		return rawContentInfo{oidData, explicit0(mustMarshal(t, der))}
	}
	sequenceOf := func(elements [][]byte) []byte {
		var body []byte
		for _, e := range elements {
			body = append(body, e...)
		}
		return mustMarshal(t, asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: body})
	}

	var certBags [][]byte
	for _, c := range certificates {
		certBags = append(certBags, bag(oidCertBag, mustMarshal(t, struct {
			ID   asn1.ObjectIdentifier
			Data asn1.RawValue
		}{oidX509CertificateType, explicit0(mustMarshal(t, c.Raw))})))
	}

	var infos []rawContentInfo
	if password == nil {
		bags := certBags
		if key != nil {
			der, _ := x509.MarshalPKCS8PrivateKey(key)
			bags = append(bags, bag(oidKeyBag, der))
		}
		infos = append(infos, data(sequenceOf(bags)))
	} else {
		algorithm, ciphertext := pbes2Encrypt(t, *password, 2048, sequenceOf(certBags))
		encrypted := mustMarshal(t, struct {
			Version int
			Info    struct {
				ContentType asn1.ObjectIdentifier
				Algorithm   pkix.AlgorithmIdentifier
				Content     asn1.RawValue
			}
		}{0, struct {
			ContentType asn1.ObjectIdentifier
			Algorithm   pkix.AlgorithmIdentifier
			Content     asn1.RawValue
		}{oidData, algorithm, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: ciphertext}}})
		infos = append(infos, rawContentInfo{oidEncryptedData, explicit0(encrypted)})
		if key != nil {
			der, _ := x509.MarshalPKCS8PrivateKey(key)
			keyAlgorithm, keyCiphertext := pbes2Encrypt(t, *password, 2048, der)
			shrouded := mustMarshal(t, struct {
				Algorithm pkix.AlgorithmIdentifier
				Data      []byte
			}{keyAlgorithm, keyCiphertext})
			infos = append(infos, data(sequenceOf([][]byte{bag(oidShroudedKeyBag, shrouded)})))
		}
	}
	var encodedInfos [][]byte
	for _, info := range infos {
		encodedInfos = append(encodedInfos, mustMarshal(t, info))
	}
	authSafe := sequenceOf(encodedInfos)

	// The MAC, keyed by the PKCS#12 KDF from the password's BMPString; crypto/hmac computes it.
	pass := ""
	if password != nil {
		pass = *password
	}
	bmp, err := bmpPassword([]byte(pass))
	if err != nil {
		t.Fatal(err)
	}
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	macKey := pkcs12KDF(sha256.New, bmp, salt, 2048, pkcs12MACID, sha256.Size)
	mac := hmac.New(sha256.New, macKey)
	mac.Write(authSafe)

	return mustMarshal(t, struct {
		Version  int
		AuthSafe rawContentInfo
		MacData  struct {
			Mac struct {
				Algorithm pkix.AlgorithmIdentifier
				Digest    []byte
			}
			Salt       []byte
			Iterations int
		}
	}{3, data(authSafe), struct {
		Mac struct {
			Algorithm pkix.AlgorithmIdentifier
			Digest    []byte
		}
		Salt       []byte
		Iterations int
	}{struct {
		Algorithm pkix.AlgorithmIdentifier
		Digest    []byte
	}{pkix.AlgorithmIdentifier{Algorithm: oidSHA256, Parameters: asn1.NullRawValue}, mac.Sum(nil)}, salt, 2048}})
}

func ptr(s string) *string { return &s }
