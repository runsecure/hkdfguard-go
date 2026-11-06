//go:build windows

package certificate

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// The Windows certificate store itself: read-only always, and - with
// HKDFGUARD_TEST_WINDOWS_CERT_STORE=1 - a round trip through a throwaway self-signed certificate
// New-SelfSignedCertificate makes in CurrentUser\My, with a non-exportable CNG key, removed with
// its key afterwards.

func TestTheRealStore_IsOpenedReadOnly(t *testing.T) {
	subject := "CN=hkdfguard-go-test-" + randomHex(t)
	_, err := NewLoader(nil, LoaderOptions{}).Load(&Options{Windows: &StoreOptions{StoreLocation: CurrentUser, Subject: subject}}, "")
	if !errors.Is(err, ErrNotFound) || !strings.Contains(err.Error(), "holds no certificate") {
		t.Fatalf("got %v", err)
	}
}

func TestEveryStoreName_IsAWindowsSystemStore(t *testing.T) {
	for _, known := range storeNames {
		if _, err := readStore(CurrentUser, known.name); err != nil {
			t.Errorf("%s: %v", known.name, err)
		}
	}
	if windowsStoreName(StoreCertificateAuthority) != "CA" || windowsStoreName("Custom") != "Custom" {
		t.Fatal("a store name isn't mapped as .NET maps it")
	}
	// A store that doesn't exist reads as empty, as .NET's does.
	if found, err := readStore(CurrentUser, "hkdfguard-no-such-store-"+StoreName(randomHex(t))); err != nil || len(found) != 0 {
		t.Fatalf("%d certificates, %v", len(found), err)
	}
}

func randomHex(t *testing.T) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// throwawayCertificate makes a self-signed certificate in CurrentUser\My with a non-exportable key
// of keyAlgorithm in the Microsoft Software Key Storage Provider, and removes it, key and all,
// when the test ends. It returns its subject.
func throwawayCertificate(t *testing.T, keyAlgorithm string) string {
	t.Helper()
	subject := "CN=hkdfguard-go-test-" + randomHex(t)
	script := `$ErrorActionPreference = 'Stop'
$c = New-SelfSignedCertificate -Subject '` + subject + `' -CertStoreLocation Cert:\CurrentUser\My ` +
		`-KeyAlgorithm ` + keyAlgorithm + ` -KeyExportPolicy NonExportable -Provider 'Microsoft Software Key Storage Provider' ` +
		`-KeyUsage DigitalSignature,KeyEncipherment -NotAfter (Get-Date).AddDays(2)
$c.Thumbprint`
	out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput()
	if err != nil {
		t.Fatalf("New-SelfSignedCertificate: %v\n%s", err, out)
	}
	thumbprint := strings.TrimSpace(string(out))
	t.Cleanup(func() {
		remove := `Remove-Item -Path Cert:\CurrentUser\My\` + thumbprint + ` -DeleteKey -ErrorAction Stop`
		if out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", remove).CombinedOutput(); err != nil {
			t.Errorf("removing the test certificate %s: %v\n%s", thumbprint, err, out)
		}
	})
	return subject
}

func requireStoreOptIn(t *testing.T) {
	t.Helper()
	if os.Getenv("HKDFGUARD_TEST_WINDOWS_CERT_STORE") != "1" {
		t.Skip("makes and removes a certificate in CurrentUser\\My: set HKDFGUARD_TEST_WINDOWS_CERT_STORE=1")
	}
}

func TestWindowsStore_AnRSAKey_SignsAndDecryptsThroughCNG(t *testing.T) {
	requireStoreOptIn(t)
	subject := throwawayCertificate(t, "RSA -KeyLength 2048")

	c, err := NewLoader(nil, LoaderOptions{}).Load(&Options{Windows: &StoreOptions{StoreLocation: CurrentUser, Subject: subject}}, "")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	public := c.Leaf().PublicKey.(*rsa.PublicKey)
	key := c.PrivateKey()

	for _, hash := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512, crypto.SHA1} {
		h := hash.New()
		h.Write([]byte("to sign"))
		digest := h.Sum(nil)

		signature, err := key.Sign(rand.Reader, digest, hash)
		if err != nil {
			t.Fatalf("PKCS #1 v1.5 %v: %v", hash, err)
		}
		if err := rsa.VerifyPKCS1v15(public, hash, digest, signature); err != nil {
			t.Fatalf("PKCS #1 v1.5 %v: %v", hash, err)
		}
		for _, salt := range []int{rsa.PSSSaltLengthEqualsHash, rsa.PSSSaltLengthAuto, 20} {
			opts := &rsa.PSSOptions{SaltLength: salt, Hash: hash}
			signature, err := key.Sign(rand.Reader, digest, opts)
			if err != nil {
				t.Fatalf("PSS %v salt %d: %v", hash, salt, err)
			}
			if err := rsa.VerifyPSS(public, hash, digest, signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto}); err != nil {
				t.Fatalf("PSS %v salt %d: %v", hash, salt, err)
			}
		}
	}

	decrypter := key.(crypto.Decrypter)
	ciphertext, _ := rsa.EncryptPKCS1v15(rand.Reader, public, []byte("secret"))
	if plaintext, err := decrypter.Decrypt(rand.Reader, ciphertext, nil); err != nil || string(plaintext) != "secret" {
		t.Fatalf("PKCS #1 v1.5: %q, %v", plaintext, err)
	}
	session, err := decrypter.Decrypt(rand.Reader, ciphertext, &rsa.PKCS1v15DecryptOptions{SessionKeyLen: 48})
	if err != nil || len(session) != 48 {
		t.Fatalf("a session key of the wrong length isn't replaced by a random one: %d bytes, %v", len(session), err)
	}
	ciphertext, _ = rsa.EncryptOAEP(sha256.New(), rand.Reader, public, []byte("secret"), []byte("label"))
	if plaintext, err := decrypter.Decrypt(rand.Reader, ciphertext, &rsa.OAEPOptions{Hash: crypto.SHA256, Label: []byte("label")}); err != nil ||
		string(plaintext) != "secret" {
		t.Fatalf("OAEP: %q, %v", plaintext, err)
	}

	assertHandshake(t, c)

	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := key.Sign(rand.Reader, make([]byte, 32), crypto.SHA256); !errors.Is(err, ErrClosed) {
		t.Fatalf("signing after Close: %v", err)
	}
}

func TestWindowsStore_AnECDSAKey_SignsInASN1(t *testing.T) {
	requireStoreOptIn(t)
	subject := throwawayCertificate(t, "ECDSA_nistP256")

	c, err := NewLoader(nil, LoaderOptions{}).Load(&Options{Windows: &StoreOptions{StoreLocation: CurrentUser, Subject: subject}}, "")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	public := c.Leaf().PublicKey.(*ecdsa.PublicKey)
	if _, ok := c.PrivateKey().(crypto.Decrypter); ok {
		t.Fatal("an ECDSA key is a crypto.Decrypter")
	}

	s256, s384 := sha256.Sum256([]byte("to sign")), sha512.Sum384([]byte("to sign"))
	for _, digest := range [][]byte{s256[:], s384[:]} {
		hash := crypto.SHA256
		if len(digest) == 48 {
			hash = crypto.SHA384
		}
		signature, err := c.PrivateKey().Sign(rand.Reader, digest, hash)
		if err != nil {
			t.Fatal(err)
		}
		if !ecdsa.VerifyASN1(public, digest, signature) {
			t.Fatalf("the %v signature doesn't verify", hash)
		}
	}
	assertHandshake(t, c)
}
