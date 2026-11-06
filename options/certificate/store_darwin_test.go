//go:build darwin && cgo

package certificate

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

// The macOS keychains themselves: read-only always, and - with HKDFGUARD_TEST_MACOS_KEYCHAIN=1 - a
// round trip through a throwaway identity imported into the login keychain, deleted afterwards.

func randomSubjectSuffix(t *testing.T) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func TestTheRealKeychain_IsOpenedReadOnly(t *testing.T) {
	for _, location := range []StoreLocation{CurrentUser, LocalMachine} {
		subject := "CN=hkdfguard-go-test-" + randomSubjectSuffix(t)
		_, err := NewLoader(nil, LoaderOptions{}).Load(&Options{MacOS: &StoreOptions{StoreLocation: location, Subject: subject}}, "")
		if !errors.Is(err, ErrNotFound) || !strings.Contains(err.Error(), "holds no certificate") {
			t.Fatalf("%s: %v", location, err)
		}
	}
}

func TestOnlyTheMyStore_IsAKeychain(t *testing.T) {
	if _, err := readStore(CurrentUser, StoreRoot); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("got %v", err)
	}
}

func TestKeychain_AnIdentity_SignsThroughTheSecurityFramework(t *testing.T) {
	if os.Getenv("HKDFGUARD_TEST_MACOS_KEYCHAIN") != "1" {
		t.Skip("imports and deletes an identity in the login keychain: set HKDFGUARD_TEST_MACOS_KEYCHAIN=1")
	}
	for name, keyArgs := range map[string][]string{
		"RSA":   {"-newkey", "rsa:2048"},
		"ECDSA": {"-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1"},
	} {
		t.Run(name, func(t *testing.T) {
			subject := "CN=hkdfguard-go-test-" + randomSubjectSuffix(t)
			importIdentity(t, subject, keyArgs)

			c, err := NewLoader(nil, LoaderOptions{}).Load(&Options{MacOS: &StoreOptions{StoreLocation: CurrentUser, Subject: subject}}, "")
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			digest := sha256.Sum256([]byte("to sign"))
			switch public := c.Leaf().PublicKey.(type) {
			case *rsa.PublicKey:
				signature, err := c.PrivateKey().Sign(rand.Reader, digest[:], crypto.SHA256)
				if err != nil || rsa.VerifyPKCS1v15(public, crypto.SHA256, digest[:], signature) != nil {
					t.Fatalf("PKCS #1 v1.5: %v", err)
				}
				pss := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
				signature, err = c.PrivateKey().Sign(rand.Reader, digest[:], pss)
				if err != nil || rsa.VerifyPSS(public, crypto.SHA256, digest[:], signature, pss) != nil {
					t.Fatalf("PSS: %v", err)
				}
			case *ecdsa.PublicKey:
				signature, err := c.PrivateKey().Sign(rand.Reader, digest[:], crypto.SHA256)
				if err != nil || !ecdsa.VerifyASN1(public, digest[:], signature) {
					t.Fatalf("ECDSA: %v", err)
				}
			}
			assertHandshake(t, c)
		})
	}
}

// importIdentity makes a self-signed certificate and key with openssl, imports them into the
// login keychain, open to every application (-A) so no dialog asks, and deletes the identity when
// the test ends.
func importIdentity(t *testing.T, subject string, keyArgs []string) {
	t.Helper()
	dir := t.TempDir()
	key, cert, pfx := filepath.Join(dir, "k.pem"), filepath.Join(dir, "c.pem"), filepath.Join(dir, "i.p12")
	run := func(name string, args ...string) {
		t.Helper()
		if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
			t.Fatalf("%s %v: %v\n%s", name, args, err, out)
		}
	}
	run("/usr/bin/openssl", append(append([]string{"req", "-x509"}, keyArgs...),
		"-nodes", "-keyout", key, "-out", cert, "-days", "2", "-subj", "/"+subject)...)
	run("/usr/bin/openssl", "pkcs12", "-export", "-in", cert, "-inkey", key, "-out", pfx, "-passout", "pass:test")

	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	keychain := filepath.Join(account.HomeDir, "Library", "Keychains", "login.keychain-db")
	run("/usr/bin/security", "import", pfx, "-k", keychain, "-P", "test", "-A")

	certificates, err := parseCertificates(mustRead(t, cert))
	if err != nil {
		t.Fatal(err)
	}
	thumbprint := sha1.Sum(certificates[0].Raw)
	t.Cleanup(func() {
		if out, err := exec.Command("/usr/bin/security", "delete-identity", "-Z", hex.EncodeToString(thumbprint[:]), keychain).CombinedOutput(); err != nil {
			t.Errorf("deleting the test identity: %v\n%s", err, out)
		}
	})
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
