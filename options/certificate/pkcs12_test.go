package certificate

import (
	"bytes"
	"crypto/pbkdf2"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"hash"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/runsecure/hkdfguard-go"
)

// The PKCS#12 and encrypted PKCS#8 reader against files other tools wrote, in testdata:
//
//	openssl req -x509 -newkey rsa:2048 -nodes -keyout rsa.key -out rsa.crt -days 3650 -subj "/O=Contoso/CN=api.example.com"
//	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ec.key -out ec.crt -days 3650 -subj "/O=Contoso/CN=api.example.com"
//	openssl pkcs12 -export -in rsa.crt -inkey rsa.key -out openssl-aes.pfx -passout file:pw.txt     # PBES2 AES-256, SHA-256 MAC
//	openssl pkcs12 -export ... -out openssl-3des.pfx -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1
//	openssl pkcs12 -export -in ec.crt -inkey ec.key -out openssl-ec.pfx -passout file:pw.txt
//	openssl pkcs12 -export ... -out openssl-nopass.pfx -passout pass: -keypbe NONE -certpbe NONE
//	openssl pkcs12 -export ... -out openssl-rc2.pfx -passout file:pw.txt -legacy                    # RC2-40 certificates
//	openssl pkcs8 -topk8 -in rsa.key -out rsa-encrypted.key -v2 aes-256-cbc -v2prf hmacWithSHA256 -iter 100000 -passout file:pw.txt
//	openssl pkcs8 -topk8 -in ec.key -out ec-encrypted.key -v2 aes-128-cbc -passout file:pw.txt     # PBKDF2-HMAC-SHA-256 by default
//
// and, from openssl-aes.pfx, by .NET 10 on Windows 11 (PowerShell 7.6):
//
//	dotnet-default.pfx     X509Certificate2.Export(Pkcs12, password)  - 3DES, SHA-1 MAC, as Windows writes
//	dotnet-nopassword.pfx  X509Certificate2.Export(Pkcs12)            - no password
//	dotnet-aes.pfx         ExportPkcs12(Pkcs12ExportPbeParameters.Pbes2Aes256Sha256, password)
//	dotnet-encrypted.key   RSA.ExportEncryptedPkcs8PrivateKeyPem(password, PBES2 AES-256-CBC SHA-256 100000)
//
// where pw.txt holds testPassword, UTF-8, with no newline.

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func fixtureCertificate(t *testing.T, name string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(readFixture(t, name))
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestOtherToolsPKCS12Files_AreRead(t *testing.T) {
	rsaCertificate := fixtureCertificate(t, "rsa.crt")
	for _, c := range []struct {
		file     string
		password []byte
		want     *x509.Certificate
	}{
		{"openssl-aes.pfx", []byte(testPassword), rsaCertificate},
		{"openssl-3des.pfx", []byte(testPassword), rsaCertificate},
		{"openssl-ec.pfx", []byte(testPassword), fixtureCertificate(t, "ec.crt")},
		{"openssl-nopass.pfx", nil, rsaCertificate},
		{"dotnet-default.pfx", []byte(testPassword), rsaCertificate},
		{"dotnet-aes.pfx", []byte(testPassword), rsaCertificate},
		{"dotnet-nopassword.pfx", nil, rsaCertificate},
	} {
		t.Run(c.file, func(t *testing.T) {
			contents, err := decodePKCS12(readFixture(t, c.file), c.password)
			if err != nil {
				t.Fatal(err)
			}
			defer contents.wipe()
			if len(contents.certificates) != 1 || !bytes.Equal(contents.certificates[0].Raw, c.want.Raw) {
				t.Fatal("not the certificate the file holds")
			}
			if len(contents.keys) != 1 || !publicKeyMatches(c.want, contents.keys[0]) {
				t.Fatal("not the certificate's key")
			}

			if c.password != nil {
				if _, err := decodePKCS12(readFixture(t, c.file), []byte("wrong")); !errors.Is(err, ErrWrongPassword) {
					t.Fatalf("a wrong password: %v", err)
				}
			}
		})
	}
}

// Through the Loader, a fixture loads from a path, with the password from the source.
func TestAnOpenSSLPfx_LoadsThroughTheLoader_AndServesTLS(t *testing.T) {
	leaf := fixtureCertificate(t, "rsa.crt")
	loader := newLoader(newFakePasswords(), LoaderOptions{Now: func() time.Time { return leaf.NotBefore.Add(time.Hour) }},
		newValidatorFor(platformWindows), nil)
	path, _ := filepath.Abs(filepath.Join("testdata", "openssl-aes.pfx"))

	c := mustLoad(t, loader, pfxOptions(path, "tls-password", false, true))

	assertSigns(t, c)
	assertHandshake(t, c)
}

func TestOtherToolsEncryptedPKCS8Keys_AreRead(t *testing.T) {
	for file, certificate := range map[string]string{
		"rsa-encrypted.key":    "rsa.crt",
		"ec-encrypted.key":     "ec.crt",
		"dotnet-encrypted.key": "rsa.crt",
	} {
		t.Run(file, func(t *testing.T) {
			key, err := parsePEMKey(readFixture(t, file), []byte(testPassword), true)
			if err != nil {
				t.Fatal(err)
			}
			defer wipeKey(key)
			if !publicKeyMatches(fixtureCertificate(t, certificate), key) {
				t.Fatal("not the certificate's key")
			}
			if _, err := parsePEMKey(readFixture(t, file), []byte("wrong"), true); !errors.Is(err, ErrWrongPassword) {
				t.Fatalf("a wrong password: %v", err)
			}
		})
	}
}

func TestALegacyRC2File_IsRefused_SayingHowToReExportIt(t *testing.T) {
	_, err := decodePKCS12(readFixture(t, "openssl-rc2.pfx"), []byte(testPassword))
	if !errors.Is(err, ErrUnsupported) || !bytes.Contains([]byte(err.Error()), []byte("re-export it with AES")) {
		t.Fatalf("got %v", err)
	}
}

func TestALegacyEncryptedPEMKey_IsRefused(t *testing.T) {
	legacy := []byte("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,00000000000000000000000000000000\n\nAAAA\n-----END RSA PRIVATE KEY-----\n")
	if _, err := parsePEMKey(legacy, []byte(testPassword), true); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("got %v", err)
	}
	if _, err := parsePEMKey([]byte("no key here"), nil, false); !errors.Is(err, ErrInvalidFile) {
		t.Fatalf("got %v", err)
	}
}

// A BER file - indefinite lengths and constructed OCTET STRINGs, as NSS writes - reads as its DER
// form does.
func TestABERPfx_IsReadAsItsDERIs(t *testing.T) {
	der := readFixture(t, "openssl-aes.pfx")
	ber := toBER(t, der)
	if bytes.Equal(ber, der) {
		t.Fatal("the BER form is the DER form")
	}
	back, err := berToDER(ber)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, der) {
		t.Fatal("BER doesn't convert back to the DER it came from")
	}
	if _, err := berToDER(der); err != nil {
		t.Fatal(err)
	}

	contents, err := decodePKCS12(ber, []byte(testPassword))
	if err != nil {
		t.Fatal(err)
	}
	contents.wipe()

	for _, broken := range [][]byte{{0x30}, {0x30, 0x80, 0x04, 0x01}, {0x04, 0x80, 0x00, 0x00}, {0x30, 0x85, 1, 2, 3, 4, 5}, {0x24, 0x03, 0x02, 0x01, 0x00}} {
		if _, err := berToDER(broken); err == nil {
			t.Errorf("% x converted", broken)
		}
	}
}

// Values parsed from DER point into it, and are wiped with it; values parsed from a BER conversion
// are copies, which the decoder must be told about to wipe them.
func TestUnmarshalBERCloned_ReportsCopiesOnlyForBER(t *testing.T) {
	der := readFixture(t, "openssl-aes.pfx")
	var fromDER pfxPDU
	if cloned, err := unmarshalBERCloned(der, &fromDER); err != nil || cloned {
		t.Fatalf("DER: cloned %v, %v; want false, nil", cloned, err)
	}
	var fromBER pfxPDU
	ber := toBER(t, der)
	if cloned, err := unmarshalBERCloned(ber, &fromBER); err != nil || !cloned {
		t.Fatalf("BER: cloned %v, %v; want true, nil", cloned, err)
	}
	// The clone is its own memory: wiping it leaves the file as it was.
	before := append([]byte(nil), ber...)
	hkdfguard.Wipe(fromBER.AuthSafe.Content.FullBytes)
	if !bytes.Equal(ber, before) {
		t.Fatal("the BER value aliases the file")
	}
}

// toBER rewrites DER's outermost SEQUENCE and the authenticated safe's OCTET STRING with
// indefinite lengths, the OCTET STRING split into two constructed segments.
func toBER(t *testing.T, der []byte) []byte {
	t.Helper()
	var convert func(in []byte) []byte
	convert = func(in []byte) []byte {
		var out []byte
		for len(in) > 0 {
			identifier := in[0]
			length, lengthLen, err := berLength(in[1:])
			if err != nil {
				t.Fatal(err)
			}
			content := in[1+lengthLen : 1+lengthLen+length]
			in = in[1+lengthLen+length:]
			switch {
			case identifier&0x20 != 0: // constructed: indefinite, its children converted
				out = append(out, identifier, 0x80)
				out = append(out, convert(content)...)
				out = append(out, 0, 0)
			case identifier == 0x04 && len(content) > 64: // a long OCTET STRING: two segments
				half := len(content) / 2
				out = append(out, 0x24, 0x80)
				out = append(out, encodeTLV([]byte{0x04}, content[:half])...)
				out = append(out, encodeTLV([]byte{0x04}, content[half:])...)
				out = append(out, 0, 0)
			default:
				out = append(out, encodeTLV([]byte{identifier}, content)...)
			}
		}
		return out
	}
	return convert(der)
}

func TestPBKDF2_IsTheStandardLibrarys(t *testing.T) {
	for _, h := range []func() hash.Hash{sha1.New, sha256.New, sha512.New} {
		for _, length := range []int{16, 32, 70} {
			want, _ := pbkdf2.Key(h, testPassword, []byte("salt-salt"), 1000, length)
			if got := pbkdf2Key(h, []byte(testPassword), []byte("salt-salt"), 1000, length); !bytes.Equal(got, want) {
				t.Fatalf("%d bytes differ", length)
			}
		}
	}
	// A key longer than the hash's block is hashed first, as HMAC says.
	long := bytes.Repeat([]byte("k"), 200)
	want, _ := pbkdf2.Key(sha256.New, string(long), []byte("s"), 3, 32)
	if got := pbkdf2Key(sha256.New, long, []byte("s"), 3, 32); !bytes.Equal(got, want) {
		t.Fatal("a long password differs")
	}
}

func pbkdf2Key(h func() hash.Hash, password, salt []byte, iterations, length int) []byte {
	return pbkdf2Derive(h, password, salt, iterations, length)
}

func TestTheBMPPassword_IsBigEndianUTF16_WithATerminator(t *testing.T) {
	got, err := bmpPassword([]byte("aé😀"))
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{0, 'a', 0, 0xe9, 0xd8, 0x3d, 0xde, 0x00, 0, 0}; !bytes.Equal(got, want) {
		t.Fatalf("% x", got)
	}
	if empty, _ := bmpPassword(nil); !bytes.Equal(empty, []byte{0, 0}) {
		t.Fatalf("% x", empty)
	}
	if _, err := bmpPassword([]byte{0xff}); !errors.Is(err, ErrWrongPassword) {
		t.Fatal("a password that isn't UTF-8 was taken")
	}
	if none, _ := pkcs12Password([]byte{}); len(none) != 0 {
		t.Fatal("no password isn't empty")
	}
}

func TestAnIterationCount_IsBounded(t *testing.T) {
	budget := &iterationBudget{}
	for _, n := range []int{0, -1, maxIterations + 1} {
		if err := budget.spend(n); !errors.Is(err, ErrInvalidFile) {
			t.Fatalf("%d iterations: %v", n, err)
		}
	}
	for range maxTotalIterations / maxIterations {
		if err := budget.spend(maxIterations); err != nil {
			t.Fatal(err)
		}
	}
	if err := budget.spend(1); err == nil {
		t.Fatal("a file's total isn't bounded")
	}
}
