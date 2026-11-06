package certificate

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

// Distinguished names: what a configured subject parses into, and how a certificate's subject -
// encoded as Go's own x509 package writes one, so independently of the parser - compares to it.

func certificateWithSubject(t *testing.T, subject pkix.Name) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: subject, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, testKey().Public(), testKey())
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

func TestASubject_MatchesTheCertificatesWholeSubject_IgnoringCase(t *testing.T) {
	c := certificateWithSubject(t, pkix.Name{CommonName: "api.example.com", Organization: []string{"Contoso"}, Country: []string{"US"}})
	subject, err := subjectOf(c)
	if err != nil {
		t.Fatal(err)
	}
	if got := subject.String(); got != "CN=api.example.com, O=Contoso, C=US" {
		t.Fatalf("rendered %q", got)
	}

	for configured, want := range map[string]bool{
		"CN=api.example.com, O=Contoso, C=US":                 true,
		"cn=API.EXAMPLE.COM;o=contoso;c=us":                   true,
		"  CN = api.example.com ,O=Contoso,   C=US  ":         true,
		`CN="api.example.com", O="Contoso", C=US`:             true,
		"OID.2.5.4.3=api.example.com, 2.5.4.10=Contoso, C=US": true,
		"CN=api.example.com, O=Contoso":                       false, // a part of it
		"CN=api.example.com, O=Contoso, C=US, L=Here":         false,
		"O=Contoso, CN=api.example.com, C=US":                 false, // another order
		"CN=api.example.co, O=Contoso, C=US":                  false,
		"CN=api.example.com + O=Contoso, C=US":                false, // one relative name of two
	} {
		name, err := parseDistinguishedName(configured)
		if err != nil {
			t.Fatalf("%q: %v", configured, err)
		}
		if got := name.equalFold(subject); got != want {
			t.Errorf("%q matches: %v, want %v", configured, got, want)
		}
	}
}

func TestASubjectValue_MayBeQuotedOrEscaped(t *testing.T) {
	c := certificateWithSubject(t, pkix.Name{CommonName: `Contoso, "Ltd" + more`, OrganizationalUnit: []string{" padded "}})
	subject, _ := subjectOf(c)

	for _, configured := range []string{
		`CN="Contoso, ""Ltd"" + more", OU=" padded "`,
		`CN=Contoso\, \"Ltd\" \+ more, OU=\20padded\20`,
		`CN=Contoso\2C \22Ltd\22 \2B more, OU="\ padded "`,
	} {
		name, err := parseDistinguishedName(configured)
		if err != nil {
			t.Fatalf("%q: %v", configured, err)
		}
		if !name.equalFold(subject) {
			t.Errorf("%q doesn't match %s", configured, subject)
		}
	}
	if got := subject.String(); got != `OU=" padded ", CN="Contoso, ""Ltd"" + more"` && got != `CN="Contoso, ""Ltd"" + more", OU=" padded "` {
		t.Fatalf("rendered %q", got)
	}
}

func TestAMultiValuedRelativeName_MatchesItsAttributesInOrder(t *testing.T) {
	sequence := pkix.RDNSequence{
		{{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "Contoso"}},
		{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "api"}, {Type: asn1.ObjectIdentifier{2, 5, 4, 11}, Value: "Web"}},
	}
	raw, _ := asn1.Marshal(sequence)
	subject, err := subjectOf(&x509.Certificate{RawSubject: raw})
	if err != nil {
		t.Fatal(err)
	}
	name, _ := parseDistinguishedName("CN=api + OU=Web, O=Contoso")
	if !name.equalFold(subject) || subject.String() != "CN=api + OU=Web, O=Contoso" {
		t.Fatalf("%s", subject)
	}
}

func TestWhatIsntADistinguishedName_IsRefused(t *testing.T) {
	for _, s := range []string{"", "api.example.com", "CN", "XX=api", "CN=a, ", `CN="a" b`, `CN="a`, `CN=a\`, "1=a", "OID.x.y=a", "2.5.-4=a"} {
		if _, err := parseDistinguishedName(s); err == nil {
			t.Errorf("%q parsed", s)
		}
	}
}

func TestAnUnknownAttribute_IsRenderedByItsOID(t *testing.T) {
	name, err := parseDistinguishedName("1.2.3.4=value, CN=x")
	if err != nil {
		t.Fatal(err)
	}
	if got := name.String(); got != "OID.1.2.3.4=value, CN=x" {
		t.Fatal(got)
	}
	if got := attributeValue(42); got != "42" {
		t.Fatal(got)
	}
	if _, err := subjectOf(&x509.Certificate{RawSubject: []byte{0x30, 0x03}}); err == nil {
		t.Fatal("a broken subject parsed")
	}
}
