package certificate

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// A distinguished name, decoded: its relative distinguished names in the order it is written -
// most specific first, "CN=api.example.com, O=Contoso" - each one or more attributes. A
// certificate's subject is encoded the other way round, so it is reversed as it is read, as .NET's
// X500DistinguishedName.Name and Windows render it.
type distinguishedName [][]attribute

type attribute struct {
	oid   asn1.ObjectIdentifier
	value string
}

// The attribute keywords a configured subject may use, as Windows' CertStrToName and .NET accept
// them, upper-cased; and the one each type is written with.
var (
	attributeKeywords = map[string]asn1.ObjectIdentifier{
		"CN":                  {2, 5, 4, 3},
		"SN":                  {2, 5, 4, 4},
		"SERIALNUMBER":        {2, 5, 4, 5},
		"C":                   {2, 5, 4, 6},
		"L":                   {2, 5, 4, 7},
		"S":                   {2, 5, 4, 8},
		"ST":                  {2, 5, 4, 8},
		"STREET":              {2, 5, 4, 9},
		"O":                   {2, 5, 4, 10},
		"OU":                  {2, 5, 4, 11},
		"T":                   {2, 5, 4, 12},
		"TITLE":               {2, 5, 4, 12},
		"DESCRIPTION":         {2, 5, 4, 13},
		"POSTALCODE":          {2, 5, 4, 17},
		"G":                   {2, 5, 4, 42},
		"GN":                  {2, 5, 4, 42},
		"GIVENNAME":           {2, 5, 4, 42},
		"I":                   {2, 5, 4, 43},
		"INITIALS":            {2, 5, 4, 43},
		"DNQUALIFIER":         {2, 5, 4, 46},
		"DC":                  {0, 9, 2342, 19200300, 100, 1, 25},
		"UID":                 {0, 9, 2342, 19200300, 100, 1, 1},
		"E":                   {1, 2, 840, 113549, 1, 9, 1},
		"EMAIL":               {1, 2, 840, 113549, 1, 9, 1},
		"EMAILADDRESS":        {1, 2, 840, 113549, 1, 9, 1},
		"UNSTRUCTUREDNAME":    {1, 2, 840, 113549, 1, 9, 2},
		"UNSTRUCTUREDADDRESS": {1, 2, 840, 113549, 1, 9, 8},
	}
	attributeNames = map[string]string{
		"2.5.4.3": "CN", "2.5.4.4": "SN", "2.5.4.5": "SERIALNUMBER", "2.5.4.6": "C", "2.5.4.7": "L",
		"2.5.4.8": "S", "2.5.4.9": "STREET", "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.12": "T",
		"2.5.4.13": "DESCRIPTION", "2.5.4.17": "PostalCode", "2.5.4.42": "G", "2.5.4.43": "I",
		"2.5.4.46": "DNQualifier", "0.9.2342.19200300.100.1.25": "DC", "0.9.2342.19200300.100.1.1": "UID",
		"1.2.840.113549.1.9.1": "E", "1.2.840.113549.1.9.2": "unstructuredName",
	}
)

var errNotADistinguishedName = errors.New("not a distinguished name")

// parseDistinguishedName parses a distinguished name as configuration writes it:
// "CN=api.example.com, O=Contoso". Relative names are separated by ',' or ';', attributes within
// one by '+'; a type is a keyword (CN, O, OU, L, S, C, E, DC, ...) or a dotted OID, optionally
// "OID."-prefixed; a value may be double-quoted, and '\' escapes the next character or two hex
// digits. Space around types and values is ignored.
func parseDistinguishedName(s string) (distinguishedName, error) {
	var (
		name    distinguishedName
		current []attribute
	)
	rest := s
	for {
		attr, next, separator, err := parseAttribute(rest)
		if err != nil {
			return nil, err
		}
		current = append(current, attr)
		if separator != '+' {
			name = append(name, current)
			current = nil
		}
		if separator == 0 {
			return name, nil
		}
		rest = next
	}
}

// parseAttribute parses one "type=value" from the start of s, returning what follows its
// separator, and the separator (',' ';' '+'), or 0 at the end.
func parseAttribute(s string) (attribute, string, byte, error) {
	equals := strings.IndexByte(s, '=')
	if equals < 0 {
		return attribute{}, "", 0, errNotADistinguishedName
	}
	oid, err := attributeType(strings.TrimSpace(s[:equals]))
	if err != nil {
		return attribute{}, "", 0, err
	}

	rest := strings.TrimLeft(s[equals+1:], " ")
	var value strings.Builder
	quoted := strings.HasPrefix(rest, `"`)
	i := 0
	if quoted {
		i = 1
	}
	// trailing is the length of value up to its last non-space, unescaped character: unquoted
	// values lose trailing spaces, but not escaped ones.
	trailing := 0
	for ; i < len(rest); i++ {
		c := rest[i]
		switch {
		case c == '\\':
			if i+1 >= len(rest) {
				return attribute{}, "", 0, errNotADistinguishedName
			}
			if i+2 < len(rest) && isHex(rest[i+1]) && isHex(rest[i+2]) {
				b, _ := hex.DecodeString(rest[i+1 : i+3])
				value.WriteByte(b[0])
				i += 2
			} else {
				value.WriteByte(rest[i+1])
				i++
			}
			trailing = value.Len()
		case quoted && c == '"':
			if i+1 < len(rest) && rest[i+1] == '"' { // "" is a quote, as Windows writes one
				value.WriteByte('"')
				i++
				trailing = value.Len()
				continue
			}
			after := strings.TrimLeft(rest[i+1:], " ")
			if after == "" {
				return attribute{oid, value.String()}, "", 0, nil
			}
			if after[0] != ',' && after[0] != ';' && after[0] != '+' {
				return attribute{}, "", 0, errNotADistinguishedName
			}
			return attribute{oid, value.String()}, after[1:], after[0], nil
		case !quoted && (c == ',' || c == ';' || c == '+'):
			return attribute{oid, value.String()[:trailing]}, rest[i+1:], c, nil
		default:
			value.WriteByte(c)
			if c != ' ' || quoted {
				trailing = value.Len()
			}
		}
	}
	if quoted {
		return attribute{}, "", 0, errNotADistinguishedName // no closing quote
	}
	return attribute{oid, value.String()[:trailing]}, "", 0, nil
}

// attributeType is the OID a keyword or dotted OID names.
func attributeType(keyword string) (asn1.ObjectIdentifier, error) {
	if oid, ok := attributeKeywords[strings.ToUpper(keyword)]; ok {
		return oid, nil
	}
	dotted := keyword
	if len(dotted) > 4 && strings.EqualFold(dotted[:4], "OID.") {
		dotted = dotted[4:]
	}
	parts := strings.Split(dotted, ".")
	if len(parts) < 2 {
		return nil, errNotADistinguishedName
	}
	oid := make(asn1.ObjectIdentifier, len(parts))
	for i, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 || part == "" || part[0] == '+' {
			return nil, errNotADistinguishedName
		}
		oid[i] = n
	}
	return oid, nil
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

// subjectOf is a certificate's subject, decoded, most specific relative name first.
func subjectOf(certificate *x509.Certificate) (distinguishedName, error) {
	var sequence pkix.RDNSequence
	rest, err := asn1.Unmarshal(certificate.RawSubject, &sequence)
	if err != nil || len(rest) != 0 {
		return nil, fmt.Errorf("the certificate's subject isn't a distinguished name: %v", err)
	}
	name := make(distinguishedName, 0, len(sequence))
	for i := len(sequence) - 1; i >= 0; i-- {
		rdn := make([]attribute, 0, len(sequence[i]))
		for _, atv := range sequence[i] {
			rdn = append(rdn, attribute{atv.Type, attributeValue(atv.Value)})
		}
		name = append(name, rdn)
	}
	return name, nil
}

// attributeValue is an attribute's value as text: every string type decoded, anything else as Go
// formats it.
func attributeValue(value any) string {
	if s, ok := value.(string); ok {
		return s
	}
	return fmt.Sprint(value)
}

// equalFold reports whether two names are the same, attribute by attribute, comparing values
// ignoring case.
func (d distinguishedName) equalFold(other distinguishedName) bool {
	if len(d) != len(other) {
		return false
	}
	for i := range d {
		if len(d[i]) != len(other[i]) {
			return false
		}
		for j := range d[i] {
			if !d[i][j].oid.Equal(other[i][j].oid) || !strings.EqualFold(d[i][j].value, other[i][j].value) {
				return false
			}
		}
	}
	return true
}

// String renders the name as .NET and Windows do: "CN=api.example.com, O=Contoso", a value
// quoted when it holds a separator, a quote or surrounding space.
func (d distinguishedName) String() string {
	var b strings.Builder
	for i, rdn := range d {
		if i > 0 {
			b.WriteString(", ")
		}
		for j, attr := range rdn {
			if j > 0 {
				b.WriteString(" + ")
			}
			if keyword, ok := attributeNames[attr.oid.String()]; ok {
				b.WriteString(keyword)
			} else {
				b.WriteString("OID." + attr.oid.String())
			}
			b.WriteByte('=')
			b.WriteString(quoteValue(attr.value))
		}
	}
	return b.String()
}

func quoteValue(v string) string {
	needsQuotes := v != strings.TrimFunc(v, unicode.IsSpace) || strings.ContainsAny(v, ",;+=\"\\<>#\n")
	if !needsQuotes {
		return v
	}
	return `"` + strings.ReplaceAll(v, `"`, `""`) + `"`
}

// describeSubject is a certificate's subject as messages name it.
func describeSubject(certificate *x509.Certificate) string {
	if name, err := subjectOf(certificate); err == nil {
		return name.String()
	}
	return certificate.Subject.String()
}
