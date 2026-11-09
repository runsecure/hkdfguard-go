package certificate

import (
	"crypto"
	"crypto/hmac"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/runsecure/hkdfguard-go"
)

// A minimal PKCS#12 (RFC 7292) reader: password-integrity MACs with HMAC-SHA-1/224/256/384/512;
// unencrypted and password-encrypted contents; key bags, shrouded key bags, certificate bags and
// nested safe contents. Encryption is PBES2 (AES-CBC or 3DES-CBC under PBKDF2) or PKCS#12's own
// 3DES; legacy RC2 and RC4, public-key (enveloped) contents and the newer PBMAC1 MAC are refused.
// The password is a []byte, never a string, and every buffer holding it, anything derived from it,
// or a decrypted key is wiped once used.

var (
	oidData                = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidEncryptedData       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}
	oidKeyBag              = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 1}
	oidShroudedKeyBag      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 2}
	oidCertBag             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 3}
	oidSafeContentsBag     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 6}
	oidX509CertificateType = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 1}
)

type pfxPDU struct {
	Version  int
	AuthSafe contentInfo
	MacData  macData `asn1:"optional"`
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

type macData struct {
	Mac        digestInfo
	MacSalt    []byte
	Iterations int `asn1:"optional,default:1"`
}

type digestInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	Digest    []byte
}

type encryptedData struct {
	Version              int
	EncryptedContentInfo encryptedContentInfo
}

type encryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           asn1.RawValue `asn1:"tag:0,optional"`
}

type safeBag struct {
	ID         asn1.ObjectIdentifier
	Value      asn1.RawValue `asn1:"tag:0,explicit"`
	Attributes asn1.RawValue `asn1:"optional"`
}

type certBag struct {
	ID   asn1.ObjectIdentifier
	Data []byte `asn1:"tag:0,explicit"`
}

type encryptedPrivateKeyInfo struct {
	Algorithm     pkix.AlgorithmIdentifier
	EncryptedData []byte
}

// pkcs12Contents is what a PKCS#12 file holds: its certificates, in file order, and its private
// keys.
type pkcs12Contents struct {
	certificates []*x509.Certificate
	keys         []crypto.Signer
}

// decodePKCS12 reads a PKCS#12 file with a UTF-8 password - nil or empty for a file without one,
// which is tried as both the empty password and no password, as tools write either. A file whose
// MAC doesn't verify fails with ErrWrongPassword.
func decodePKCS12(data, password []byte) (*pkcs12Contents, error) {
	var pfx pfxPDU
	cloned, err := unmarshalBERCloned(data, &pfx)
	if err != nil {
		return nil, fmt.Errorf("%w: not a PKCS#12 file: %v", ErrInvalidFile, err)
	}
	if cloned {
		// A copy of the contents, unencrypted key bags and all; otherwise it is data's own bytes.
		defer hkdfguard.Wipe(pfx.AuthSafe.Content.FullBytes)
	}
	if pfx.Version != 3 {
		return nil, fmt.Errorf("%w: PKCS#12 version %d", ErrUnsupported, pfx.Version)
	}
	if !pfx.AuthSafe.ContentType.Equal(oidData) {
		return nil, fmt.Errorf("%w: a PKCS#12 file signed with a public key (%v)", ErrUnsupported, pfx.AuthSafe.ContentType)
	}
	var authSafe []byte
	err = unmarshalBER(pfx.AuthSafe.Content.Bytes, &authSafe)
	defer hkdfguard.Wipe(authSafe)
	if err != nil {
		return nil, fmt.Errorf("%w: the PKCS#12 contents: %v", ErrInvalidFile, err)
	}

	budget := &iterationBudget{}
	// The passwords to try: the one given; for none, the empty BMPString (00 00) and no bytes at all.
	candidates := [][]byte{password}
	if len(password) == 0 {
		candidates = [][]byte{nil, {}}
	}
	if len(pfx.MacData.Mac.Algorithm.Algorithm) > 0 {
		chosen, err := verifyMAC(pfx.MacData, authSafe, candidates, budget)
		if err != nil {
			return nil, err
		}
		candidates = [][]byte{chosen}
	}

	var lastErr error
	for _, candidate := range candidates {
		contents, err := readAuthenticatedSafe(authSafe, candidate, budget)
		if err == nil {
			return contents, nil
		}
		lastErr = err
		if !errors.Is(err, ErrWrongPassword) {
			break
		}
	}
	return nil, lastErr
}

// verifyMAC checks the file's integrity MAC under each candidate, returning the one it verifies
// under; the "no bytes" candidate is reported as the empty slice, so it is tried as such.
func verifyMAC(mac macData, authSafe []byte, candidates [][]byte, budget *iterationBudget) ([]byte, error) {
	if mac.Mac.Algorithm.Algorithm.Equal(oidPBMAC1) {
		return nil, fmt.Errorf("%w: the PKCS#12 file's PBMAC1 integrity check", ErrUnsupported)
	}
	newHash, ok := digestFor(mac.Mac.Algorithm.Algorithm)
	if !ok {
		return nil, fmt.Errorf("%w: the PKCS#12 MAC algorithm %v", ErrUnsupported, mac.Mac.Algorithm.Algorithm)
	}
	for _, candidate := range candidates {
		if err := budget.spend(mac.Iterations); err != nil {
			return nil, err
		}
		bmp, err := pkcs12Password(candidate)
		if err != nil {
			return nil, err
		}
		key := pkcs12KDF(newHash, bmp, mac.MacSalt, mac.Iterations, pkcs12MACID, newHash().Size())
		hkdfguard.Wipe(bmp)
		m := newMACKey(newHash, key)
		hkdfguard.Wipe(key)
		sum := m.sum(nil, newHash(), newHash(), authSafe)
		m.wipe()
		if hmac.Equal(sum, mac.Mac.Digest) {
			return candidate, nil
		}
	}
	return nil, fmt.Errorf("%w: the PKCS#12 file's integrity check fails", ErrWrongPassword)
}

// readAuthenticatedSafe reads every content of the file's authenticated safe.
func readAuthenticatedSafe(authSafe, password []byte, budget *iterationBudget) (*pkcs12Contents, error) {
	var infos []contentInfo
	cloned, err := unmarshalBERCloned(authSafe, &infos)
	if err != nil {
		return nil, fmt.Errorf("%w: the PKCS#12 authenticated safe: %v", ErrInvalidFile, err)
	}
	if cloned {
		// Copies of the contents. Uncloned, they are authSafe's own bytes, which the next password
		// tried reads again, and which decodePKCS12 wipes.
		defer func() {
			for _, info := range infos {
				hkdfguard.Wipe(info.Content.FullBytes)
			}
		}()
	}
	contents := &pkcs12Contents{}
	fail := func(err error) (*pkcs12Contents, error) {
		contents.wipe()
		return nil, err
	}
	for _, info := range infos {
		var safe []byte
		switch {
		case info.ContentType.Equal(oidData):
			// safe is a copy, holding any unencrypted key bag: it is wiped once read.
			if err := unmarshalBER(info.Content.Bytes, &safe); err != nil {
				hkdfguard.Wipe(safe)
				return fail(fmt.Errorf("%w: PKCS#12 data: %v", ErrInvalidFile, err))
			}
			err := contents.readSafeContents(safe, password, budget, 0)
			hkdfguard.Wipe(safe)
			if err != nil {
				return fail(err)
			}
		case info.ContentType.Equal(oidEncryptedData):
			var encrypted encryptedData
			if err := unmarshalBER(info.Content.Bytes, &encrypted); err != nil {
				return fail(fmt.Errorf("%w: PKCS#12 encrypted data: %v", ErrInvalidFile, err))
			}
			ciphertext, err := implicitOctetString(encrypted.EncryptedContentInfo.EncryptedContent)
			if err != nil {
				return fail(err)
			}
			plaintext, err := decryptPBE(encrypted.EncryptedContentInfo.ContentEncryptionAlgorithm, password, ciphertext, budget)
			if err != nil {
				return fail(err)
			}
			err = contents.readSafeContents(plaintext, password, budget, 0)
			hkdfguard.Wipe(plaintext)
			if err != nil {
				// Contents that decrypted to nonsense were decrypted with the wrong password.
				if errors.Is(err, ErrInvalidFile) {
					err = fmt.Errorf("%w: %v", ErrWrongPassword, err)
				}
				return fail(err)
			}
		default:
			return fail(fmt.Errorf("%w: PKCS#12 contents of type %v", ErrUnsupported, info.ContentType))
		}
	}
	return contents, nil
}

// implicitOctetString is the bytes of a [0] IMPLICIT OCTET STRING, primitive or, in BER,
// constructed of segments.
func implicitOctetString(value asn1.RawValue) ([]byte, error) {
	if !value.IsCompound {
		return value.Bytes, nil
	}
	flat, err := concatenateOctetStrings(value.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: PKCS#12 encrypted content: %v", ErrInvalidFile, err)
	}
	return flat, nil
}

// readSafeContents reads one SafeContents' bags into c.
func (c *pkcs12Contents) readSafeContents(der, password []byte, budget *iterationBudget, depth int) error {
	if depth > 4 {
		return fmt.Errorf("%w: PKCS#12 safe contents nested too deep", ErrInvalidFile)
	}
	var bags []safeBag
	cloned, err := unmarshalBERCloned(der, &bags)
	if err != nil {
		return fmt.Errorf("%w: PKCS#12 safe contents: %v", ErrInvalidFile, err)
	}
	if cloned {
		// Copies of the bags, an unencrypted key bag's key among them. Uncloned, they are der's own
		// bytes, which its caller wipes.
		defer func() {
			for _, bag := range bags {
				hkdfguard.Wipe(bag.Value.FullBytes)
			}
		}()
	}
	for _, bag := range bags {
		switch {
		case bag.ID.Equal(oidCertBag):
			var cert certBag
			if err := unmarshalExact(bag.Value.Bytes, &cert); err != nil {
				return fmt.Errorf("%w: a PKCS#12 certificate bag: %v", ErrInvalidFile, err)
			}
			if !cert.ID.Equal(oidX509CertificateType) {
				continue // an SDSI certificate, say: not one an x509.Certificate can hold
			}
			parsed, err := x509.ParseCertificate(cert.Data)
			if err != nil {
				return fmt.Errorf("%w: a PKCS#12 certificate: %v", ErrInvalidFile, err)
			}
			c.certificates = append(c.certificates, parsed)

		case bag.ID.Equal(oidKeyBag):
			key, err := parsePKCS8(bag.Value.Bytes)
			if err != nil {
				return err
			}
			c.keys = append(c.keys, key)

		case bag.ID.Equal(oidShroudedKeyBag):
			key, err := decryptPKCS8(bag.Value.Bytes, password, budget)
			if err != nil {
				return err
			}
			c.keys = append(c.keys, key)

		case bag.ID.Equal(oidSafeContentsBag):
			if err := c.readSafeContents(bag.Value.Bytes, password, budget, depth+1); err != nil {
				return err
			}
		}
		// CRL and secret bags hold nothing a certificate needs.
	}
	return nil
}

// wipe wipes every key read.
func (c *pkcs12Contents) wipe() {
	for _, key := range c.keys {
		wipeKey(key)
	}
	c.keys = nil
}

// decryptPKCS8 decrypts an EncryptedPrivateKeyInfo with a UTF-8 password and parses the key in it.
func decryptPKCS8(der, password []byte, budget *iterationBudget) (crypto.Signer, error) {
	var info encryptedPrivateKeyInfo
	if err := unmarshalBER(der, &info); err != nil {
		return nil, fmt.Errorf("%w: an encrypted private key: %v", ErrInvalidFile, err)
	}
	plaintext, err := decryptPBE(info.Algorithm, password, info.EncryptedData, budget)
	if err != nil {
		return nil, err
	}
	defer hkdfguard.Wipe(plaintext)
	key, err := parsePKCS8(plaintext)
	if err != nil {
		// A key that decrypted to nonsense was decrypted with the wrong password.
		return nil, fmt.Errorf("%w: the key doesn't decrypt to one", ErrWrongPassword)
	}
	return key, nil
}

// unmarshalBER parses der into out as encoding/asn1 does, and, if that fails, parses its BER
// converted to DER: a file from a tool that writes BER. The converted copy is wiped, as berToDER
// wipes every intermediate copy it makes; what out points into is cloned first.
func unmarshalBER(der []byte, out any) error {
	_, err := unmarshalBERCloned(der, out)
	return err
}

// unmarshalBERCloned is unmarshalBER, reporting whether out's asn1.RawValues were cloned from a
// conversion - copies of their own, which the caller wipes when they may hold a secret - rather
// than pointing into der, which is wiped with der.
func unmarshalBERCloned(der []byte, out any) (cloned bool, err error) {
	err = unmarshalExact(der, out)
	if err == nil {
		return false, nil
	}
	converted, convertErr := berToDER(der)
	if convertErr != nil {
		return false, err
	}
	defer hkdfguard.Wipe(converted)
	if err := unmarshalExact(converted, out); err != nil {
		return false, err
	}
	cloneBytes(out)
	return true, nil
}

// cloneBytes copies every []byte and asn1.RawValue an unmarshaled value points into, so it no
// longer aliases the converted buffer about to be wiped.
func cloneBytes(out any) {
	switch v := out.(type) {
	case *[]byte:
		*v = append([]byte(nil), *v...)
	case *pfxPDU:
		v.AuthSafe.Content = cloneRaw(v.AuthSafe.Content)
		v.MacData.Mac.Algorithm.Parameters = cloneRaw(v.MacData.Mac.Algorithm.Parameters)
		v.MacData.Mac.Digest = append([]byte(nil), v.MacData.Mac.Digest...)
		v.MacData.MacSalt = append([]byte(nil), v.MacData.MacSalt...)
	case *[]contentInfo:
		for i := range *v {
			(*v)[i].Content = cloneRaw((*v)[i].Content)
		}
	case *encryptedData:
		info := &v.EncryptedContentInfo
		info.ContentEncryptionAlgorithm.Parameters = cloneRaw(info.ContentEncryptionAlgorithm.Parameters)
		info.EncryptedContent = cloneRaw(info.EncryptedContent)
	case *[]safeBag:
		for i := range *v {
			(*v)[i].Value = cloneRaw((*v)[i].Value)
			(*v)[i].Attributes = cloneRaw((*v)[i].Attributes)
		}
	case *encryptedPrivateKeyInfo:
		v.Algorithm.Parameters = cloneRaw(v.Algorithm.Parameters)
		v.EncryptedData = append([]byte(nil), v.EncryptedData...)
	}
}

func cloneRaw(raw asn1.RawValue) asn1.RawValue {
	full := append([]byte(nil), raw.FullBytes...)
	raw.Bytes = full[len(full)-len(raw.Bytes):]
	raw.FullBytes = full
	return raw
}
