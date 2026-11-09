package certificate

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509/pkix"
	"encoding"
	"encoding/asn1"
	"fmt"
	"hash"
	"unicode/utf8"

	"github.com/runsecure/hkdfguard-go"
)

// Password-based decryption for PKCS#12 files and encrypted PKCS#8 keys, written here rather than
// taken from crypto/pbkdf2 or a PKCS#12 library because those take the password as a string, which
// can't be wiped. Every buffer holding the password or anything derived from it - the BMPString
// form PKCS#12 hashes, HMAC pads, derived keys and IVs - is a []byte wiped once used. What can't be
// reached is wiped as far as Go allows: crypto/aes and crypto/des keep their own key schedules, and
// the hash states hold only compressed, one-way chaining values.

// The most iterations one key derivation may ask for, and a whole file all its derivations: a
// file can't make loading it take minutes. Generous beside what tools write (OpenSSL 2048,
// Windows 2000-10000, .NET's PBES2 default 100000 and its loader's 600000 cap).
const (
	maxIterations      = 1_000_000
	maxTotalIterations = 4_000_000
)

var (
	oidPBES2                = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2               = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidHMACWithSHA1         = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	oidHMACWithSHA224       = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 8}
	oidHMACWithSHA256       = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidHMACWithSHA384       = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 10}
	oidHMACWithSHA512       = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}
	oidAES128CBC            = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES192CBC            = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	oidAES256CBC            = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidDESEDE3CBC           = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}
	oidPBEWithSHAAnd3DES    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 3}
	oidPBEWithSHAAnd2DES    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 4}
	oidPBEWithSHAAnd128RC2  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 5}
	oidPBEWithSHAAnd40RC2   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 6}
	oidPBEWithSHAAnd128RC4  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 1}
	oidPBEWithSHAAnd40RC4   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 2}
	oidSHA1                 = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA224               = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 4}
	oidSHA256               = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384               = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512               = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	oidPBMAC1               = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 14}
	legacyRC2AndRC4Ciphers  = []asn1.ObjectIdentifier{oidPBEWithSHAAnd128RC2, oidPBEWithSHAAnd40RC2, oidPBEWithSHAAnd128RC4, oidPBEWithSHAAnd40RC4}
	errIterationsOutOfRange = fmt.Errorf("%w: an iteration count is out of range", ErrInvalidFile)
)

// digestFor is the hash a digest algorithm OID names.
func digestFor(oid asn1.ObjectIdentifier) (func() hash.Hash, bool) {
	switch {
	case oid.Equal(oidSHA1):
		return sha1.New, true
	case oid.Equal(oidSHA224):
		return sha256.New224, true
	case oid.Equal(oidSHA256):
		return sha256.New, true
	case oid.Equal(oidSHA384):
		return sha512.New384, true
	case oid.Equal(oidSHA512):
		return sha512.New, true
	}
	return nil, false
}

// prfFor is the hash an HMAC PRF OID names.
func prfFor(oid asn1.ObjectIdentifier) (func() hash.Hash, bool) {
	switch {
	case oid.Equal(oidHMACWithSHA1):
		return sha1.New, true
	case oid.Equal(oidHMACWithSHA224):
		return sha256.New224, true
	case oid.Equal(oidHMACWithSHA256):
		return sha256.New, true
	case oid.Equal(oidHMACWithSHA384):
		return sha512.New384, true
	case oid.Equal(oidHMACWithSHA512):
		return sha512.New, true
	}
	return nil, false
}

// iterationBudget counts the key-derivation iterations one file has spent.
type iterationBudget struct{ spent int }

func (b *iterationBudget) spend(iterations int) error {
	if iterations < 1 || iterations > maxIterations || b.spent+iterations > maxTotalIterations {
		return errIterationsOutOfRange
	}
	b.spent += iterations
	return nil
}

// macKey is a keyed HMAC whose pads are wiped: the inner and outer hash states after the key's
// block, marshaled, so each use restores them instead of hashing the key again.
type macKey struct {
	newHash      func() hash.Hash
	inner, outer []byte
}

func newMACKey(newHash func() hash.Hash, key []byte) *macKey {
	h := newHash()
	blockSize := h.BlockSize()
	pad := make([]byte, blockSize)
	defer hkdfguard.Wipe(pad)
	if len(key) > blockSize {
		h.Write(key)
		sum := h.Sum(nil)
		copy(pad, sum)
		hkdfguard.Wipe(sum)
		h.Reset()
	} else {
		copy(pad, key)
	}

	m := &macKey{newHash: newHash}
	for i := range pad {
		pad[i] ^= 0x36
	}
	h.Write(pad)
	m.inner = marshalState(h)
	for i := range pad {
		pad[i] ^= 0x36 ^ 0x5c
	}
	outer := newHash()
	outer.Write(pad)
	m.outer = marshalState(outer)
	return m
}

func marshalState(h hash.Hash) []byte {
	state, err := h.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		panic("certificate: a standard hash can't be marshaled: " + err.Error()) // every crypto/sha* hash can
	}
	return state
}

func restoreState(h hash.Hash, state []byte) {
	if err := h.(encoding.BinaryUnmarshaler).UnmarshalBinary(state); err != nil {
		panic("certificate: a standard hash can't be unmarshaled: " + err.Error())
	}
}

// sum appends HMAC(key, message...) to dst. inner and outer are hashes to reuse, from newHash.
func (m *macKey) sum(dst []byte, inner, outer hash.Hash, message ...[]byte) []byte {
	restoreState(inner, m.inner)
	for _, part := range message {
		inner.Write(part)
	}
	var innerSum [sha512.Size]byte
	digest := inner.Sum(innerSum[:0])
	restoreState(outer, m.outer)
	outer.Write(digest)
	hkdfguard.Wipe(innerSum[:])
	return outer.Sum(dst)
}

func (m *macKey) wipe() {
	hkdfguard.Wipe(m.inner)
	hkdfguard.Wipe(m.outer)
}

// pbkdf2Derive derives keyLength bytes from password and salt (RFC 8018 5.2), into a buffer the caller
// wipes.
func pbkdf2Derive(newHash func() hash.Hash, password, salt []byte, iterations, keyLength int) []byte {
	prf := newMACKey(newHash, password)
	defer prf.wipe()
	inner, outer := newHash(), newHash()
	size := inner.Size()

	key := make([]byte, 0, (keyLength+size-1)/size*size)
	u := make([]byte, 0, size)
	t := make([]byte, size)
	defer hkdfguard.Wipe(t)
	var index [4]byte
	for block := uint32(1); len(key) < keyLength; block++ {
		index = [4]byte{byte(block >> 24), byte(block >> 16), byte(block >> 8), byte(block)}
		u = prf.sum(u[:0], inner, outer, salt, index[:])
		copy(t, u)
		for range iterations - 1 {
			u = prf.sum(u[:0], inner, outer, u)
			for i := range t {
				t[i] ^= u[i]
			}
		}
		key = append(key, t...)
	}
	hkdfguard.Wipe(u[:cap(u)])
	hkdfguard.Wipe(key[keyLength:])
	return key[:keyLength]
}

// The purposes PKCS#12's key derivation derives for (RFC 7292 B.3).
const (
	pkcs12KeyID = 1
	pkcs12IVID  = 2
	pkcs12MACID = 3
)

// pkcs12KDF derives size bytes from a BMPString password and salt for id (RFC 7292 B.2), into a
// buffer the caller wipes.
func pkcs12KDF(newHash func() hash.Hash, password, salt []byte, iterations int, id byte, size int) []byte {
	h := newHash()
	u, v := h.Size(), h.BlockSize()

	d := make([]byte, v)
	for i := range d {
		d[i] = id
	}
	fill := func(in []byte) []byte {
		if len(in) == 0 {
			return nil
		}
		out := make([]byte, v*((len(in)+v-1)/v))
		for i := range out {
			out[i] = in[i%len(in)]
		}
		return out
	}
	s := fill(salt)
	p := fill(password)
	i := append(s, p...)
	hkdfguard.Wipe(p)
	defer hkdfguard.Wipe(i)

	out := make([]byte, 0, (size+u-1)/u*u)
	a := make([]byte, 0, u)
	b := make([]byte, v)
	defer hkdfguard.Wipe(b)
	for len(out) < size {
		h.Reset()
		h.Write(d)
		h.Write(i)
		a = h.Sum(a[:0])
		for range iterations - 1 {
			h.Reset()
			h.Write(a)
			a = h.Sum(a[:0])
		}
		out = append(out, a...)
		if len(out) >= size {
			break
		}
		for j := range b {
			b[j] = a[j%u]
		}
		// Each v-byte block of I becomes (I_j + B + 1) mod 2^(8v).
		for block := 0; block < len(i); block += v {
			carry := uint16(1)
			for k := v - 1; k >= 0; k-- {
				sum := uint16(i[block+k]) + uint16(b[k]) + carry
				i[block+k] = byte(sum)
				carry = sum >> 8
			}
		}
	}
	hkdfguard.Wipe(a[:cap(a)])
	hkdfguard.Wipe(out[size:])
	return out[:size]
}

// bmpPassword is a UTF-8 password as PKCS#12's key derivation takes it: a BMPString - big-endian
// UTF-16 - with a two-byte terminator, in a buffer the caller wipes. A nil password is the empty
// one, which is the terminator alone.
func bmpPassword(password []byte) ([]byte, error) {
	out := make([]byte, 0, 2*len(password)+2)
	for rest := password; len(rest) > 0; {
		r, size := utf8.DecodeRune(rest)
		if r == utf8.RuneError && size <= 1 {
			hkdfguard.Wipe(out[:cap(out)])
			return nil, fmt.Errorf("%w: the password isn't UTF-8", ErrWrongPassword)
		}
		if r > 0xFFFF {
			r -= 0x10000
			out = append(out, byte(0xD8|r>>18&0x03), byte(r>>10), byte(0xDC|r>>8&0x03), byte(r))
		} else {
			out = append(out, byte(r>>8), byte(r))
		}
		rest = rest[size:]
	}
	return append(out, 0, 0), nil
}

// pkcs12Password is password as PKCS#12's own key derivation takes it: its BMPString, nil being
// the empty password (00 00), and a non-nil empty slice no password at all (no bytes) - the two
// ways tools write a file without one.
func pkcs12Password(password []byte) ([]byte, error) {
	if password != nil && len(password) == 0 {
		return []byte{}, nil
	}
	return bmpPassword(password)
}

type pbes2Params struct {
	KeyDerivationFunc pkix.AlgorithmIdentifier
	EncryptionScheme  pkix.AlgorithmIdentifier
}

type pbkdf2Params struct {
	Salt           []byte
	IterationCount int
	KeyLength      int                      `asn1:"optional"`
	PRF            pkix.AlgorithmIdentifier `asn1:"optional"`
}

type pkcs12PBEParams struct {
	Salt       []byte
	Iterations int
}

// decryptPBE decrypts ciphertext under a password-based encryption algorithm: PBES2 (PBKDF2 with
// HMAC-SHA-1/224/256/384/512, and AES-128/192/256-CBC or 3DES-CBC), or PKCS#12's
// pbeWithSHAAnd3-KeyTripleDES-CBC or 2-KeyTripleDES. password is UTF-8; PBES2 uses it as it is,
// as OpenSSL and .NET do, and PKCS#12's own PBE as a BMPString. The plaintext is in a buffer the
// caller wipes. A wrong password shows as bad padding, ErrWrongPassword.
func decryptPBE(algorithm pkix.AlgorithmIdentifier, password, ciphertext []byte, budget *iterationBudget) ([]byte, error) {
	var (
		block cipher.Block
		iv    []byte
	)
	switch {
	case algorithm.Algorithm.Equal(oidPBES2):
		var params pbes2Params
		if err := unmarshalExact(algorithm.Parameters.FullBytes, &params); err != nil {
			return nil, fmt.Errorf("%w: PBES2 parameters: %v", ErrInvalidFile, err)
		}
		var err error
		block, iv, err = pbes2Cipher(params, password, budget)
		if err != nil {
			return nil, err
		}

	case algorithm.Algorithm.Equal(oidPBEWithSHAAnd3DES), algorithm.Algorithm.Equal(oidPBEWithSHAAnd2DES):
		var params pkcs12PBEParams
		if err := unmarshalExact(algorithm.Parameters.FullBytes, &params); err != nil {
			return nil, fmt.Errorf("%w: PKCS#12 PBE parameters: %v", ErrInvalidFile, err)
		}
		if err := budget.spend(params.Iterations); err != nil {
			return nil, err
		}
		bmp, err := pkcs12Password(password)
		if err != nil {
			return nil, err
		}
		defer hkdfguard.Wipe(bmp)
		keyLength := 24
		if algorithm.Algorithm.Equal(oidPBEWithSHAAnd2DES) {
			keyLength = 16
		}
		key := pkcs12KDF(sha1.New, bmp, params.Salt, params.Iterations, pkcs12KeyID, keyLength)
		defer hkdfguard.Wipe(key)
		if keyLength == 16 { // two-key 3DES is K1 K2 K1
			expanded := make([]byte, 24)
			copy(expanded, key)
			copy(expanded[16:], key[:8])
			hkdfguard.Wipe(key)
			key = expanded
		}
		iv = pkcs12KDF(sha1.New, bmp, params.Salt, params.Iterations, pkcs12IVID, des.BlockSize)
		// Decrypt-only: 3DES is the cipher PKCS#12 defines here, and existing .p12/.pfx files
		// (older Windows and OpenSSL -legacy exports) use it. Nothing is ever encrypted with it.
		if block, err = des.NewTripleDESCipher(key); err != nil { // NOSONAR go:S5547 - decrypting an existing file in its standard format
			return nil, fmt.Errorf("%w: %v", ErrInvalidFile, err)
		}

	default:
		for _, legacy := range legacyRC2AndRC4Ciphers {
			if algorithm.Algorithm.Equal(legacy) {
				return nil, fmt.Errorf("%w: the file is encrypted with legacy RC2 or RC4 (%v); re-export it with AES - "+
					"for instance with openssl pkcs12 -export, without -legacy", ErrUnsupported, algorithm.Algorithm)
			}
		}
		return nil, fmt.Errorf("%w: the encryption algorithm %v", ErrUnsupported, algorithm.Algorithm)
	}
	defer hkdfguard.Wipe(iv)

	if len(ciphertext) == 0 || len(ciphertext)%block.BlockSize() != 0 || len(iv) != block.BlockSize() {
		return nil, fmt.Errorf("%w: the encrypted data isn't whole cipher blocks", ErrInvalidFile)
	}
	plaintext := make([]byte, len(ciphertext))
	// Decrypt-only: PBES2 and PKCS#12 PBE define CBC with PKCS#7 padding, so reading these files
	// requires it. The input is a local file, so there is no padding oracle to query.
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext) // NOSONAR go:S5542 - decrypting an existing file in its standard format

	// PKCS#7 padding, checked whole.
	padding := int(plaintext[len(plaintext)-1])
	if padding == 0 || padding > block.BlockSize() {
		hkdfguard.Wipe(plaintext)
		return nil, ErrWrongPassword
	}
	for _, b := range plaintext[len(plaintext)-padding:] {
		if int(b) != padding {
			hkdfguard.Wipe(plaintext)
			return nil, ErrWrongPassword
		}
	}
	hkdfguard.Wipe(plaintext[len(plaintext)-padding:])
	return plaintext[:len(plaintext)-padding], nil
}

// pbes2Cipher is the block cipher and IV PBES2 parameters name, keyed from password.
func pbes2Cipher(params pbes2Params, password []byte, budget *iterationBudget) (cipher.Block, []byte, error) {
	if !params.KeyDerivationFunc.Algorithm.Equal(oidPBKDF2) {
		return nil, nil, fmt.Errorf("%w: the PBES2 key derivation %v", ErrUnsupported, params.KeyDerivationFunc.Algorithm)
	}
	var kdf pbkdf2Params
	if err := unmarshalExact(params.KeyDerivationFunc.Parameters.FullBytes, &kdf); err != nil {
		return nil, nil, fmt.Errorf("%w: PBKDF2 parameters: %v", ErrInvalidFile, err)
	}
	if err := budget.spend(kdf.IterationCount); err != nil {
		return nil, nil, err
	}
	newHash := sha1.New
	if len(kdf.PRF.Algorithm) > 0 {
		var ok bool
		if newHash, ok = prfFor(kdf.PRF.Algorithm); !ok {
			return nil, nil, fmt.Errorf("%w: the PBKDF2 PRF %v", ErrUnsupported, kdf.PRF.Algorithm)
		}
	}

	scheme := params.EncryptionScheme
	var keyLength int
	var newCipher func([]byte) (cipher.Block, error)
	switch {
	case scheme.Algorithm.Equal(oidAES128CBC):
		keyLength, newCipher = 16, aes.NewCipher
	case scheme.Algorithm.Equal(oidAES192CBC):
		keyLength, newCipher = 24, aes.NewCipher
	case scheme.Algorithm.Equal(oidAES256CBC):
		keyLength, newCipher = 32, aes.NewCipher
	case scheme.Algorithm.Equal(oidDESEDE3CBC):
		keyLength, newCipher = 24, des.NewTripleDESCipher
	default:
		return nil, nil, fmt.Errorf("%w: the PBES2 cipher %v", ErrUnsupported, scheme.Algorithm)
	}
	if kdf.KeyLength != 0 && kdf.KeyLength != keyLength {
		return nil, nil, fmt.Errorf("%w: PBKDF2's key length doesn't fit its cipher", ErrInvalidFile)
	}
	var iv []byte
	if err := unmarshalExact(scheme.Parameters.FullBytes, &iv); err != nil {
		return nil, nil, fmt.Errorf("%w: the cipher's IV: %v", ErrInvalidFile, err)
	}

	key := pbkdf2Derive(newHash, password, kdf.Salt, kdf.IterationCount, keyLength)
	defer hkdfguard.Wipe(key)
	block, err := newCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidFile, err)
	}
	return block, iv, nil
}

// unmarshalExact parses DER into out, refusing anything after it.
func unmarshalExact(der []byte, out any) error {
	rest, err := asn1.Unmarshal(der, out)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return fmt.Errorf("trailing data after the %T", out)
	}
	return nil
}
