package certificate

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"sync"

	"github.com/runsecure/hkdfguard-go"
)

// parsePKCS8 parses a PrivateKeyInfo into a signer: RSA, ECDSA or Ed25519.
func parsePKCS8(der []byte) (crypto.Signer, error) {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("%w: a private key: %v", ErrInvalidFile, err)
	}
	return asSigner(key)
}

func asSigner(key any) (crypto.Signer, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return k, nil
	case *ecdsa.PrivateKey:
		return k, nil
	case ed25519.PrivateKey:
		return k, nil
	}
	wipeKey(key)
	return nil, fmt.Errorf("%w: a %T private key", ErrUnsupported, key)
}

// wipeKey zeroes what of a parsed key Go lets it reach: an RSA key's private exponent, primes and
// CRT values, an ECDSA key's scalar, an Ed25519 key's seed. crypto/rsa and crypto/ecdsa keep
// precomputed copies of their own, out of reach, until the garbage collector frees them.
func wipeKey(key any) {
	wipeInt := func(n *big.Int) {
		if n != nil {
			clear(n.Bits())
			n.SetInt64(0)
		}
	}
	switch k := key.(type) {
	case *rsa.PrivateKey:
		wipeInt(k.D)
		for _, p := range k.Primes {
			wipeInt(p)
		}
		wipeInt(k.Precomputed.Dp)
		wipeInt(k.Precomputed.Dq)
		wipeInt(k.Precomputed.Qinv)
		for _, v := range k.Precomputed.CRTValues {
			wipeInt(v.Exp)
			wipeInt(v.Coeff)
			wipeInt(v.R)
		}
	case *ecdsa.PrivateKey:
		wipeInt(k.D)
	case ed25519.PrivateKey:
		hkdfguard.Wipe(k)
	}
}

// parsePEMKey parses the private key in a PEM file. With a password (non-nil) the key must be an
// ENCRYPTED PRIVATE KEY - encrypted PKCS#8 - which it decrypts; without, a PRIVATE KEY (PKCS#8), RSA
// PRIVATE KEY (PKCS#1) or EC PRIVATE KEY (SEC 1). Legacy OpenSSL-encrypted PEM (Proc-Type headers)
// is refused. data is the caller's, and isn't wiped; every decoded copy is.
func parsePEMKey(data, password []byte, hasPassword bool) (crypto.Signer, error) {
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			if hasPassword {
				return nil, fmt.Errorf("%w: the key file holds no ENCRYPTED PRIVATE KEY", ErrInvalidFile)
			}
			return nil, fmt.Errorf("%w: the key file holds no PRIVATE KEY, RSA PRIVATE KEY or EC PRIVATE KEY", ErrInvalidFile)
		}
		key, done, err := parsePEMBlock(block, password, hasPassword)
		hkdfguard.Wipe(block.Bytes)
		if done {
			return key, err
		}
	}
}

func parsePEMBlock(block *pem.Block, password []byte, hasPassword bool) (crypto.Signer, bool, error) {
	if _, legacy := block.Headers["Proc-Type"]; legacy {
		return nil, true, fmt.Errorf("%w: a legacy OpenSSL-encrypted PEM key (Proc-Type); convert it to encrypted PKCS#8 "+
			"(openssl pkcs8 -topk8 -v2 aes-256-cbc)", ErrUnsupported)
	}
	switch block.Type {
	case "ENCRYPTED PRIVATE KEY":
		if !hasPassword {
			return nil, true, fmt.Errorf("%w: the key is encrypted, but no File.PasswordSecretName names its password", ErrInvalidFile)
		}
		key, err := decryptPKCS8(block.Bytes, password, &iterationBudget{})
		return key, true, err
	case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
		if hasPassword {
			return nil, true, fmt.Errorf("%w: the key file's key isn't encrypted, but File.PasswordSecretName names a password for it; "+
				"encrypt it, or leave PasswordSecretName unset and set AllowUnprotectedPrivateKey", ErrInvalidFile)
		}
		var (
			key any
			err error
		)
		switch block.Type {
		case "PRIVATE KEY":
			key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		case "RSA PRIVATE KEY":
			key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		default:
			key, err = x509.ParseECPrivateKey(block.Bytes)
		}
		if err != nil {
			return nil, true, fmt.Errorf("%w: a %s: %v", ErrInvalidFile, block.Type, err)
		}
		signer, err := asSigner(key)
		return signer, true, err
	}
	return nil, false, nil // a certificate, parameters...: look on
}

// parseCertificates parses every certificate in a PEM file, or the one DER certificate a file
// holds, in file order.
func parseCertificates(data []byte) ([]*x509.Certificate, error) {
	if !bytes.Contains(data, []byte("-----BEGIN")) {
		certificate, err := x509.ParseCertificate(data)
		if err != nil {
			return nil, fmt.Errorf("%w: not a PEM or DER certificate: %v", ErrInvalidFile, err)
		}
		return []*x509.Certificate{certificate}, nil
	}
	var certificates []*x509.Certificate
	for rest := data; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: a PEM certificate: %v", ErrInvalidFile, err)
		}
		certificates = append(certificates, certificate)
	}
	if len(certificates) == 0 {
		return nil, fmt.Errorf("%w: the file holds no CERTIFICATE", ErrInvalidFile)
	}
	return certificates, nil
}

// publicKeyMatches reports whether key is the private half of certificate's public key.
func publicKeyMatches(certificate *x509.Certificate, key crypto.Signer) bool {
	public, ok := key.Public().(interface{ Equal(crypto.PublicKey) bool })
	return ok && public.Equal(certificate.PublicKey)
}

// closableKey is a private key that refuses every use once closed: a parsed key, wiped on Close,
// or a key held by the operating system, released on Close. Close waits for operations in flight.
type closableKey struct {
	mu      sync.RWMutex
	closed  bool
	public  crypto.PublicKey
	sign    func(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)
	decrypt func(rand io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) // nil when it can't
	release func()
}

func (k *closableKey) Public() crypto.PublicKey { return k.public }

func (k *closableKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.closed {
		return nil, ErrClosed
	}
	return k.sign(rand, digest, opts)
}

func (k *closableKey) doDecrypt(rand io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.closed {
		return nil, ErrClosed
	}
	return k.decrypt(rand, ciphertext, opts)
}

func (k *closableKey) Close() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if !k.closed {
		k.closed = true
		k.release()
	}
	return nil
}

// signerKey is a closableKey that only signs.
type signerKey struct{ *closableKey }

// decrypterKey is a closableKey that also decrypts: an RSA key.
type decrypterKey struct{ *closableKey }

func (k decrypterKey) Decrypt(rand io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	return k.doDecrypt(rand, ciphertext, opts)
}

// privateKey is what a Certificate holds: a crypto.Signer - and crypto.Decrypter, for RSA - that
// stops working once closed.
type privateKey interface {
	crypto.Signer
	io.Closer
}

// newPrivateKey wraps k: a crypto.Decrypter when decrypt isn't nil.
func newPrivateKey(k *closableKey) privateKey {
	if k.decrypt != nil {
		return decrypterKey{k}
	}
	return signerKey{k}
}

// fileKey wraps a key parsed from a file, wiped on Close.
func fileKey(key crypto.Signer) privateKey {
	k := &closableKey{public: key.Public(), sign: key.Sign, release: func() { wipeKey(key) }}
	if decrypter, ok := key.(crypto.Decrypter); ok {
		if _, isRSA := key.(*rsa.PrivateKey); isRSA {
			k.decrypt = decrypter.Decrypt
		}
	}
	return newPrivateKey(k)
}
