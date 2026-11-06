//go:build windows

package certificate

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// A CNG key, held by its NCrypt handle: every signature is an NCryptSignHash call and every
// decryption an NCryptDecrypt call, so the key never enters the process. ncrypt.dll is loaded
// from System32 the first time a key is used.

var (
	ncrypt               = windows.NewLazySystemDLL("ncrypt.dll")
	procNCryptSignHash   = ncrypt.NewProc("NCryptSignHash")
	procNCryptDecrypt    = ncrypt.NewProc("NCryptDecrypt")
	procNCryptFreeObject = ncrypt.NewProc("NCryptFreeObject")
)

const (
	bcryptPadPKCS1   = 0x00000002
	bcryptPadOAEP    = 0x00000004
	bcryptPadPSS     = 0x00000008
	ncryptSilentFlag = 0x00000040
)

// The BCRYPT_*_PADDING_INFO structures NCryptSignHash and NCryptDecrypt take.
type bcryptPKCS1PaddingInfo struct {
	algID *uint16
}

type bcryptPSSPaddingInfo struct {
	algID *uint16
	salt  uint32
}

type bcryptOAEPPaddingInfo struct {
	algID *uint16
	label *byte
	size  uint32
}

type ncryptKey struct {
	handle windows.Handle
	free   bool // whether the handle is this key's to free, not the certificate context's
}

func (k *ncryptKey) close() {
	if k.free && k.handle != 0 {
		_, _, _ = procNCryptFreeObject.Call(uintptr(k.handle))
	}
	k.handle = 0
}

// rsa is k as an RSA private key: a crypto.Signer for PKCS #1 v1.5 and PSS, and a
// crypto.Decrypter for PKCS #1 v1.5 and OAEP.
func (k *ncryptKey) rsa(public *rsa.PublicKey) privateKey {
	size := (public.N.BitLen() + 7) / 8
	return newPrivateKey(&closableKey{
		public:  public,
		release: k.close,
		sign: func(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
			return k.signRSA(public, size, digest, opts)
		},
		decrypt: func(_ io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
			return k.decryptRSA(size, ciphertext, opts)
		},
	})
}

// ecdsa is k as an ECDSA private key: a crypto.Signer whose signatures are ASN.1, as Go's are.
func (k *ncryptKey) ecdsa(public *ecdsa.PublicKey) privateKey {
	size := (public.Curve.Params().BitSize + 7) / 8
	return newPrivateKey(&closableKey{
		public:  public,
		release: k.close,
		sign: func(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
			if opts.HashFunc() != 0 && len(digest) != opts.HashFunc().Size() {
				return nil, fmt.Errorf("certificate: the digest is %d bytes, not %v's %d", len(digest), opts.HashFunc(), opts.HashFunc().Size())
			}
			p1363, err := k.signHash(nil, digest, 0, 2*size)
			if err != nil {
				return nil, err
			}
			if len(p1363) != 2*size {
				return nil, fmt.Errorf("certificate: NCryptSignHash gave a %d-byte ECDSA signature, not %d", len(p1363), 2*size)
			}
			// CNG gives r||s (IEEE P1363); Go, and X.509, take SEQUENCE { r INTEGER, s INTEGER }.
			return asn1.Marshal(struct{ R, S *big.Int }{
				new(big.Int).SetBytes(p1363[:size]),
				new(big.Int).SetBytes(p1363[size:]),
			})
		},
	})
}

// cngHashName is the CNG algorithm identifier for a hash, as padding information names it.
func cngHashName(hash crypto.Hash) (string, error) {
	switch hash {
	case crypto.SHA1:
		return "SHA1", nil
	case crypto.SHA256:
		return "SHA256", nil
	case crypto.SHA384:
		return "SHA384", nil
	case crypto.SHA512:
		return "SHA512", nil
	case crypto.MD5:
		return "MD5", nil
	}
	return "", fmt.Errorf("%w: signing a %v digest with a CNG key", ErrUnsupported, hash)
}

func (k *ncryptKey) signRSA(public *rsa.PublicKey, size int, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	hash := opts.HashFunc()
	if hash != 0 && len(digest) != hash.Size() {
		return nil, fmt.Errorf("certificate: the digest is %d bytes, not %v's %d", len(digest), hash, hash.Size())
	}

	if pss, ok := opts.(*rsa.PSSOptions); ok {
		name, err := cngHashName(hash)
		if err != nil {
			return nil, err
		}
		salt := pss.SaltLength
		switch salt {
		case rsa.PSSSaltLengthEqualsHash:
			salt = hash.Size()
		case rsa.PSSSaltLengthAuto: // the largest that fits, as rsa.SignPSS chooses
			salt = (public.N.BitLen()-1+7)/8 - hash.Size() - 2
		}
		if salt < 0 {
			return nil, fmt.Errorf("certificate: the key is too small for a PSS signature with a %v digest", hash)
		}
		algID, _ := windows.UTF16PtrFromString(name)
		info := &bcryptPSSPaddingInfo{algID: algID, salt: uint32(salt)}
		signature, err := k.signHash(unsafe.Pointer(info), digest, bcryptPadPSS, size)
		runtime.KeepAlive(info)
		runtime.KeepAlive(algID)
		return signature, err
	}

	// PKCS #1 v1.5, its DigestInfo naming the hash - or none, for the MD5+SHA1 of TLS 1.0 and 1.1.
	info := &bcryptPKCS1PaddingInfo{}
	if hash != crypto.MD5SHA1 {
		name, err := cngHashName(hash)
		if err != nil {
			return nil, err
		}
		info.algID, _ = windows.UTF16PtrFromString(name)
	}
	signature, err := k.signHash(unsafe.Pointer(info), digest, bcryptPadPKCS1, size)
	runtime.KeepAlive(info)
	return signature, err
}

// signHash signs digest with NCryptSignHash, into a buffer of size bytes.
func (k *ncryptKey) signHash(paddingInfo unsafe.Pointer, digest []byte, flags uint32, size int) ([]byte, error) {
	if len(digest) == 0 {
		return nil, fmt.Errorf("certificate: an empty digest")
	}
	signature := make([]byte, size)
	var written uint32
	status, _, _ := procNCryptSignHash.Call(uintptr(k.handle), uintptr(paddingInfo),
		uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)),
		uintptr(unsafe.Pointer(&signature[0])), uintptr(len(signature)), uintptr(unsafe.Pointer(&written)),
		uintptr(flags|ncryptSilentFlag))
	if status != 0 {
		return nil, fmt.Errorf("certificate: NCryptSignHash: %w", windows.Errno(status))
	}
	return signature[:written], nil
}

func (k *ncryptKey) decryptRSA(size int, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	switch o := opts.(type) {
	case *rsa.OAEPOptions:
		mgf := o.MGFHash
		if mgf == 0 {
			mgf = o.Hash
		}
		if mgf != o.Hash {
			return nil, fmt.Errorf("%w: OAEP with an MGF1 hash other than its label's hash", ErrUnsupported)
		}
		name, err := cngHashName(o.Hash)
		if err != nil {
			return nil, err
		}
		algID, _ := windows.UTF16PtrFromString(name)
		info := &bcryptOAEPPaddingInfo{algID: algID, size: uint32(len(o.Label))}
		if len(o.Label) > 0 {
			info.label = &o.Label[0]
		}
		plaintext, err := k.decryptData(unsafe.Pointer(info), ciphertext, bcryptPadOAEP, size)
		runtime.KeepAlive(info)
		runtime.KeepAlive(algID)
		return plaintext, err

	case nil, *rsa.PKCS1v15DecryptOptions:
		plaintext, err := k.decryptData(nil, ciphertext, bcryptPadPKCS1, size)
		// With a SessionKeyLen, a padding failure gives a random key, not an error, as
		// rsa.PrivateKey.Decrypt does: crypto/tls's RSA key exchange must not reveal which failed.
		if pkcs1, ok := o.(*rsa.PKCS1v15DecryptOptions); ok && pkcs1.SessionKeyLen > 0 {
			if err != nil || len(plaintext) != pkcs1.SessionKeyLen {
				key := make([]byte, pkcs1.SessionKeyLen)
				if _, randErr := io.ReadFull(rand.Reader, key); randErr != nil {
					return nil, randErr
				}
				return key, nil
			}
		}
		return plaintext, err
	}
	return nil, fmt.Errorf("%w: decrypting with %T", ErrUnsupported, opts)
}

// decryptData decrypts ciphertext with NCryptDecrypt, into a buffer of size bytes.
func (k *ncryptKey) decryptData(paddingInfo unsafe.Pointer, ciphertext []byte, flags uint32, size int) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("certificate: an empty ciphertext")
	}
	plaintext := make([]byte, size)
	var written uint32
	status, _, _ := procNCryptDecrypt.Call(uintptr(k.handle), uintptr(unsafe.Pointer(&ciphertext[0])), uintptr(len(ciphertext)),
		uintptr(paddingInfo), uintptr(unsafe.Pointer(&plaintext[0])), uintptr(len(plaintext)), uintptr(unsafe.Pointer(&written)),
		uintptr(flags|ncryptSilentFlag))
	if status != 0 {
		clear(plaintext)
		return nil, fmt.Errorf("certificate: NCryptDecrypt: %w", windows.Errno(status))
	}
	clear(plaintext[written:])
	return plaintext[:written], nil
}
