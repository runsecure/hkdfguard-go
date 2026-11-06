//go:build darwin && cgo

package certificate

/*
#cgo CFLAGS: -Wno-deprecated-declarations
#cgo LDFLAGS: -framework CoreFoundation -framework Security
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Every Core Foundation object crosses into Go as a uintptr_t, never a pointer: Go's garbage
// collector must not see one, and some are tagged pointers.

// What an OSStatus means, into message.
static void hg_status_message(OSStatus status, char* message, long capacity) {
	message[0] = 0;
	CFStringRef text = SecCopyErrorMessageString(status, NULL);
	if (text != NULL) {
		CFStringGetCString(text, message, (CFIndex)capacity, kCFStringEncodingUTF8);
		CFRelease(text);
	}
}

// Opens the keychain at path; *out is 0, and 0 returned, when there is no keychain there.
static OSStatus hg_open_keychain(const char* path, uintptr_t* out) {
	SecKeychainRef keychain = NULL;
	*out = 0;
	OSStatus status = SecKeychainOpen(path, &keychain);
	if (status != errSecSuccess)
		return status;
	SecKeychainStatus keychainStatus = 0;
	status = SecKeychainGetStatus(keychain, &keychainStatus);
	if (status == errSecNoSuchKeychain) {
		CFRelease(keychain);
		return errSecSuccess;
	}
	if (status != errSecSuccess) {
		CFRelease(keychain);
		return status;
	}
	*out = (uintptr_t)keychain;
	return errSecSuccess;
}

// Copies every item of a class (kSecClassIdentity when identities is set, else
// kSecClassCertificate) in one keychain alone; *out is an array the caller releases, or 0 for none.
static OSStatus hg_copy_items(uintptr_t keychain, int identities, uintptr_t* out) {
	*out = 0;
	const void* searchItems[] = { (const void*)keychain };
	CFArrayRef searchList = CFArrayCreate(NULL, searchItems, 1, &kCFTypeArrayCallBacks);
	if (searchList == NULL)
		return errSecAllocate;
	const void* keys[] = { kSecClass, kSecMatchSearchList, kSecMatchLimit, kSecReturnRef };
	const void* values[] = { identities ? kSecClassIdentity : kSecClassCertificate, searchList, kSecMatchLimitAll, kCFBooleanTrue };
	CFDictionaryRef query = CFDictionaryCreate(NULL, keys, values, 4, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFRelease(searchList);
	if (query == NULL)
		return errSecAllocate;
	CFTypeRef result = NULL;
	OSStatus status = SecItemCopyMatching(query, &result);
	CFRelease(query);
	if (status == errSecItemNotFound)
		return errSecSuccess;
	if (status != errSecSuccess)
		return status;
	if (CFGetTypeID(result) != CFArrayGetTypeID()) {
		CFRelease(result);
		return errSecInternalComponent;
	}
	*out = (uintptr_t)result;
	return errSecSuccess;
}

static long hg_array_count(uintptr_t array) { return (long)CFArrayGetCount((CFArrayRef)array); }

// The item at index, retained: the caller releases it.
static uintptr_t hg_array_copy(uintptr_t array, long index) {
	CFTypeRef item = CFArrayGetValueAtIndex((CFArrayRef)array, (CFIndex)index);
	if (item != NULL)
		CFRetain(item);
	return (uintptr_t)item;
}

static void hg_release(uintptr_t ref) {
	if (ref != 0)
		CFRelease((CFTypeRef)ref);
}

// The DER of a certificate, or of an identity's certificate, as a CFData the caller releases; 0 if
// it has none.
static uintptr_t hg_copy_certificate_data(uintptr_t item, int identity) {
	SecCertificateRef certificate = NULL;
	if (identity) {
		if (SecIdentityCopyCertificate((SecIdentityRef)item, &certificate) != errSecSuccess)
			return 0;
	} else {
		certificate = (SecCertificateRef)item;
		CFRetain(certificate);
	}
	CFDataRef data = SecCertificateCopyData(certificate);
	CFRelease(certificate);
	return (uintptr_t)data;
}

static const uint8_t* hg_data_bytes(uintptr_t data) { return CFDataGetBytePtr((CFDataRef)data); }
static long hg_data_length(uintptr_t data) { return (long)CFDataGetLength((CFDataRef)data); }

// The identity's private key, retained, into *out.
static OSStatus hg_copy_private_key(uintptr_t identity, uintptr_t* out) {
	SecKeyRef key = NULL;
	*out = 0;
	OSStatus status = SecIdentityCopyPrivateKey((SecIdentityRef)identity, &key);
	if (status == errSecSuccess)
		*out = (uintptr_t)key;
	return status;
}

// The signature algorithms hg_sign takes, by number.
enum {
	HG_RSA_PKCS1_RAW = 1, HG_RSA_PKCS1_SHA1, HG_RSA_PKCS1_SHA256, HG_RSA_PKCS1_SHA384, HG_RSA_PKCS1_SHA512,
	HG_RSA_PSS_SHA1 = 11, HG_RSA_PSS_SHA256, HG_RSA_PSS_SHA384, HG_RSA_PSS_SHA512,
	HG_ECDSA_SHA1 = 21, HG_ECDSA_SHA256, HG_ECDSA_SHA384, HG_ECDSA_SHA512,
};

static SecKeyAlgorithm hg_algorithm(int algorithm) {
	switch (algorithm) {
	case HG_RSA_PKCS1_RAW: return kSecKeyAlgorithmRSASignatureDigestPKCS1v15Raw;
	case HG_RSA_PKCS1_SHA1: return kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1;
	case HG_RSA_PKCS1_SHA256: return kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256;
	case HG_RSA_PKCS1_SHA384: return kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384;
	case HG_RSA_PKCS1_SHA512: return kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512;
	case HG_RSA_PSS_SHA1: return kSecKeyAlgorithmRSASignatureDigestPSSSHA1;
	case HG_RSA_PSS_SHA256: return kSecKeyAlgorithmRSASignatureDigestPSSSHA256;
	case HG_RSA_PSS_SHA384: return kSecKeyAlgorithmRSASignatureDigestPSSSHA384;
	case HG_RSA_PSS_SHA512: return kSecKeyAlgorithmRSASignatureDigestPSSSHA512;
	case HG_ECDSA_SHA1: return kSecKeyAlgorithmECDSASignatureDigestX962SHA1;
	case HG_ECDSA_SHA256: return kSecKeyAlgorithmECDSASignatureDigestX962SHA256;
	case HG_ECDSA_SHA384: return kSecKeyAlgorithmECDSASignatureDigestX962SHA384;
	case HG_ECDSA_SHA512: return kSecKeyAlgorithmECDSASignatureDigestX962SHA512;
	}
	return NULL;
}

// Signs digest with key, into *signature, a CFData the caller releases. On failure returns the
// error's code - or -1 for an algorithm the key doesn't support - with its description in message.
static long hg_sign(uintptr_t key, int algorithm, const uint8_t* digest, long length, uintptr_t* signature, char* message, long capacity) {
	*signature = 0;
	message[0] = 0;
	SecKeyAlgorithm secAlgorithm = hg_algorithm(algorithm);
	if (secAlgorithm == NULL || !SecKeyIsAlgorithmSupported((SecKeyRef)key, kSecKeyOperationTypeSign, secAlgorithm)) {
		strncpy(message, "the key doesn't support this signature algorithm", (size_t)capacity - 1);
		message[capacity - 1] = 0;
		return -1;
	}
	CFDataRef data = CFDataCreate(NULL, digest, (CFIndex)length);
	if (data == NULL)
		return errSecAllocate;
	CFErrorRef error = NULL;
	CFDataRef result = SecKeyCreateSignature((SecKeyRef)key, secAlgorithm, data, &error);
	CFRelease(data);
	if (result == NULL) {
		long code = errSecInternalComponent;
		if (error != NULL) {
			code = (long)CFErrorGetCode(error);
			CFStringRef description = CFErrorCopyDescription(error);
			if (description != NULL) {
				CFStringGetCString(description, message, (CFIndex)capacity, kCFStringEncodingUTF8);
				CFRelease(description);
			}
			CFRelease(error);
		}
		return code == 0 ? errSecInternalComponent : code;
	}
	*signature = (uintptr_t)result;
	return 0;
}
*/
import "C"

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"
	"os/user"
	"path/filepath"
	"sync"
	"unsafe"
)

// The macOS keychains, through the Security framework: CurrentUser is the login keychain and
// LocalMachine the System keychain, and the search is restricted to that one keychain. A
// certificate with its private key is an identity (kSecClassIdentity); its key stays in the
// keychain, and every signature is a SecKeyCreateSignature call.

const systemKeychain = "/Library/Keychains/System.keychain"

// readStore reads the identities and certificates of the keychain location names. Only My - the
// keychain itself - is a store on macOS; a keychain that doesn't exist reads as empty.
func readStore(location StoreLocation, name StoreName) ([]storeCertificate, error) {
	if name != StoreMy {
		return nil, fmt.Errorf("%w: only the My store - the keychain itself - can be read on macOS, not %s", ErrUnsupported, name)
	}
	path := systemKeychain
	if location == CurrentUser {
		account, err := user.Current()
		if err != nil {
			return nil, fmt.Errorf("finding the login keychain: %w", err)
		}
		path = filepath.Join(account.HomeDir, "Library", "Keychains", "login.keychain-db")
	}

	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))
	var keychain C.uintptr_t
	if status := C.hg_open_keychain(cpath, &keychain); status != 0 {
		return nil, fmt.Errorf("opening the keychain %s: %w", path, osStatus(status))
	}
	if keychain == 0 {
		return nil, nil
	}
	defer C.hg_release(keychain)

	var found []storeCertificate
	fail := func(err error) ([]storeCertificate, error) {
		for _, c := range found {
			_ = c.Close()
		}
		return nil, err
	}

	// Identities first - certificates with their keys - then every certificate that isn't one.
	for _, identities := range []bool{true, false} {
		flag := C.int(0)
		if identities {
			flag = 1
		}
		var items C.uintptr_t
		if status := C.hg_copy_items(keychain, flag, &items); status != 0 {
			return fail(fmt.Errorf("searching the keychain %s: %w", path, osStatus(status)))
		}
		if items == 0 {
			continue
		}
		count := C.hg_array_count(items)
		for i := C.long(0); i < count; i++ {
			item := C.hg_array_copy(items, i)
			der := copyCertificateData(item, flag)
			certificate, err := x509.ParseCertificate(der)
			if err != nil || !identities && containsCertificate(found, der) {
				C.hg_release(item)
				continue
			}
			c := &keychainCertificate{certificate: certificate}
			if identities {
				c.identity = item
			} else {
				C.hg_release(item)
			}
			found = append(found, c)
		}
		C.hg_release(items)
	}
	return found, nil
}

func copyCertificateData(item C.uintptr_t, identity C.int) []byte {
	data := C.hg_copy_certificate_data(item, identity)
	if data == 0 {
		return nil
	}
	defer C.hg_release(data)
	return C.GoBytes(unsafe.Pointer(C.hg_data_bytes(data)), C.int(C.hg_data_length(data)))
}

func containsCertificate(found []storeCertificate, der []byte) bool {
	for _, c := range found {
		if bytes.Equal(c.Certificate().Raw, der) {
			return true
		}
	}
	return false
}

// keychainCertificate is one certificate from a keychain: an identity, holding its reference until
// closed, or a certificate alone.
type keychainCertificate struct {
	mu          sync.Mutex
	identity    C.uintptr_t // 0 for a certificate without its key
	certificate *x509.Certificate
}

func (c *keychainCertificate) Certificate() *x509.Certificate { return c.certificate }

func (c *keychainCertificate) HasPrivateKey() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.identity != 0
}

func (c *keychainCertificate) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	C.hg_release(c.identity)
	c.identity = 0
	return nil
}

func (c *keychainCertificate) PrivateKey() (privateKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.identity == 0 {
		return nil, ErrNoPrivateKey
	}
	var key C.uintptr_t
	if status := C.hg_copy_private_key(c.identity, &key); status != 0 {
		return nil, fmt.Errorf("%w: the keychain won't give its private key: %w", ErrNoPrivateKey, osStatus(status))
	}
	k := &keychainKey{ref: key}

	switch public := c.certificate.PublicKey.(type) {
	case *rsa.PublicKey:
		return newPrivateKey(&closableKey{public: public, release: k.close,
			sign: func(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
				return k.signRSA(digest, opts)
			}}), nil
	case *ecdsa.PublicKey:
		return newPrivateKey(&closableKey{public: public, release: k.close,
			sign: func(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
				return k.signECDSA(digest, opts)
			}}), nil
	}
	k.close()
	return nil, fmt.Errorf("%w: the certificate's key algorithm (%v) isn't RSA or ECDSA", ErrUnsupported, c.certificate.PublicKeyAlgorithm)
}

// keychainKey is a SecKeyRef in the keychain.
type keychainKey struct{ ref C.uintptr_t }

func (k *keychainKey) close() {
	C.hg_release(k.ref)
	k.ref = 0
}

func (k *keychainKey) signRSA(digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	hash := opts.HashFunc()
	if pss, ok := opts.(*rsa.PSSOptions); ok {
		// The Security framework's PSS salt is always the hash's length.
		if pss.SaltLength != rsa.PSSSaltLengthEqualsHash && pss.SaltLength != hash.Size() {
			return nil, fmt.Errorf("%w: a PSS salt other than the hash's length with a keychain key", ErrUnsupported)
		}
		return k.sign(map[crypto.Hash]C.int{crypto.SHA1: C.HG_RSA_PSS_SHA1, crypto.SHA256: C.HG_RSA_PSS_SHA256,
			crypto.SHA384: C.HG_RSA_PSS_SHA384, crypto.SHA512: C.HG_RSA_PSS_SHA512}, hash, digest)
	}
	return k.sign(map[crypto.Hash]C.int{crypto.MD5SHA1: C.HG_RSA_PKCS1_RAW, crypto.SHA1: C.HG_RSA_PKCS1_SHA1,
		crypto.SHA256: C.HG_RSA_PKCS1_SHA256, crypto.SHA384: C.HG_RSA_PKCS1_SHA384, crypto.SHA512: C.HG_RSA_PKCS1_SHA512}, hash, digest)
}

func (k *keychainKey) signECDSA(digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// X9.62 signatures are ASN.1 already, as Go's are.
	return k.sign(map[crypto.Hash]C.int{crypto.SHA1: C.HG_ECDSA_SHA1, crypto.SHA256: C.HG_ECDSA_SHA256,
		crypto.SHA384: C.HG_ECDSA_SHA384, crypto.SHA512: C.HG_ECDSA_SHA512}, opts.HashFunc(), digest)
}

func (k *keychainKey) sign(algorithms map[crypto.Hash]C.int, hash crypto.Hash, digest []byte) ([]byte, error) {
	algorithm, ok := algorithms[hash]
	if !ok {
		return nil, fmt.Errorf("%w: signing a %v digest with a keychain key", ErrUnsupported, hash)
	}
	if len(digest) == 0 || hash != crypto.MD5SHA1 && len(digest) != hash.Size() {
		return nil, fmt.Errorf("certificate: the digest is %d bytes, not %v's %d", len(digest), hash, hash.Size())
	}
	var signature C.uintptr_t
	message := make([]byte, 256)
	code := C.hg_sign(k.ref, algorithm, (*C.uint8_t)(unsafe.Pointer(&digest[0])), C.long(len(digest)), &signature,
		(*C.char)(unsafe.Pointer(&message[0])), C.long(len(message)))
	if code != 0 {
		text := cString(message)
		if code == -1 {
			return nil, fmt.Errorf("%w: %s", ErrUnsupported, text)
		}
		return nil, fmt.Errorf("certificate: SecKeyCreateSignature failed (%d): %s", int(code), text)
	}
	defer C.hg_release(signature)
	return C.GoBytes(unsafe.Pointer(C.hg_data_bytes(signature)), C.int(C.hg_data_length(signature))), nil
}

// osStatus is an OSStatus as an error, with what the Security framework says it means.
func osStatus(status C.OSStatus) error {
	message := make([]byte, 256)
	C.hg_status_message(status, (*C.char)(unsafe.Pointer(&message[0])), C.long(len(message)))
	if text := cString(message); text != "" {
		return fmt.Errorf("OSStatus %d: %s", int32(status), text)
	}
	return fmt.Errorf("OSStatus %d", int32(status))
}

// cString is the NUL-terminated text at the start of b.
func cString(b []byte) string {
	if end := bytes.IndexByte(b, 0); end >= 0 {
		return string(b[:end])
	}
	return string(b)
}
