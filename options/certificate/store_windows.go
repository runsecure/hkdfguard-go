//go:build windows

package certificate

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The Windows certificate store, through crypt32 (golang.org/x/sys/windows, no cgo): a system
// store opened read-only and only if it exists, its certificates enumerated, and a chosen one's
// private key acquired through CNG alone - CryptAcquireCertificatePrivateKey with
// CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG - as an NCrypt key handle that every signature and decryption
// goes through (ncrypt_windows.go). The key is never exported.

var (
	crypt32                               = windows.NewLazySystemDLL("crypt32.dll")
	procCertGetCertificateContextProperty = crypt32.NewProc("CertGetCertificateContextProperty")
)

// The certificate context properties that say the store holds a certificate's private key, as
// .NET's HasPrivateKey reads them: its key provider's name and container, a key handle already
// acquired, or a CNG key handle.
const (
	certKeyContextPropID      = 5
	certKeyProvInfoPropID     = 2
	certNCryptKeyHandlePropID = 78
)

// windowsStoreName is the system store name a StoreName opens, as .NET maps it.
func windowsStoreName(name StoreName) string {
	for _, known := range storeNames {
		if known.name == name {
			return known.windows
		}
	}
	return string(name)
}

// readStore reads every certificate in the system store name at location, read-only. A store
// that doesn't exist, or can't be opened, reads as empty, as .NET's does.
func readStore(location StoreLocation, name StoreName) ([]storeCertificate, error) {
	flags := uint32(windows.CERT_STORE_READONLY_FLAG | windows.CERT_STORE_OPEN_EXISTING_FLAG)
	if location == CurrentUser {
		flags |= windows.CERT_SYSTEM_STORE_CURRENT_USER
	} else {
		flags |= windows.CERT_SYSTEM_STORE_LOCAL_MACHINE
	}
	storeName, err := windows.UTF16PtrFromString(windowsStoreName(name))
	if err != nil {
		return nil, fmt.Errorf("%w: the store name %q", ErrInvalidOptions, name)
	}
	store, err := windows.CertOpenStore(windows.CERT_STORE_PROV_SYSTEM, 0, 0, flags, uintptr(unsafe.Pointer(storeName)))
	if err != nil {
		return nil, nil
	}
	// Each certificate kept is a duplicated context, which holds the store open until it is freed.
	defer func() { _ = windows.CertCloseStore(store, 0) }()

	var (
		found []storeCertificate
		prev  *windows.CertContext
	)
	for {
		// Frees prev, and returns the next certificate, or CRYPT_E_NOT_FOUND after the last.
		context, err := windows.CertEnumCertificatesInStore(store, prev)
		if err != nil {
			if err == windows.Errno(windows.CRYPT_E_NOT_FOUND) {
				return found, nil
			}
			for _, c := range found {
				_ = c.Close()
			}
			return nil, fmt.Errorf("reading the %s %s certificate store: %w", location, name, err)
		}
		prev = context

		der := make([]byte, context.Length)
		copy(der, unsafe.Slice(context.EncodedCert, context.Length))
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			continue // a certificate Go can't parse can't be the one named
		}
		duplicate := windows.CertDuplicateCertificateContext(context)
		found = append(found, &windowsCertificate{
			context:     duplicate,
			certificate: certificate,
			hasKey: hasProperty(duplicate, certKeyProvInfoPropID) || hasProperty(duplicate, certKeyContextPropID) ||
				hasProperty(duplicate, certNCryptKeyHandlePropID),
		})
	}
}

// hasProperty reports whether a certificate context has a property, without reading it.
func hasProperty(context *windows.CertContext, property uint32) bool {
	var size uint32
	r, _, _ := procCertGetCertificateContextProperty.Call(uintptr(unsafe.Pointer(context)), uintptr(property), 0,
		uintptr(unsafe.Pointer(&size)))
	return r != 0
}

// windowsCertificate is one certificate from a Windows store, holding its context until closed.
type windowsCertificate struct {
	mu          sync.Mutex
	context     *windows.CertContext
	certificate *x509.Certificate
	hasKey      bool
}

func (c *windowsCertificate) Certificate() *x509.Certificate { return c.certificate }

func (c *windowsCertificate) HasPrivateKey() bool { return c.hasKey }

func (c *windowsCertificate) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.context == nil {
		return nil
	}
	err := windows.CertFreeCertificateContext(c.context)
	c.context = nil
	return err
}

// PrivateKey acquires the certificate's private key as a CNG key handle, silently - a key that
// would need a dialog to open fails instead. A key only a legacy CryptoAPI provider holds is
// refused: re-import it into a CNG key storage provider.
func (c *windowsCertificate) PrivateKey() (privateKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.context == nil {
		return nil, ErrClosed
	}
	var (
		handle     windows.Handle
		keySpec    uint32
		callerFree bool
	)
	err := windows.CryptAcquireCertificatePrivateKey(c.context,
		windows.CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG|windows.CRYPT_ACQUIRE_SILENT_FLAG, nil, &handle, &keySpec, &callerFree)
	if err != nil {
		return nil, fmt.Errorf("%w: its private key can't be opened through CNG: %w", ErrNoPrivateKey, err)
	}
	if keySpec != windows.CERT_NCRYPT_KEY_SPEC {
		// Not an NCrypt key, despite the flag: a CryptoAPI provider handle, which this never uses.
		if callerFree {
			_ = windows.CryptReleaseContext(handle, 0)
		}
		return nil, fmt.Errorf("%w: its private key isn't a CNG key", ErrUnsupported)
	}

	key := &ncryptKey{handle: handle, free: callerFree}
	switch public := c.certificate.PublicKey.(type) {
	case *rsa.PublicKey:
		return key.rsa(public), nil
	case *ecdsa.PublicKey:
		return key.ecdsa(public), nil
	}
	key.close()
	return nil, fmt.Errorf("%w: the certificate's key algorithm (%v) isn't RSA or ECDSA", ErrUnsupported, c.certificate.PublicKeyAlgorithm)
}
