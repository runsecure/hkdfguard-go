package certificate

import (
	"crypto/x509"
)

// storeCertificate is one certificate a store read gave, holding whatever native handle reaches
// it until it is closed.
type storeCertificate interface {
	// Certificate is the certificate itself.
	Certificate() *x509.Certificate

	// HasPrivateKey reports whether the store holds the certificate's private key, without
	// opening it.
	HasPrivateKey() bool

	// PrivateKey opens the certificate's private key where the store keeps it; the key is never
	// exported. Close the key before the storeCertificate, as Certificate.Close does.
	PrivateKey() (privateKey, error)

	// Close releases the native handle to the certificate.
	Close() error
}

// storeReader reads every certificate in a store, read-only; a store that doesn't exist reads as
// empty. The operating system's own is readStore; the tests hand the Loader their own.
type storeReader func(location StoreLocation, name StoreName) ([]storeCertificate, error)
