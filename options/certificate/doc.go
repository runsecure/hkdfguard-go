// Package certificate opens one X.509 certificate and its private key from where configuration
// says it is - the Go port of the .NET HkdfGuard.Options.Certificate (CertificateOptions,
// CertificateOptionsValidator, CertificateOptionsLoader). Options names exactly one source:
//
//   - Windows: a certificate in a Windows certificate store (StoreLocation, StoreName), its key held
//     by CNG - or the TPM, through the Platform Crypto Provider.
//   - MacOS: a certificate in a macOS keychain - CurrentUser the login keychain, LocalMachine the
//     System keychain - its key held by the keychain.
//   - Linux: a PEM certificate whose key an OpenSSL 3 provider holds (tpm2, pkcs11). Kept for
//     configuration parity: Go has no OpenSSL binding, so only the certificate itself can be opened
//     (RequirePrivateKey false), and the Validator refuses the key.
//   - File: a PKCS#12 file, or a PEM certificate with an encrypted PKCS#8 key, whose password is
//     read from a protected secret source - never from configuration.
//
// A store's certificate is found by its subject distinguished name, compared whole and decoded,
// ignoring case: of the certificates with that subject, the one valid now - and with its private
// key, when one is required - that expires last is opened, so a renewal under the same subject is
// picked up with no change to configuration.
//
//	loader := certificate.NewLoader(secrets, certificate.LoaderOptions{}) // secrets: a hkdfguard.ProtectedReadOnlyCache
//	cert, err := loader.LoadContext(ctx, &certificate.Options{
//		Windows: &certificate.StoreOptions{StoreLocation: certificate.LocalMachine, Subject: "CN=api.example.com"},
//	}, "tls")
//	if err != nil { ... }
//	defer cert.Close()
//	server := &http.Server{TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert.TLSCertificate()}}}
//
// # Keys stay where they are kept
//
// A store's key is never exported: on Windows it is acquired through CryptAcquireCertificatePrivateKey
// with CNG alone, and every signature is an NCryptSignHash call (RSA PKCS #1 v1.5 and PSS, ECDSA)
// and every decryption an NCryptDecrypt call (PKCS #1 v1.5, OAEP), through golang.org/x/sys/windows
// and a lazily loaded ncrypt.dll, with no cgo; on macOS it is the identity's SecKeyRef, and every
// signature is a SecKeyCreateSignature call, through cgo and the Security framework. Close releases
// the handles.
//
// A file's key is read into memory: its password, decrypted from the hkdfguard.ProtectedReadOnlyCache
// into a []byte, is wiped as soon as the key is read, as is every buffer derived from it, and the
// key itself is wiped on Close as far as Go lets it be reached - crypto/rsa and crypto/ecdsa keep
// precomputed copies of their own until the garbage collector frees them. The PKCS#12 and PBES2
// decryption is this package's own, not a library's, because the libraries take the password as a
// string, which can't be wiped: PBES2 (PBKDF2 with HMAC-SHA-1/2, AES-CBC or 3DES-CBC) and PKCS#12's
// own 3DES, with HMAC-SHA-1/2 integrity MACs and BER as well as DER; legacy RC2 and RC4 encryption,
// public-key (enveloped) PKCS#12 contents and the PBMAC1 MAC are refused with ErrUnsupported.
//
// The returned Certificate is idiomatic crypto/tls material: Leaf, the DER chain its source gave,
// and a crypto.Signer (a crypto.Decrypter too, for RSA) that fails with ErrClosed once the
// Certificate is closed.
//
// It is a module of its own (github.com/runsecure/hkdfguard-go/options/certificate) because it
// depends on golang.org/x/sys and holds platform-specific code.
package certificate
