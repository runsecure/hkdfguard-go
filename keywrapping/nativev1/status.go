package nativev1

// Each platform's native status codes, exactly as its header defines them, and what they mean.
// They are plain data, compiled on every platform, so they can be tested anywhere; each platform's
// binding picks its own table. A code missing from a table (reserved, unassigned, or unknown) has
// no description.

// macOS libhkdfguard_v1.dylib status codes (hkdfguard.h).
const (
	macErrInvalidInputLength          = -1
	macErrOutputBufferTooSmall        = -2
	macErrKeyUnavailable              = -3 // reserved; no longer returned
	macErrPublicKeyUnavailable        = -4 // reserved; never returned
	macErrEncryptionFailed            = -5
	macErrDecryptionFailed            = -6
	macErrUnexpectedOutputLength      = -7
	macErrInvalidServiceIdentifier    = -8
	macErrEnclaveUnavailable          = -9
	macErrKEKNotFound                 = -10
	macErrKEKCorrupted                = -11
	macErrAccessControlCreationFailed = -12
	macErrKeyGenerationFailed         = -13
	macErrKeychainWriteFailed         = -14
	macErrKEKVerificationFailed       = -15
	macErrFingerprintMismatch         = -16
	macErrKeychainAccessDenied        = -17
	macErrKeychainReadFailed          = -18
)

var macStatusDescriptions = map[int32]string{
	macErrInvalidInputLength:          "invalid input length, or a null buffer",
	macErrOutputBufferTooSmall:        "the output buffer is too small for the result",
	macErrEncryptionFailed:            "encryption failed",
	macErrDecryptionFailed:            "AES-GCM authentication failed: the payload was altered, or wrapped for another service under this KEK",
	macErrUnexpectedOutputLength:      "the native library produced an unexpected output length",
	macErrInvalidServiceIdentifier:    "the service name is null, empty, too long, or has a character other than an ASCII letter, digit or '.'",
	macErrEnclaveUnavailable:          "this Mac has no Secure Enclave",
	macErrKEKNotFound:                 "no KEK is provisioned for this service in this keychain mode; run hkdfguard-v1-initialize provision",
	macErrKEKCorrupted:                "the keychain item for this service can't be reconstructed into a key",
	macErrAccessControlCreationFailed: "the access policy for a new KEK could not be created",
	macErrKeyGenerationFailed:         "the Secure Enclave refused to generate a key",
	macErrKeychainWriteFailed:         "the new KEK could not be stored in the keychain",
	macErrKEKVerificationFailed:       "the new KEK could not be reloaded after it was stored",
	macErrFingerprintMismatch:         "the payload was wrapped under a different KEK than this service's",
	macErrKeychainAccessDenied:        "the keychain denied access: it is locked, there is no session to prompt in, or this process isn't allowed",
	macErrKeychainReadFailed:          "the keychain could not be read",
}

// Linux libhkdfguard.so.1 status codes (the native library's status module).
const (
	linuxErrInvalidArgument        = -1
	linuxErrBufferTooSmall         = -2
	linuxErrProviderUnavailable    = -3
	linuxErrProviderError          = -4
	linuxErrCryptoError            = -5
	linuxErrInternalError          = -6
	linuxErrInvalidUTF8            = -7 // reserved; no longer returned (now linuxErrInvalidServiceName)
	linuxErrInvalidServiceName     = -8
	linuxErrKEKNotFound            = -9
	linuxErrFingerprintMismatch    = -16 // -10..-15 are unassigned on Linux
	linuxErrProcessHardeningFailed = -17
)

var linuxStatusDescriptions = map[int32]string{
	linuxErrInvalidArgument:        "invalid argument: a null pointer, wrong DEK length, or negative buffer capacity",
	linuxErrBufferTooSmall:         "the output buffer is too small for the result",
	linuxErrProviderUnavailable:    "no KEK provider could be reached: no usable TPM, PKCS#11 token or external secret under /etc/hkdfguard/policy.toml",
	linuxErrProviderError:          "a KEK provider was reached but failed (policy file, secret file permissions, TPM or token error); the native library's log names the reason",
	linuxErrCryptoError:            "the wrapped payload is malformed or failed AES-GCM authentication",
	linuxErrInternalError:          "an unexpected internal failure in the native library",
	linuxErrInvalidServiceName:     "the service name is malformed or invalid",
	linuxErrKEKNotFound:            "no KEK is provisioned for this service; run hkdfguard-v1-initialize provision",
	linuxErrFingerprintMismatch:    "the payload was wrapped under a different KEK than this service's current one: another service, or the KEK or TPM derivation secret has changed",
	linuxErrProcessHardeningFailed: "process hardening failed: core dumps or ptrace access could not be disabled",
}

// Windows HkdfGuardV1.dll status codes (HKDFGUARD_ERR_*).
const (
	winErrInvalidArg         = -1
	winErrBufferTooSmall     = -2
	winErrProvider           = -3
	winErrCrypto             = -4
	winErrAuthFailed         = -5
	winErrMalformed          = -6
	winErrInternal           = -7
	winErrServiceNameInvalid = -8
	winErrInvalidPolicy      = -9
	winErrGroupInvalid       = -10
	winErrKEKMismatch        = -11
	winErrKEKNotFound        = -12
	winErrAccessDenied       = -13
	winErrKEKACLInvalid      = -14
)

var windowsStatusDescriptions = map[int32]string{
	winErrInvalidArg:         "invalid argument: a null pointer, wrong DEK length, or bad service",
	winErrBufferTooSmall:     "the output buffer is too small for the result",
	winErrProvider:           "the KEK provider or key could not be opened or created",
	winErrCrypto:             "an ECDH, HKDF or AES operation failed",
	winErrAuthFailed:         "AES-GCM authentication failed: the wrapped payload was altered",
	winErrMalformed:          "the wrapped payload is not a valid WrappedDekV1",
	winErrInternal:           "an unexpected internal failure in the native library",
	winErrServiceNameInvalid: "the service name is malformed or invalid",
	winErrInvalidPolicy:      `HKLM\Software\Policies\HkdfGuard\KeyStoragePolicy is invalid`,
	winErrGroupInvalid:       `an HKLM\Software\Policies\HkdfGuard\KeyUseGroups entry is unresolvable, not a group, or over-broad`,
	winErrKEKMismatch:        "the payload was wrapped under a different KEK than this service's",
	winErrKEKNotFound:        "no KEK is provisioned for this service; run hkdfguard-v1-initialize provision",
	winErrAccessDenied:       "the KEK exists, but this account is not authorized to use it; add it to the HkdfGuardUsers group or a KeyUseGroups group",
	winErrKEKACLInvalid:      "the existing KEK's ACL is missing, lacks SYSTEM/Administrators, or grants an over-broad principal",
}
