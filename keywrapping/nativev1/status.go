package nativev1

// The native status codes and what they mean. Every platform's library - Windows, Linux and macOS -
// shares the header's HKDFGUARD_ERR_* table number for number, so it is defined here once. Each
// platform's binding adds what to do about a code there (which group grants access to a KEK, where
// the policy lives) and falls back to the shared meaning for the rest. They are plain data, compiled
// on every platform, so they can be tested anywhere. A code missing from the table (reserved or
// unknown) has no description.

// Status codes, exactly as every platform's hkdfguard.h defines them (HKDFGUARD_OK is statusOK).
// Each platform band refines one of the common codes above it.
const (
	// General (-1..-7; -7 reserved)
	errInvalidArgument     = -1
	errBufferTooSmall      = -2
	errProviderUnavailable = -3
	errProviderError       = -4
	errCryptoError         = -5
	errInternalError       = -6

	// Service name and policy (-8..-9)
	errInvalidServiceName = -8
	errPolicyInvalid      = -9

	// Wrapped payload (-10..-15; -14..-15 reserved)
	errPayloadMalformed      = -10
	errPayloadAuthFailed     = -11
	errPayloadUnsupported    = -12
	errPayloadVersionRefused = -13

	// KEK and process (-16..-31; -21..-31 reserved)
	errKEKFingerprintMismatch = -16
	errKEKNotFound            = -17
	errKEKAccessDenied        = -18
	errKEKInvalid             = -19
	errProcessHardeningFailed = -20

	// Key file, hkdfguard_open_file (-32..-39; -40..-63 reserved for future common codes)
	errFileNotFound     = -32
	errFileAccessDenied = -33
	errFileIO           = -34
	errFileTooShort     = -35
	errFileTooLong      = -36
	errFilePlaintextKey = -37
	errFileMalformed    = -38
	errFileUntrusted    = -39

	// Windows-specific (-64..-79), refining errPolicyInvalid
	errWinGroupInvalid = -64

	// Linux-specific (-80..-95): none defined yet

	// macOS-specific (-96..-111), each refining errProviderError
	errMacAccessControlCreationFailed = -96
	errMacKeyGenerationFailed         = -97
	errMacKeychainWriteFailed         = -98
	errMacKEKVerificationFailed       = -99
	errMacKeychainReadFailed          = -100
)

// statusDescriptions is what each status means on every platform.
var statusDescriptions = map[int32]string{
	errInvalidArgument:                "invalid argument: a null pointer, wrong DEK length, negative buffer capacity, or bad path",
	errBufferTooSmall:                 "the output buffer is too small for the result",
	errProviderUnavailable:            "no key storage provider could be used at all",
	errProviderError:                  "the KEK provider or key could not be opened or created",
	errCryptoError:                    "an ECDH, HKDF, AES or random number operation failed",
	errInternalError:                  "an unexpected internal failure in the native library",
	errInvalidServiceName:             "the service name is null, empty, too long, or has a character other than an ASCII letter, digit or '.'",
	errPolicyInvalid:                  "the machine's HkdfGuard policy is invalid",
	errPayloadMalformed:               "the wrapped payload is not a valid wrapped DEK",
	errPayloadAuthFailed:              "AES-GCM authentication failed: the wrapped payload was altered",
	errPayloadUnsupported:             "the wrapped payload's version or suite is not one this native library understands",
	errPayloadVersionRefused:          "the wrapped payload's version is one this native library understands, but this host's policy does not use",
	errKEKFingerprintMismatch:         "the payload was wrapped under a different KEK than this service's current one",
	errKEKNotFound:                    "no KEK is provisioned for this service; run hkdfguard provision",
	errKEKAccessDenied:                "the KEK exists, but this account is not authorized to use it",
	errKEKInvalid:                     "the existing KEK is unusable as found",
	errProcessHardeningFailed:         "process hardening failed",
	errFileNotFound:                   "the key file, or a folder in its path, does not exist",
	errFileAccessDenied:               "this account may not read the key file",
	errFileIO:                         "the key file is not a regular file, is in use by a writer, or could not be read",
	errFileTooShort:                   "the key file is shorter than a wrapped DEK",
	errFileTooLong:                    "the key file is longer than a wrapped DEK",
	errFilePlaintextKey:               "the key file holds what looks like an UNWRAPPED key (32 raw bytes, or its hex or base64): treat it as a key exposure",
	errFileMalformed:                  "the key file is the right size, but is not a valid wrapped DEK",
	errFileUntrusted:                  "the key file's path is not trusted: a link or reparse point, a short or network path, or a file or folder another account could replace",
	errWinGroupInvalid:                `an HKLM\Software\Policies\HkdfGuard\KeyUseGroups entry is unresolvable, not a group, not host-local, or over-broad`,
	errMacAccessControlCreationFailed: "the access policy for a new KEK could not be created",
	errMacKeyGenerationFailed:         "the Secure Enclave refused to generate a key",
	errMacKeychainWriteFailed:         "the new KEK could not be stored in the keychain",
	errMacKEKVerificationFailed:       "the new KEK could not be reloaded after it was stored",
	errMacKeychainReadFailed:          "the keychain could not be read",
}

// describeStatus is what a non-zero status means on every platform, or "" when it is unknown.
func describeStatus(status int32) string { return statusDescriptions[status] }

// windowsStatusHints says what a status means on Windows where that is more specific than the
// shared meaning.
var windowsStatusHints = map[int32]string{
	errProviderUnavailable:    `payload version 2 is unavailable on this host: the TPM can't be used for it and KeyStoragePolicy, or an existing TPM KEK, rules out the software key store (event 2008 names the reason); set HKLM\Software\Policies\HkdfGuard\ClassicalMode to 1 to keep using version 1`,
	errProviderError:          "the KEK's key storage provider (Platform Crypto Provider or Software KSP) could not open or create the key",
	errPolicyInvalid:          `a machine policy value under HKLM\Software\Policies\HkdfGuard is invalid`,
	errPayloadVersionRefused:  `the wrapped payload is the other payload version from the one HKLM\Software\Policies\HkdfGuard\ClassicalMode selects (absent or 0: version 2; 1: version 1); a host unwraps only its own version`,
	errKEKNotFound:            "no KEK is provisioned for this service; run hkdfguard provision from an elevated prompt",
	errKEKAccessDenied:        "the KEK exists, but this account is not authorized to use it (or, for a new KEK, the process is not elevated); add it to the HkdfGuardUsers group or a KeyUseGroups group",
	errKEKInvalid:             "the existing KEK's ACL is missing, lacks SYSTEM/Administrators, or grants an over-broad principal",
	errProcessHardeningFailed: "process hardening failed: the crash-report heap exclusion or the process and thread access lists could not be set, or (with RequireProtectedSignature) the process could not be closed to its own user",
}

// linuxStatusHints says what a status means on Linux where that is more specific than the shared
// meaning.
var linuxStatusHints = map[int32]string{
	errProviderUnavailable:    "no KEK provider could be reached: no usable TPM, PKCS#11 token or external secret under /etc/hkdfguard/policy.toml",
	errProviderError:          "a KEK provider was reached but failed (policy file, secret file permissions, TPM or token error); the native library's log names the reason",
	errPolicyInvalid:          "/etc/hkdfguard/policy.toml can't be used: unparsable, an invalid or contradictory setting, insecure ownership or permissions, or a provider this build lacks",
	errKEKNotFound:            "no KEK is provisioned for this service; run hkdfguard provision",
	errKEKFingerprintMismatch: "the payload was wrapped under a different KEK than this service's current one: another service, or the KEK or TPM derivation secret has changed",
	errProcessHardeningFailed: "process hardening failed: core dumps or ptrace access could not be disabled",
}

// macStatusHints says what a status means on macOS where that is more specific than the shared
// meaning.
var macStatusHints = map[int32]string{
	errProviderUnavailable:    "this Mac has no Secure Enclave",
	errPayloadAuthFailed:      "AES-GCM authentication failed: the payload was altered, or wrapped for another service under this KEK",
	errKEKNotFound:            "no KEK is provisioned for this service in this keychain mode; run hkdfguard provision",
	errKEKAccessDenied:        "the keychain denied access: it is locked, there is no session to prompt in, or this process isn't allowed",
	errKEKInvalid:             "the keychain item for this service can't be reconstructed into a key",
	errProcessHardeningFailed: "process hardening failed: core dumps or debugger attachment could not be denied, or (with RequireProtectedSignature) the host executable's code signature still allows it - it needs the Hardened Runtime, without get-task-allow or DYLD_* entitlements",
}

// describeWindowsStatus is what a status means on Windows, or "" when it is unknown.
func describeWindowsStatus(status int32) string { return describeWith(windowsStatusHints, status) }

// describeLinuxStatus is what a status means on Linux, or "" when it is unknown.
func describeLinuxStatus(status int32) string { return describeWith(linuxStatusHints, status) }

// describeMacStatus is what a status means on macOS, or "" when it is unknown.
func describeMacStatus(status int32) string { return describeWith(macStatusHints, status) }

func describeWith(hints map[int32]string, status int32) string {
	if hint, ok := hints[status]; ok {
		return hint
	}
	return describeStatus(status)
}
