package nativev1

import (
	"strings"
	"testing"

	"github.com/runsecure/hkdfguard-go"
)

func TestDEKLengthAndOK(t *testing.T) {
	if DEKLength != 32 || statusOK != 0 {
		t.Errorf("DEKLength = %d, statusOK = %d", DEKLength, statusOK)
	}
}

// headerStatuses is every status code hkdfguard.h defines, by its header name, with its value
// there. Every platform's library shares this table number for number.
var headerStatuses = map[string]int32{
	"HKDFGUARD_ERR_INVALID_ARGUMENT":                   -1,
	"HKDFGUARD_ERR_BUFFER_TOO_SMALL":                   -2,
	"HKDFGUARD_ERR_PROVIDER_UNAVAILABLE":               -3,
	"HKDFGUARD_ERR_PROVIDER_ERROR":                     -4,
	"HKDFGUARD_ERR_CRYPTO_ERROR":                       -5,
	"HKDFGUARD_ERR_INTERNAL_ERROR":                     -6,
	"HKDFGUARD_ERR_INVALID_SERVICE_NAME":               -8,
	"HKDFGUARD_ERR_POLICY_INVALID":                     -9,
	"HKDFGUARD_ERR_PAYLOAD_MALFORMED":                  -10,
	"HKDFGUARD_ERR_PAYLOAD_AUTH_FAILED":                -11,
	"HKDFGUARD_ERR_PAYLOAD_UNSUPPORTED":                -12,
	"HKDFGUARD_ERR_PAYLOAD_VERSION_REFUSED":            -13,
	"HKDFGUARD_ERR_KEK_FINGERPRINT_MISMATCH":           -16,
	"HKDFGUARD_ERR_KEK_NOT_FOUND":                      -17,
	"HKDFGUARD_ERR_KEK_ACCESS_DENIED":                  -18,
	"HKDFGUARD_ERR_KEK_INVALID":                        -19,
	"HKDFGUARD_ERR_PROCESS_HARDENING_FAILED":           -20,
	"HKDFGUARD_ERR_FILE_NOT_FOUND":                     -32,
	"HKDFGUARD_ERR_FILE_ACCESS_DENIED":                 -33,
	"HKDFGUARD_ERR_FILE_IO":                            -34,
	"HKDFGUARD_ERR_FILE_TOO_SHORT":                     -35,
	"HKDFGUARD_ERR_FILE_TOO_LONG":                      -36,
	"HKDFGUARD_ERR_FILE_PLAINTEXT_KEY":                 -37,
	"HKDFGUARD_ERR_FILE_MALFORMED":                     -38,
	"HKDFGUARD_ERR_FILE_UNTRUSTED":                     -39,
	"HKDFGUARD_ERR_WIN_GROUP_INVALID":                  -64,
	"HKDFGUARD_ERR_MAC_ACCESS_CONTROL_CREATION_FAILED": -96,
	"HKDFGUARD_ERR_MAC_KEY_GENERATION_FAILED":          -97,
	"HKDFGUARD_ERR_MAC_KEYCHAIN_WRITE_FAILED":          -98,
	"HKDFGUARD_ERR_MAC_KEK_VERIFICATION_FAILED":        -99,
	"HKDFGUARD_ERR_MAC_KEYCHAIN_READ_FAILED":           -100,
}

func TestStatusConstants_AreTheHeadersValues(t *testing.T) {
	constants := map[string]int32{
		"HKDFGUARD_ERR_INVALID_ARGUMENT":                   errInvalidArgument,
		"HKDFGUARD_ERR_BUFFER_TOO_SMALL":                   errBufferTooSmall,
		"HKDFGUARD_ERR_PROVIDER_UNAVAILABLE":               errProviderUnavailable,
		"HKDFGUARD_ERR_PROVIDER_ERROR":                     errProviderError,
		"HKDFGUARD_ERR_CRYPTO_ERROR":                       errCryptoError,
		"HKDFGUARD_ERR_INTERNAL_ERROR":                     errInternalError,
		"HKDFGUARD_ERR_INVALID_SERVICE_NAME":               errInvalidServiceName,
		"HKDFGUARD_ERR_POLICY_INVALID":                     errPolicyInvalid,
		"HKDFGUARD_ERR_PAYLOAD_MALFORMED":                  errPayloadMalformed,
		"HKDFGUARD_ERR_PAYLOAD_AUTH_FAILED":                errPayloadAuthFailed,
		"HKDFGUARD_ERR_PAYLOAD_UNSUPPORTED":                errPayloadUnsupported,
		"HKDFGUARD_ERR_PAYLOAD_VERSION_REFUSED":            errPayloadVersionRefused,
		"HKDFGUARD_ERR_KEK_FINGERPRINT_MISMATCH":           errKEKFingerprintMismatch,
		"HKDFGUARD_ERR_KEK_NOT_FOUND":                      errKEKNotFound,
		"HKDFGUARD_ERR_KEK_ACCESS_DENIED":                  errKEKAccessDenied,
		"HKDFGUARD_ERR_KEK_INVALID":                        errKEKInvalid,
		"HKDFGUARD_ERR_PROCESS_HARDENING_FAILED":           errProcessHardeningFailed,
		"HKDFGUARD_ERR_FILE_NOT_FOUND":                     errFileNotFound,
		"HKDFGUARD_ERR_FILE_ACCESS_DENIED":                 errFileAccessDenied,
		"HKDFGUARD_ERR_FILE_IO":                            errFileIO,
		"HKDFGUARD_ERR_FILE_TOO_SHORT":                     errFileTooShort,
		"HKDFGUARD_ERR_FILE_TOO_LONG":                      errFileTooLong,
		"HKDFGUARD_ERR_FILE_PLAINTEXT_KEY":                 errFilePlaintextKey,
		"HKDFGUARD_ERR_FILE_MALFORMED":                     errFileMalformed,
		"HKDFGUARD_ERR_FILE_UNTRUSTED":                     errFileUntrusted,
		"HKDFGUARD_ERR_WIN_GROUP_INVALID":                  errWinGroupInvalid,
		"HKDFGUARD_ERR_MAC_ACCESS_CONTROL_CREATION_FAILED": errMacAccessControlCreationFailed,
		"HKDFGUARD_ERR_MAC_KEY_GENERATION_FAILED":          errMacKeyGenerationFailed,
		"HKDFGUARD_ERR_MAC_KEYCHAIN_WRITE_FAILED":          errMacKeychainWriteFailed,
		"HKDFGUARD_ERR_MAC_KEK_VERIFICATION_FAILED":        errMacKEKVerificationFailed,
		"HKDFGUARD_ERR_MAC_KEYCHAIN_READ_FAILED":           errMacKeychainReadFailed,
	}
	if len(constants) != len(headerStatuses) {
		t.Errorf("%d constants for %d header statuses", len(constants), len(headerStatuses))
	}
	for name, want := range headerStatuses {
		if got, ok := constants[name]; !ok || got != want {
			t.Errorf("%s = %d (defined: %v), want %d", name, got, ok, want)
		}
	}
}

func TestWrappedKeyFileLengths_FitTheBufferTheKeyFileReadUses(t *testing.T) {
	// Each platform's HKDFGUARD_WRAPPED_MAX_LEN: hkdfguard_open_file needs at least that much room,
	// and openKeyFile always offers hkdfguard.MaxWrappedKeyBytes.
	for platform, length := range map[string]int{"windows": 132, "linux": 276, "darwin": 125} {
		if length > hkdfguard.MaxWrappedKeyBytes {
			t.Errorf("%s: a %d-byte wrapped DEK does not fit %d bytes", platform, length, hkdfguard.MaxWrappedKeyBytes)
		}
	}
}

var platformDescribers = map[string]func(int32) string{
	"shared":  describeStatus,
	"windows": describeWindowsStatus,
	"linux":   describeLinuxStatus,
	"darwin":  describeMacStatus,
}

func TestEveryPlatform_DescribesEveryDefinedStatus_AndNoReservedOne(t *testing.T) {
	defined := map[int32]bool{}
	for _, status := range headerStatuses {
		defined[status] = true
	}

	for platform, describe := range platformDescribers {
		for status := int32(-200); status <= 1; status++ {
			description := describe(status)
			switch {
			case defined[status] && description == "":
				t.Errorf("%s: no description for %d", platform, status)
			case !defined[status] && description != "":
				t.Errorf("%s: reserved or unknown %d is described as %q", platform, status, description)
			}
		}
	}
}

func TestPlatformHints_SayWhatToDoThere(t *testing.T) {
	checks := []struct {
		platform string
		status   int32
		want     []string
	}{
		{"windows", errKEKAccessDenied, []string{"not authorized", "HkdfGuardUsers", "KeyUseGroups"}},
		{"windows", errKEKNotFound, []string{"hkdfguard provision", "elevated"}},
		{"windows", errPolicyInvalid, []string{`HKLM\Software\Policies\HkdfGuard`}},
		{"windows", errWinGroupInvalid, []string{"KeyUseGroups"}},
		{"windows", errPayloadVersionRefused, []string{"ClassicalMode"}},
		{"windows", errProviderUnavailable, []string{"ClassicalMode"}},
		{"linux", errPolicyInvalid, []string{"/etc/hkdfguard/policy.toml"}},
		{"linux", errKEKNotFound, []string{"hkdfguard provision"}},
		{"linux", errKEKFingerprintMismatch, []string{"different KEK"}},
		{"darwin", errKEKAccessDenied, []string{"keychain"}},
		{"darwin", errProviderUnavailable, []string{"Secure Enclave"}},
		{"darwin", errKEKNotFound, []string{"hkdfguard provision", "keychain mode"}},
		{"windows", errProcessHardeningFailed, []string{"access lists", "RequireProtectedSignature"}},
		{"linux", errProcessHardeningFailed, []string{"ptrace"}},
		{"darwin", errProcessHardeningFailed, []string{"Hardened Runtime", "get-task-allow", "RequireProtectedSignature"}},
		{"shared", errFilePlaintextKey, []string{"UNWRAPPED", "key exposure"}},
		{"shared", errKEKNotFound, []string{"hkdfguard provision"}},
	}
	for _, c := range checks {
		description := platformDescribers[c.platform](c.status)
		for _, want := range c.want {
			if !strings.Contains(description, want) {
				t.Errorf("%s %d = %q, want it to mention %q", c.platform, c.status, description, want)
			}
		}
	}

	// Where a platform adds nothing, it says what every platform says.
	for platform, describe := range platformDescribers {
		if describe(errFileUntrusted) != describeStatus(errFileUntrusted) {
			t.Errorf("%s describes -39 as %q", platform, describe(errFileUntrusted))
		}
	}
}
