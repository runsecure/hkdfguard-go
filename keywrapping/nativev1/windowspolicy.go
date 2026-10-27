package nativev1

import (
	"fmt"
	"slices"
	"strings"
)

// The Windows loader's decisions, kept free of system calls (a security descriptor and signer are
// passed in as plain data) so they can be checked on any platform. The loader (kms_windows.go)
// loads the library from its one installed location and nowhere else, after five checks:
//
//  1. The file exists at %ProgramFiles%\HkdfGuard\v1\HkdfGuard.dll. The Program Files location
//     comes from the known-folder registry setting, which only an administrator can change, not
//     from the ProgramFiles environment variable.
//  2. No component of that path, from the file up to (not including) the drive root, is a reparse
//     point - a symlink or junction could redirect a trusted-looking path somewhere writable.
//  3. Every one of those components is owned by, and writable only by, SYSTEM, Administrators, or
//     TrustedInstaller. The drive root is held only to what could rename the folder beneath it.
//  4. The file carries a valid Authenticode signature issued to winExpectedPublisher under
//     HkdfGuard's Artifact Signing profile (winExpectedProfileEKU), whose chain - as
//     WinVerifyTrust validated it - ends at the pinned root winExpectedRootSHA256.
//  5. Its PE header - covered by that signature - marks it a DLL for this process's architecture,
//     which refuses the profile's other binaries (hkdfguard.exe renamed into place).
//  6. Its version resource - also covered by that signature - is at least
//     winMinimumLibraryVersion, so an older genuine release can't be put back in its place.
//
// The library's own dependencies are then resolved from System32 only. After loading, the module
// Windows actually mapped must be the file that was verified (winVerifyLoadedModule): a module of
// the same name already in the process, or loader redirection, would otherwise hand back another
// image under the verified path's name.

const (
	winFileName = "HkdfGuard.dll"

	// winExpectedPublisher is the Authenticode signer subject the library must carry, as Windows
	// renders it (CertNameToStr, X.500 form, reversed). The signing certificate is short-lived and
	// reissued frequently, so a thumbprint can't be pinned; the root and profile are pinned too.
	winExpectedPublisher = "CN=Torin Blair, O=Torin Blair, L=Littleton, S=co, C=US"

	// winExpectedRootSHA256 is the SHA-256 of the root the signer's chain must end at: Microsoft
	// Identity Verification Root Certificate Authority 2020, the root of Azure Artifact Signing.
	// Without it, any root trusted on the machine - including one a non-administrator added to
	// their own CurrentUser\Root store - could vouch for winExpectedPublisher.
	winExpectedRootSHA256 = "5367F20C7ADE0E2BCA790915056D086B720C33C1FA2A2661ACF787E3292E1270"

	// winExpectedProfileEKU identifies HkdfGuard's Artifact Signing certificate profile. Not to be
	// confused with 1.3.6.1.4.1.311.97.1.0, which every Artifact Signing leaf carries.
	winExpectedProfileEKU = "1.3.6.1.4.1.311.97.492781510.305179978.413069662.611988563"

	// winCodeSigningEKU is id-kp-codeSigning, required of the leaf.
	winCodeSigningEKU = "1.3.6.1.5.5.7.3.3"
)

// Trusted principals' SIDs: LocalSystem, BUILTIN\Administrators, and NT SERVICE\TrustedInstaller.
const (
	sidLocalSystem      = "S-1-5-18"
	sidAdministrators   = "S-1-5-32-544"
	sidTrustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
)

var winTrustedPrincipals = []string{sidLocalSystem, sidAdministrators, sidTrustedInstaller}

// Access-mask bits.
const (
	rightWriteData              = 0x00000002 // FILE_WRITE_DATA / FILE_ADD_FILE
	rightAppendData             = 0x00000004 // FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
	rightWriteExtendedAttribute = 0x00000010 // FILE_WRITE_EA
	rightDeleteChild            = 0x00000040 // FILE_DELETE_CHILD
	rightDelete                 = 0x00010000 // DELETE
	rightWriteDAC               = 0x00040000 // WRITE_DAC
	rightWriteOwner             = 0x00080000 // WRITE_OWNER
	rightGenericAll             = 0x10000000 // GENERIC_ALL
	rightGenericWrite           = 0x40000000 // GENERIC_WRITE

	// winGuardedRights is any right that lets a principal change what this path loads: write or
	// append data, delete or rename, write extended attributes, or take over the ACL. Generic bits
	// are listed too, since an ACE can carry them unmapped.
	winGuardedRights = rightWriteData | rightAppendData | rightWriteExtendedAttribute | rightDeleteChild |
		rightDelete | rightWriteDAC | rightWriteOwner | rightGenericAll | rightGenericWrite

	// winGuardedRootRights is, on the drive root, only what lets a principal rename or delete an
	// entry directly beneath it - delete-child, or taking over the ACL to grant it. Creating new
	// entries there can't affect this path, and GENERIC_WRITE includes none of these.
	winGuardedRootRights = rightDeleteChild | rightWriteDAC | rightWriteOwner | rightGenericAll
)

// ACE types and flags.
const (
	aceTypeAccessAllowed         = 0x0
	aceTypeAccessDenied          = 0x1
	aceTypeAccessAllowedCallback = 0x9
	aceTypeAccessDeniedCallback  = 0xA
	aceFlagInheritOnly           = 0x8
)

// winACE is one entry of a DACL.
type winACE struct {
	aceType uint8
	flags   uint8
	mask    uint32
	sid     string // "" for ACE types whose SID isn't read (they are refused before it matters)
}

// winSecurity is the parts of a security descriptor the checks read.
type winSecurity struct {
	owner      string // "" when the descriptor has no owner
	daclAbsent bool   // a NULL DACL: everyone has full control
	aces       []winACE
}

// winVerifyTrustedOnly requires a trusted owner and no allow entry granting any of guardedRights
// to anyone else. Inherit-only entries don't apply to this item, and deny entries can only remove
// access, so both are ignored. Any other kind of ACE is refused rather than interpreted. describe
// renders a SID for messages.
func winVerifyTrustedOnly(security winSecurity, displayPath string, guardedRights uint32, describe func(sid string) string) error {
	if security.owner == "" || !slices.Contains(winTrustedPrincipals, security.owner) {
		owner := "an unknown principal"
		if security.owner != "" {
			owner = describe(security.owner)
		}
		return untrusted("'%s' is owned by %s; the HkdfGuard native library is only loaded from a location owned by SYSTEM, Administrators, or TrustedInstaller.", displayPath, owner)
	}

	if security.daclAbsent {
		return untrusted("'%s' has no DACL, which grants everyone full control; the HkdfGuard native library is only loaded from a location that only SYSTEM, Administrators, or TrustedInstaller can modify.", displayPath)
	}

	for _, ace := range security.aces {
		if ace.flags&aceFlagInheritOnly != 0 {
			continue
		}
		switch ace.aceType {
		case aceTypeAccessDenied, aceTypeAccessDeniedCallback:
			continue
		case aceTypeAccessAllowed, aceTypeAccessAllowedCallback:
			if ace.mask&guardedRights != 0 && !slices.Contains(winTrustedPrincipals, ace.sid) {
				return untrusted("'%s' grants 0x%08X to %s; the HkdfGuard native library is only loaded from a location that only SYSTEM, Administrators, or TrustedInstaller can modify.", displayPath, ace.mask, describe(ace.sid))
			}
		default:
			return untrusted("'%s' has an access control entry of type 0x%X, which is not checked; refusing to load the HkdfGuard native library from there.", displayPath, ace.aceType)
		}
	}
	return nil
}

// winVerifySignerIdentity is the signer policy: the leaf is issued to expectedPublisher, carries
// the Code Signing EKU and winExpectedProfileEKU, and its chain ends at winExpectedRootSHA256. The
// chain's trust is WinVerifyTrust's to decide, not this.
func winVerifySignerIdentity(path, leafSubject string, leafEKUs []string, rootSHA256, expectedPublisher string) error {
	if leafSubject != expectedPublisher {
		return untrusted("'%s' is signed by '%s', not the expected HkdfGuard publisher '%s'.", path, leafSubject, expectedPublisher)
	}
	if !strings.EqualFold(rootSHA256, winExpectedRootSHA256) {
		return untrusted("'%s' is signed under a root with SHA-256 %s, not Microsoft Identity Verification Root Certificate Authority 2020 (%s), which HkdfGuard is signed under.", path, rootSHA256, winExpectedRootSHA256)
	}
	if !slices.Contains(leafEKUs, winCodeSigningEKU) {
		return untrusted("'%s' is signed with a certificate not issued for code signing (no EKU %s).", path, winCodeSigningEKU)
	}
	if !slices.Contains(leafEKUs, winExpectedProfileEKU) {
		return untrusted("'%s' is signed with a certificate not issued under HkdfGuard's Artifact Signing profile (no EKU %s).", path, winExpectedProfileEKU)
	}
	return nil
}

// winCertRevoked is CERT_E_REVOKED: WinVerifyTrust's answer when a certificate in the signer's
// chain has definitely been revoked.
const winCertRevoked uint32 = 0x800B010C

// winRevocationDecision is the rule for the revocation pass: refuse only a definite revocation.
// Every other result - success, revocation servers offline (CRYPT_E_REVOCATION_OFFLINE), no
// revocation check possible (CRYPT_E_NO_REVOCATION_CHECK), CERT_E_REVOCATION_FAILURE, or anything
// else - lets the load continue: the first pass already validated the signature and its pins, and
// a host that can't reach a revocation server must still start.
func winRevocationDecision(path string, status uint32) error {
	if status == winCertRevoked {
		return untrusted("'%s' is signed with a certificate that has been revoked; refusing to load it. Install a current release.", path)
	}
	return nil
}

// winMinimumLibraryVersion is the oldest Windows native library release this package loads
// (major, minor, patch): 0.9.0, the first to carry a version resource. A release that fixes a
// security issue raises it, so a genuinely signed older release is refused rather than loaded.
var winMinimumLibraryVersion = [3]uint16{0, 9, 0}

// winRequireMinimumVersion refuses a library whose file version - major, minor and patch from its
// signed version resource; ok is false when it has none or it can't be read - is below
// winMinimumLibraryVersion. The fourth (revision) field is not compared. Run after the signature
// check, whose hash covers the resource.
func winRequireMinimumVersion(path string, version [3]uint16, ok bool) error {
	minimum := winMinimumLibraryVersion
	if !ok {
		return untrusted("'%s' carries no readable version resource, so it predates %d.%d.%d, the oldest HkdfGuard native library this package accepts; install a current release.",
			path, minimum[0], minimum[1], minimum[2])
	}
	if slices.Compare(version[:], minimum[:]) < 0 {
		return untrusted("'%s' is HkdfGuard native library version %d.%d.%d, older than the minimum this package accepts (%d.%d.%d); install a current release.",
			path, version[0], version[1], version[2], minimum[0], minimum[1], minimum[2])
	}
	return nil
}

// winVerifyLoadedModule requires the file Windows mapped the loaded module from (GetModuleFileName)
// to be the verified path. LoadLibraryEx returns an already-loaded module of the same name, and
// honours loader redirection (.local, manifests), without mapping the path it was given; this is
// the Windows counterpart of the dladdr check on Linux and macOS. The comparison is
// case-insensitive, as NTFS names are, and ignores a \\?\ prefix.
func winVerifyLoadedModule(verified, loaded string) error {
	if !strings.EqualFold(winStripLongPathPrefix(loaded), winStripLongPathPrefix(verified)) {
		return untrusted("'%s' passed verification, but Windows loaded '%s' instead (a module of the same name was already loaded, or the load was redirected); refusing to use it.", verified, loaded)
	}
	return nil
}

func winStripLongPathPrefix(path string) string {
	if rest, ok := strings.CutPrefix(path, `\\?\UNC\`); ok {
		return `\\` + rest
	}
	return strings.TrimPrefix(path, `\\?\`)
}

// PE header values.
const (
	peFileDLL      = 0x2000 // IMAGE_FILE_DLL
	peMachineI386  = 0x014C
	peMachineAMD64 = 0x8664
	peMachineARM64 = 0xAA64
)

// winVerifyImageKind requires the PE header to mark the file a DLL built for goarch. Run after the
// signature check, whose hash covers the header.
func winVerifyImageKind(path string, characteristics, machine uint16, goarch string) error {
	if characteristics&peFileDLL == 0 {
		return untrusted("'%s' is signed by the HkdfGuard publisher but is not a DLL (an executable renamed into place?); refusing to load it.", path)
	}

	expected := map[string]uint16{"amd64": peMachineAMD64, "arm64": peMachineARM64, "386": peMachineI386}
	if want, ok := expected[goarch]; !ok || machine != want {
		return untrusted("'%s' is built for machine %s, but this is a %s process; refusing to load it.", path, describeMachine(machine), goarch)
	}
	return nil
}

func describeMachine(machine uint16) string {
	switch machine {
	case peMachineAMD64:
		return "AMD64"
	case peMachineARM64:
		return "ARM64"
	case peMachineI386:
		return "I386"
	default:
		return fmt.Sprintf("0x%04X", machine)
	}
}
