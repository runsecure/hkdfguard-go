package nativev1

import (
	"strings"
	"testing"
)

// The Windows loader's decisions, against security descriptors and signers given as plain data,
// so they run on every platform.

const (
	sidUsers              = "S-1-5-32-545"
	sidAuthenticatedUsers = "S-1-5-11"
	artifactSigningEKU    = "1.3.6.1.4.1.311.97.1.0" // carried by every Artifact Signing leaf
	fileAllAccess         = 0x001F01FF
	fileReadAndExecute    = 0x001200A9
	fileWrite             = 0x00120116 // FILE_GENERIC_WRITE
)

var genuineEKUs = []string{artifactSigningEKU, winCodeSigningEKU, winExpectedProfileEKU}

func allow(sid string, mask uint32) winACE {
	return winACE{aceType: aceTypeAccessAllowed, mask: mask, sid: sid}
}

func describeAsIs(sid string) string { return sid }

func verifyTrustedOnly(security winSecurity) error {
	return winVerifyTrustedOnly(security, "test", winGuardedRights, describeAsIs)
}

func verifyDriveRoot(security winSecurity) error {
	return winVerifyTrustedOnly(security, `C:\`, winGuardedRootRights, describeAsIs)
}

func TestWinTrustedOwnerAndReadOnlyForEveryoneElse_Passes(t *testing.T) {
	security := winSecurity{owner: sidLocalSystem, aces: []winACE{
		allow(sidLocalSystem, fileAllAccess),
		allow(sidAdministrators, fileAllAccess),
		allow(sidTrustedInstaller, fileAllAccess),
		allow(sidUsers, fileReadAndExecute),
	}}

	if err := verifyTrustedOnly(security); err != nil {
		t.Error(err)
	}
}

func TestWinAnyWriteRightForAnUntrustedPrincipal_IsRefused(t *testing.T) {
	rights := []uint32{rightWriteData, rightAppendData, rightWriteExtendedAttribute, rightDeleteChild,
		rightDelete, rightWriteDAC, rightWriteOwner, 0x001301BF /* Modify */, rightGenericAll, rightGenericWrite}
	for _, right := range rights {
		security := winSecurity{owner: sidAdministrators, aces: []winACE{allow(sidUsers, right)}}

		requireUntrusted(t, verifyTrustedOnly(security), sidUsers)
	}
}

func TestWinAnUntrustedOwner_IsRefused(t *testing.T) {
	// An owner can always rewrite the ACL, whatever it currently says.
	requireUntrusted(t, verifyTrustedOnly(winSecurity{owner: sidUsers, aces: []winACE{allow(sidLocalSystem, fileAllAccess)}}))

	// One that maps to no account here, e.g. left behind by a deleted user, is named by SID.
	orphan := "S-1-5-21-1-2-3-4242"
	requireUntrusted(t, verifyTrustedOnly(winSecurity{owner: orphan, aces: []winACE{allow(sidLocalSystem, fileAllAccess)}}), orphan)
}

func TestWinNoOwnerAtAll_IsRefused(t *testing.T) {
	requireUntrusted(t, verifyTrustedOnly(winSecurity{aces: []winACE{allow(sidLocalSystem, fileAllAccess)}}), "an unknown principal")
}

func TestWinANullDACL_IsRefused(t *testing.T) {
	requireUntrusted(t, verifyTrustedOnly(winSecurity{owner: sidLocalSystem, daclAbsent: true}), "no DACL")
}

func TestWinInheritOnlyAndDenyEntries_AreIgnored(t *testing.T) {
	// A folder like Program Files: Users get full control of what they create beneath it
	// (inherit-only, so not of the folder itself), plus an explicit deny.
	security := winSecurity{owner: sidLocalSystem, aces: []winACE{
		{aceType: aceTypeAccessDenied, mask: fileWrite, sid: sidUsers},
		allow(sidLocalSystem, fileAllAccess),
		{aceType: aceTypeAccessAllowed, flags: aceFlagInheritOnly | 0x3, mask: fileAllAccess, sid: sidUsers},
		allow(sidUsers, fileReadAndExecute),
	}}

	if err := verifyTrustedOnly(security); err != nil {
		t.Error(err)
	}
}

func TestWinACallbackAllowEntry_IsCheckedLikeAnyOther(t *testing.T) {
	security := winSecurity{owner: sidLocalSystem, aces: []winACE{
		{aceType: aceTypeAccessAllowedCallback, mask: rightWriteData, sid: sidUsers},
	}}

	requireUntrusted(t, verifyTrustedOnly(security), sidUsers)
}

func TestWinAnUnrecognizedEntryType_IsRefusedRatherThanInterpreted(t *testing.T) {
	security := winSecurity{owner: sidLocalSystem, aces: []winACE{{aceType: 0x5 /* object ACE */, mask: rightWriteData}}}

	requireUntrusted(t, verifyTrustedOnly(security), "type 0x5")
}

func TestWinADefaultSystemDriveACL_Passes(t *testing.T) {
	// As a default C:\: Authenticated Users may create folders in the root (0x4) and get Modify on
	// what they create (inherit-only) - neither lets them rename an existing folder.
	security := winSecurity{owner: sidLocalSystem, aces: []winACE{
		allow(sidAdministrators, fileAllAccess),
		allow(sidLocalSystem, fileAllAccess),
		allow(sidUsers, fileReadAndExecute),
		{aceType: aceTypeAccessAllowed, flags: aceFlagInheritOnly | 0x3, mask: 0xE0010000, sid: sidAuthenticatedUsers},
		allow(sidAuthenticatedUsers, 0x4),
	}}

	if err := verifyDriveRoot(security); err != nil {
		t.Error(err)
	}
}

func TestWinADriveRootRightThatCouldRenameAFolderBeneath_IsRefused(t *testing.T) {
	for _, right := range []uint32{rightDeleteChild, rightWriteDAC, rightWriteOwner, rightGenericAll, fileAllAccess} {
		security := winSecurity{owner: sidLocalSystem, aces: []winACE{allow(sidLocalSystem, fileAllAccess), allow(sidUsers, right)}}

		requireUntrusted(t, verifyDriveRoot(security), sidUsers)
	}
}

func TestWinDriveRootRightsThatOnlyCreateNewEntries_AreAllowed(t *testing.T) {
	for _, right := range []uint32{rightWriteData /* FILE_ADD_FILE */, rightAppendData /* FILE_ADD_SUBDIRECTORY */, rightGenericWrite} {
		security := winSecurity{owner: sidLocalSystem, aces: []winACE{allow(sidLocalSystem, fileAllAccess), allow(sidUsers, right)}}

		if err := verifyDriveRoot(security); err != nil {
			t.Errorf("0x%X: %v", right, err)
		}
	}
}

func TestWinADriveRootWithAnUntrustedOwner_IsRefused(t *testing.T) {
	requireUntrusted(t, verifyDriveRoot(winSecurity{owner: sidUsers, aces: []winACE{allow(sidLocalSystem, fileAllAccess)}}))
}

// --- Signer ---------------------------------------------------------------------------------

func verifySigner(ekus []string, subject, root string) error {
	return winVerifySignerIdentity("test", subject, ekus, root, winExpectedPublisher)
}

func TestWinThePinnedRootProfileAndPublisher_Pass(t *testing.T) {
	if err := verifySigner(genuineEKUs, winExpectedPublisher, winExpectedRootSHA256); err != nil {
		t.Error(err)
	}
	if err := verifySigner(genuineEKUs, winExpectedPublisher, strings.ToLower(winExpectedRootSHA256)); err != nil {
		t.Errorf("lower-case root hash: %v", err)
	}
}

func TestWinAnotherRoot_IsRefused(t *testing.T) {
	// e.g. a root a non-administrator added to their own CurrentUser\Root, issuing the same subject.
	otherRoot := strings.Repeat("A", 64)
	requireUntrusted(t, verifySigner(genuineEKUs, winExpectedPublisher, otherRoot), otherRoot)
}

func TestWinMissingOrForeignProfileEKU_IsRefused(t *testing.T) {
	requireUntrusted(t, verifySigner([]string{winCodeSigningEKU, artifactSigningEKU}, winExpectedPublisher, winExpectedRootSHA256), winExpectedProfileEKU)
	// Another Artifact Signing customer's leaf: same root, same shared EKU, its own profile EKU.
	requireUntrusted(t, verifySigner([]string{artifactSigningEKU, winCodeSigningEKU, "1.3.6.1.4.1.311.97.1.2.3.4"}, winExpectedPublisher, winExpectedRootSHA256), winExpectedProfileEKU)
}

func TestWinNoCodeSigningEKU_IsRefused(t *testing.T) {
	requireUntrusted(t, verifySigner([]string{artifactSigningEKU, winExpectedProfileEKU}, winExpectedPublisher, winExpectedRootSHA256), winCodeSigningEKU)
	requireUntrusted(t, verifySigner(nil, winExpectedPublisher, winExpectedRootSHA256))
}

func TestWinAnotherSubject_IsRefused_EvenWithThePinnedRootAndProfile(t *testing.T) {
	requireUntrusted(t, verifySigner(genuineEKUs, "CN=Someone Else", winExpectedRootSHA256), "not the expected HkdfGuard publisher")
}

// --- Image kind -----------------------------------------------------------------------------

func TestWinADLLForThisProcessArchitecture_Passes(t *testing.T) {
	for goarch, machine := range map[string]uint16{"amd64": peMachineAMD64, "arm64": peMachineARM64, "386": peMachineI386} {
		if err := winVerifyImageKind("test", peFileDLL|0x0002, machine, goarch); err != nil {
			t.Errorf("%s: %v", goarch, err)
		}
	}
}

func TestWinAnExecutable_IsRefused(t *testing.T) {
	// e.g. hkdfguard.exe renamed into place: signed by the same profile.
	requireUntrusted(t, winVerifyImageKind("test", 0x0002, peMachineAMD64, "amd64"), "not a DLL")
}

func TestWinADLLForAnotherArchitecture_IsRefused(t *testing.T) {
	cases := []struct {
		goarch  string
		machine uint16
	}{{"amd64", peMachineARM64}, {"arm64", peMachineAMD64}, {"amd64", peMachineI386}, {"wasm", 0}}
	for _, c := range cases {
		requireUntrusted(t, winVerifyImageKind("test", peFileDLL, c.machine, c.goarch))
	}
}

func TestWinRevocationDecision_RefusesOnlyADefiniteRevocation(t *testing.T) {
	const path = `C:\Program Files\HkdfGuard\v1\HkdfGuard.dll`
	requireUntrusted(t, winRevocationDecision(path, 0x800B010C), path, "revoked") // CERT_E_REVOKED

	for _, status := range []uint32{
		0,          // success: not revoked
		0x80092013, // CRYPT_E_REVOCATION_OFFLINE: the server couldn't be reached
		0x80092012, // CRYPT_E_NO_REVOCATION_CHECK: no revocation data
		0x800B010E, // CERT_E_REVOCATION_FAILURE: revocation status unknown
		0x80096010, // anything else (TRUST_E_BAD_DIGEST): the first pass already decided validity
	} {
		if err := winRevocationDecision(path, status); err != nil {
			t.Errorf("status %#x: %v; only a definite revocation refuses the load", status, err)
		}
	}
}
