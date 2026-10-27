package securefile

import (
	"fmt"
	"slices"
	"testing"
)

// The Windows key-file location rules. The rules themselves run on every platform, against
// security descriptors built here; the tests that need Windows to parse SDDL, canonicalize a SID
// or name an account are in windowsrules_windows_test.go, and read_windows_test.go runs the rules
// against real files.

const (
	windowsKeyFile     = `C:\HkdfGuardKeys\myapp\v1.key`
	sidUsers           = "S-1-5-32-545"
	sidAuthenticated   = "S-1-5-11"
	sidDeployers       = "S-1-5-21-1111111111-2222222222-3333333333-1005"
	rightsFullControl  = 0x1f01ff
	rightsModify       = 0x1301bf
	rightsWrite        = 0x116
	rightsReadExecSync = 0x1200a9
)

var testAccounts = map[string]string{sidSystem: `NT AUTHORITY\SYSTEM`, sidAdministrators: `BUILTIN\Administrators`, sidUsers: `BUILTIN\Users`}

func testAccountName(sid string) string { return testAccounts[sid] }

// testCanonicalSID stands in for ConvertStringSidToSidW: a well-formed SID string is its own
// canonical form.
func testCanonicalSID(sid string) (string, bool) {
	if len(sid) > 4 && sid[:4] == "S-1-" {
		return sid, true
	}
	return "", false
}

func testTrusted(t *testing.T, extra ...string) []string {
	t.Helper()
	trusted, err := trustedPrincipals(NewKeyFileTrust(KeyFileTrustOptions{WindowsPrincipals: extra}), testCanonicalSID, testAccountName)
	if err != nil {
		t.Fatal(err)
	}
	return trusted
}

func allow(sid string, mask uint32, flags ...uint8) winACE {
	ace := winACE{aceType: aceAllowed, mask: mask, sid: sid}
	if len(flags) > 0 {
		ace.flags = flags[0]
	}
	return ace
}

// locked is a descriptor owned by owner that SYSTEM, Administrators and TrustedInstaller control
// and Users may read, plus extra.
func locked(owner string, extra ...winACE) winSecurity {
	return winSecurity{owner: owner, aces: append([]winACE{
		allow(sidSystem, rightsFullControl), allow(sidAdministrators, rightsFullControl), allow(sidTrustedInstaller, rightsFullControl),
		allow(sidUsers, rightsReadExecSync),
	}, extra...)}
}

func verify(t *testing.T, security winSecurity, item string, guarded uint32, trusted []string) error {
	t.Helper()
	return verifyTrustedOnly(security, windowsKeyFile, item, guarded, trusted, testAccountName)
}

func requireUntrusted(t *testing.T, err error, contains ...string) {
	t.Helper()
	requireKeyFileError(t, err, ErrUntrusted, append([]string{"is not trusted"}, contains...)...)
}

func TestWindowsTrustedPrincipals_AlwaysIncludeSystemAdministratorsAndTrustedInstaller(t *testing.T) {
	if got := testTrusted(t); !slices.Equal(got, []string{sidSystem, sidAdministrators, sidTrustedInstaller}) {
		t.Fatalf("got %v", got)
	}
}

func TestWindowsTrustedPrincipals_AddTheListedDeployers(t *testing.T) {
	if !slices.Contains(testTrusted(t, sidDeployers), sidDeployers) {
		t.Fatal("the deployers are not trusted")
	}
}

func TestWindowsTrustedPrincipals_RefuseGroupsEveryoneIsIn(t *testing.T) {
	for _, sid := range []string{"S-1-1-0", "S-1-5-11", "S-1-5-32-545", "S-1-5-4", "S-1-5-7"} {
		_, err := trustedPrincipals(NewKeyFileTrust(KeyFileTrustOptions{WindowsPrincipals: []string{sid}}), testCanonicalSID, testAccountName)
		requireErrorContaining(t, err, ErrInvalidTrust, "every account")
	}
}

func TestWindowsTrustedPrincipals_RefuseWhatIsNotASid(t *testing.T) {
	for _, value := range []string{"HkdfGuardDeployers", ""} {
		_, err := trustedPrincipals(NewKeyFileTrust(KeyFileTrustOptions{WindowsPrincipals: []string{value}}), testCanonicalSID, testAccountName)
		requireErrorContaining(t, err, ErrInvalidTrust, "not a security identifier")
	}
}

func TestWindowsPathForm_PassAPathOnALocalFixedDrive(t *testing.T) {
	if err := verifyPathForm(windowsKeyFile, driveFixed); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsPathForm_RefuseUncAndDevicePaths(t *testing.T) {
	for _, path := range []string{`\\server\share\v1.key`, `\\?\C:\HkdfGuardKeys\v1.key`, `\\.\PhysicalDrive0`, "//server/share/v1.key"} {
		requireUntrusted(t, verifyPathForm(path, driveFixed), "UNC or device path")
	}
}

func TestWindowsPathForm_RefuseEveryOtherKindOfDrive_NamedAsDotNetNamesIt(t *testing.T) {
	for _, driveType := range []uint32{driveUnknown, driveNoRootDirectory, driveRemovable, driveNetwork, driveCDRom, driveRAM} {
		requireUntrusted(t, verifyPathForm(windowsKeyFile, driveType), driveTypeName(driveType)+" drive")
	}
	var names []string
	for _, driveType := range []uint32{0, 1, 2, 3, 4, 5, 6, 7, 0xffffffff} {
		names = append(names, driveTypeName(driveType))
	}
	if want := []string{"Unknown", "NoRootDirectory", "Removable", "Fixed", "Network", "CDRom", "Ram", "Unknown", "Unknown"}; !slices.Equal(names, want) {
		t.Errorf("got %v; want %v", names, want)
	}
}

func TestWindowsFinalPath_PassTheSameFinalPath_WhateverItsCase(t *testing.T) {
	for _, final := range []string{`\\?\C:\HkdfGuardKeys\myapp\v1.key`, `\\?\c:\hkdfguardkeys\MYAPP\v1.KEY`} {
		if err := verifyFinalPath(windowsKeyFile, final); err != nil {
			t.Errorf("%s: %v", final, err)
		}
	}
}

func TestWindowsFinalPath_RefuseAFinalPathElsewhere_OrRemote(t *testing.T) {
	for _, final := range []string{
		`\\?\D:\elsewhere\v1.key`,                // a junction or symbolic link on the path
		`\\?\C:\real\HkdfGuardKeys\myapp\v1.key`, // a substituted drive
		`\\?\UNC\server\share\myapp\v1.key`,      // a mapped network drive
		`\\?\unc\server\share\myapp\v1.key`,
		`C:\HkdfGuardKeys\myapp\v1.key`, // not the form GetFinalPathNameByHandleW returns
		`\\?\`,
	} {
		requireUntrusted(t, verifyFinalPath(windowsKeyFile, final), final)
	}
}

func TestWindowsFinalPath_RefuseAShortNameThatWasAskedFor(t *testing.T) {
	requireUntrusted(t, verifyFinalPath(`C:\PROGRA~1\HkdfGuard\v1.key`, `\\?\C:\Program Files\HkdfGuard\v1.key`))
}

func TestWindowsFinalPath_CompareCaseAsNtfsDoes_NeverExpandingOneCharacterIntoSeveral(t *testing.T) {
	if err := verifyFinalPath(`C:\Schlüssel\v1.key`, `\\?\C:\SCHLÜSSEL\V1.KEY`); err != nil {
		t.Error(err)
	}
	requireUntrusted(t, verifyFinalPath(`C:\Straße\v1.key`, `\\?\C:\STRASSE\v1.key`))
	// Case only: the Kelvin sign is not a K, though Unicode case folding says it is.
	requireUntrusted(t, verifyFinalPath(`C:\Keys\v1.key`, "\\\\?\\C:\\\u212Aeys\\v1.key"))
}

func TestWindowsReparsePoints_PassARealFolder_AndRefuseAJunctionLinkOrAFolderThatCannotBeExamined(t *testing.T) {
	if err := verifyNotReparsePoint(0x10, windowsKeyFile, `C:\HkdfGuardKeys`); err != nil { // FILE_ATTRIBUTE_DIRECTORY
		t.Error(err)
	}
	requireUntrusted(t, verifyNotReparsePoint(0x10|fileAttributeReparsePoint, windowsKeyFile, `C:\HkdfGuardKeys`), "reparse point")
	requireUntrusted(t, verifyNotReparsePoint(invalidFileAttributes, windowsKeyFile, `C:\HkdfGuardKeys`))
}

func TestWindowsOwnerAndDacl_PassATrustedOwner_ReadOnlyForEveryoneElse(t *testing.T) {
	if err := verify(t, locked(sidAdministrators), windowsKeyFile, guardedRights, testTrusted(t)); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsOwnerAndDacl_RefuseAnUntrustedOwner_NamingIt(t *testing.T) {
	requireUntrusted(t, verify(t, locked(sidUsers), windowsKeyFile, guardedRights, testTrusted(t)), `is owned by BUILTIN\Users (S-1-5-32-545)`)
}

func TestWindowsOwnerAndDacl_RefuseNoOwner(t *testing.T) {
	requireUntrusted(t, verify(t, locked(""), windowsKeyFile, guardedRights, testTrusted(t)), "an unknown principal")
}

func TestWindowsOwnerAndDacl_RefuseNoDacl_WhichGrantsEveryoneEverything(t *testing.T) {
	requireUntrusted(t, verify(t, winSecurity{owner: sidAdministrators, daclAbsent: true}, windowsKeyFile, guardedRights, testTrusted(t)), "no DACL")
}

func TestWindowsOwnerAndDacl_RefuseAnyWriteRightForAnUntrustedPrincipal(t *testing.T) {
	for _, rights := range []uint32{rightWriteData, rightAppendData, rightWriteExtendedAttributes, rightDeleteSubdirectoriesAndFiles, rightDelete,
		rightChangePermissions, rightTakeOwnership, rightsModify, rightsFullControl, rightGenericAll, rightGenericWrite} {
		requireUntrusted(t, verify(t, locked(sidAdministrators, allow(sidUsers, rights)), windowsKeyFile, guardedRights, testTrusted(t)), "grants")
	}
}

func TestWindowsOwnerAndDacl_RefuseAWriteRightForAnAllowEntryWithNoReadableSid(t *testing.T) {
	requireUntrusted(t, verify(t, locked(sidAdministrators, allow("", rightWriteData)), windowsKeyFile, guardedRights, testTrusted(t)), "an unknown principal")
}

func TestWindowsOwnerAndDacl_LetATrustedDeployerOwnAndModify(t *testing.T) {
	security := locked(sidDeployers, allow(sidDeployers, rightsModify))
	if err := verify(t, security, windowsKeyFile, guardedRights, testTrusted(t, sidDeployers)); err != nil {
		t.Fatal(err)
	}
	requireUntrusted(t, verify(t, security, windowsKeyFile, guardedRights, testTrusted(t)))
}

func TestWindowsOwnerAndDacl_IgnoreDenyAndInheritOnlyEntries(t *testing.T) {
	// A folder's: only a folder carries entries meant for what's created inside it.
	security := winSecurity{owner: sidAdministrators, aces: []winACE{
		allow(sidAdministrators, rightsFullControl), {aceType: aceDenied, mask: rightsFullControl, sid: sidUsers},
		allow(sidAuthenticated, rightsModify, inheritOnlyACE|0x3),
	}}
	if err := verify(t, security, `C:\HkdfGuardKeys`, guardedRights, testTrusted(t)); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsOwnerAndDacl_RefuseAnEntryItCannotEvaluate(t *testing.T) {
	for _, aceType := range []uint8{aceAllowedObject, aceAllowedCallbackObject, 0x11} {
		requireUntrusted(t, verify(t, locked(sidAdministrators, winACE{aceType: aceType, mask: rightWriteData}), windowsKeyFile, guardedRights, testTrusted(t)),
			fmt.Sprintf("type 0x%02X, which this check can't evaluate", aceType))
	}
}

func TestWindowsOwnerAndDacl_IgnoreEveryKindOfDenyEntry(t *testing.T) {
	for _, aceType := range []uint8{aceDeniedObject, aceDeniedCallback, aceDeniedCallbackObject} {
		if err := verify(t, locked(sidAdministrators, winACE{aceType: aceType, mask: rightsFullControl}), windowsKeyFile, guardedRights, testTrusted(t)); err != nil {
			t.Errorf("type 0x%02X: %v", aceType, err)
		}
	}
}

func TestWindowsOwnerAndDacl_CheckCallbackAllowEntriesLikePlainOnes(t *testing.T) {
	requireUntrusted(t, verify(t, locked(sidAdministrators, winACE{aceType: aceAllowedCallback, mask: rightWriteData, sid: sidUsers}),
		windowsKeyFile, guardedRights, testTrusted(t)), "grants")
}

func TestWindowsOwnerAndDacl_LetTheDriveRootAllowCreatingFolders_ButNotRenamingThem(t *testing.T) {
	// A default C:\: Authenticated Users may create folders (AppendData) in the root itself.
	root := locked(sidTrustedInstaller, allow(sidAuthenticated, rightAppendData))
	if err := verify(t, root, `C:\`, guardedRootRights, testTrusted(t)); err != nil {
		t.Fatal(err)
	}

	// The same entry on any folder below the root is refused: they could create files there.
	requireUntrusted(t, verify(t, root, `C:\HkdfGuardKeys`, guardedRights, testTrusted(t)))

	renamable := locked(sidTrustedInstaller, allow(sidAuthenticated, rightAppendData), allow(sidAuthenticated, rightDeleteSubdirectoriesAndFiles))
	requireUntrusted(t, verify(t, renamable, `C:\`, guardedRootRights, testTrusted(t)))
}

func TestWindowsOwnerAndDacl_DescribeAnUnmappableSidByItsValue_AndNameTheRights(t *testing.T) {
	requireUntrusted(t, verify(t, locked(sidAdministrators, allow(sidDeployers, rightsWrite)), windowsKeyFile, guardedRights, testTrusted(t)),
		"to "+sidDeployers+".", "grants 0x00000116 (WriteData, AppendData, WriteExtendedAttributes, WriteAttributes)")
}

func TestDescribeRights_NamesGenericAndUnnamedBits(t *testing.T) {
	for mask, want := range map[uint32]string{
		0:          "0x00000000",
		0x10000200: "0x10000200 (0x00000200, GenericAll)",
		0x80000000: "0x80000000 (GenericRead)",
	} {
		if got := describeRights(mask); got != want {
			t.Errorf("describeRights(%#x) = %q; want %q", mask, got, want)
		}
	}
}

func TestExpandShortNames_ExpandsTheLongestLeadingPartThatExists_KeepingTheRest(t *testing.T) {
	longNames := map[string]string{`C:\PROGRA~1`: `C:\Program Files`, `C:\PROGRA~1\HKDFGU~1`: `C:\Program Files\HkdfGuard Keys`}
	longPath := func(path string) (string, bool) { long, ok := longNames[path]; return long, ok }

	for full, want := range map[string]string{
		`C:\PROGRA~1\HKDFGU~1`:               `C:\Program Files\HkdfGuard Keys`,
		`C:\PROGRA~1\HKDFGU~1\MISSING~1.KEY`: `C:\Program Files\HkdfGuard Keys\MISSING~1.KEY`,
		`C:\PROGRA~1\missing\v1.key`:         `C:\Program Files\missing\v1.key`,
		`C:\NOSUCH~1\v1.key`:                 `C:\NOSUCH~1\v1.key`, // nothing to expand: left as it is
	} {
		if got := expandShortNames(full, longPath); got != want {
			t.Errorf("expandShortNames(%q) = %q; want %q", full, got, want)
		}
	}
}
