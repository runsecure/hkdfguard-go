package securefile

import (
	"fmt"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The Windows key-file location rules - the native library's (hkdfguard_open_file's) - kept free
// of system calls: a security descriptor, attributes and paths are passed in as plain data, so the
// rules are tested on every platform. read_windows.go wires them to the Win32 calls.
//
//   - The path names a file on a local fixed drive. UNC paths, device paths (\\?\, \\.\) and
//     network drives are refused before anything is opened, so no server named in a path is ever
//     contacted.
//   - The opened file's final path - with every symbolic link, junction, mount point and
//     substituted drive resolved - is the path that was asked for, once the full path has expanded
//     any 8.3 short name (it expands each one that exists on disk; a path still spelled with a short
//     name doesn't match the final path and is refused). So nothing on the path redirects it, and
//     the folders checked are the ones the file is in.
//   - The file, and every folder above it, is owned by a trusted principal, and grants no one else
//     any right to write, append, delete, rename, change its permissions or take ownership. For a
//     folder that also covers creating files and folders in it. The drive root is held only to what
//     could rename or delete what's beneath it, since a default C:\ lets Authenticated Users create
//     folders. A missing (NULL) DACL, and an entry whose trustee can't be read the plain way (an
//     object ACE), are refused.
//
// Trusted principals are SYSTEM, Administrators, TrustedInstaller and KeyFileTrust's
// WindowsPrincipals.

// What GetDriveTypeW reports for a drive root (DRIVE_*).
const (
	driveUnknown         = 0
	driveNoRootDirectory = 1
	driveRemovable       = 2
	driveFixed           = 3
	driveNetwork         = 4
	driveCDRom           = 5
	driveRAM             = 6
)

// driveTypeNames names the drive types as .NET's DriveType does, as every port does in messages.
var driveTypeNames = []string{"Unknown", "NoRootDirectory", "Removable", "Fixed", "Network", "CDRom", "Ram"}

// driveTypeName is a drive type's name as .NET names it; anything GetDriveTypeW doesn't define is
// "Unknown".
func driveTypeName(driveType uint32) string {
	if int(driveType) < len(driveTypeNames) {
		return driveTypeNames[driveType]
	}
	return "Unknown"
}

const (
	sidSystem           = "S-1-5-18"
	sidAdministrators   = "S-1-5-32-544"
	sidTrustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464" // NT SERVICE\TrustedInstaller's fixed service SID
)

// alwaysTrusted are the principals every Windows key file may be owned and modified by.
var alwaysTrusted = []string{sidSystem, sidAdministrators, sidTrustedInstaller}

// neverTrusted are the groups every account, or every signed-in one, is in - Everyone,
// Authenticated Users, Users, Interactive, Anonymous: trusting one trusts everybody.
var neverTrusted = []string{"S-1-1-0", "S-1-5-11", "S-1-5-32-545", "S-1-5-4", "S-1-5-7"}

// File access rights (winnt.h).
const (
	rightWriteData                    = 0x0002 // FILE_WRITE_DATA; FILE_ADD_FILE on a folder
	rightAppendData                   = 0x0004 // FILE_APPEND_DATA; FILE_ADD_SUBDIRECTORY on a folder
	rightWriteExtendedAttributes      = 0x0010 // FILE_WRITE_EA
	rightDeleteSubdirectoriesAndFiles = 0x0040 // FILE_DELETE_CHILD
	rightDelete                       = 0x0001_0000
	rightChangePermissions            = 0x0004_0000 // WRITE_DAC
	rightTakeOwnership                = 0x0008_0000 // WRITE_OWNER
	rightGenericAll                   = 0x1000_0000
	rightGenericWrite                 = 0x4000_0000
)

// guardedRights is any right that lets a principal change what this path reads: write or append
// data (on a folder, create files or folders), delete or rename (Delete on the item,
// DeleteSubdirectoriesAndFiles on its parent), write extended attributes, or take over the ACL.
// Generic bits are listed too, since an ACE can carry them unmapped.
const guardedRights = rightWriteData | rightAppendData | rightWriteExtendedAttributes | rightDeleteSubdirectoriesAndFiles |
	rightDelete | rightChangePermissions | rightTakeOwnership | rightGenericAll | rightGenericWrite

// guardedRootRights is, on the drive root, only what lets a principal rename or delete an entry
// directly beneath it.
const guardedRootRights = rightDeleteSubdirectoriesAndFiles | rightChangePermissions | rightTakeOwnership | rightGenericAll

// ACE types (winnt.h).
const (
	aceAllowed               = 0x00
	aceDenied                = 0x01
	aceAllowedObject         = 0x05
	aceDeniedObject          = 0x06
	aceAllowedCallback       = 0x09
	aceDeniedCallback        = 0x0a
	aceAllowedCallbackObject = 0x0b
	aceDeniedCallbackObject  = 0x0c
)

// inheritOnlyACE (INHERIT_ONLY_ACE): the entry applies only to what is created inside a folder,
// never the folder itself.
const inheritOnlyACE = 0x08

const (
	// invalidFileAttributes is INVALID_FILE_ATTRIBUTES, which has every bit set - the reparse-point
	// bit included.
	invalidFileAttributes     = 0xffff_ffff
	fileAttributeReparsePoint = 0x400
)

// winACE is one DACL entry: its type, flags (inheritance), the access mask it allows or denies,
// and its trustee's SID - "" for a type with no plain SID.
type winACE struct {
	aceType uint8
	flags   uint8
	mask    uint32
	sid     string
}

// winSecurity is an item's owner ("" if the descriptor has none) and DACL; daclAbsent is a missing
// or NULL DACL, which grants every user full control.
type winSecurity struct {
	owner      string
	daclAbsent bool
	aces       []winACE
}

// accountNameFunc is the account a SID string maps to, or "" - for describing principals in
// messages.
type accountNameFunc func(sid string) string

// trustedPrincipals returns the principals trust trusts, the always-trusted ones included, as
// canonical SID strings. canonicalSID returns a SID string's canonical form, or false if it isn't
// one. It fails with ErrInvalidTrust if a listed SID isn't valid, or is one that every account is
// in.
func trustedPrincipals(trust KeyFileTrust, canonicalSID func(string) (string, bool), accountName accountNameFunc) ([]string, error) {
	trusted := slices.Clone(alwaysTrusted)
	for _, value := range trust.windowsPrincipals {
		sid, ok := "", false
		if value != "" {
			sid, ok = canonicalSID(value)
		}
		if !ok {
			return nil, invalidTrust("KeyFileTrust.WindowsPrincipals holds '%s', which is not a security identifier (S-1-...).", value)
		}
		if slices.Contains(neverTrusted, sid) {
			return nil, invalidTrust("KeyFileTrust.WindowsPrincipals holds %s, which every account (or every signed-in one) is in; "+
				"trusting it would trust anyone to replace a key file.", describePrincipal(sid, accountName))
		}
		trusted = append(trusted, sid)
	}
	return trusted, nil
}

// verifyPathForm refuses a path that isn't on a local fixed drive, before anything is opened.
// driveType is the DRIVE_* type of the drive the path's root names.
func verifyPathForm(fullPath string, driveType uint32) error {
	if strings.HasPrefix(fullPath, `\\`) || strings.HasPrefix(fullPath, "//") {
		return untrustedWindows(fullPath, "it is a UNC or device path; key files are only read from a local drive")
	}
	if driveType != driveFixed {
		return untrustedWindows(fullPath, "it is on a %s drive; key files are only read from a local fixed drive", driveTypeName(driveType))
	}
	return nil
}

// verifyFinalPath requires the opened file's final path - GetFinalPathNameByHandleW's answer for
// the opened handle (\\?\C:\...) - to be the one that was asked for.
func verifyFinalPath(fullPath, finalPath string) error {
	const localPrefix = `\\?\`
	isLocal := strings.HasPrefix(finalPath, localPrefix) &&
		!(len(finalPath) >= 8 && equalsIgnoreCase(finalPath[:8], `\\?\UNC\`))
	if !isLocal || !equalsIgnoreCase(finalPath[len(localPrefix):], fullPath) {
		return untrustedWindows(fullPath, "it opens '%s' - its path runs through a symbolic link, junction, mount point or substituted drive. "+
			"Configure it as the full, real path", finalPath)
	}
	return nil
}

// verifyNotReparsePoint refuses a folder that is a symbolic link, junction or other reparse point,
// by its GetFileAttributesW value. invalidFileAttributes has every bit set, so a folder that can't
// be examined is refused too.
func verifyNotReparsePoint(attributes uint32, fullPath, folder string) error {
	if attributes&fileAttributeReparsePoint != 0 {
		return untrustedWindows(fullPath, "'%s' is a symbolic link, junction or other reparse point", folder)
	}
	return nil
}

// verifyTrustedOnly requires a trusted owner, and no Allow entry granting any of guarded
// (guardedRights for the file and folders, guardedRootRights for the drive root) to anyone else.
// Inherit-only entries don't apply to the item itself, and Deny entries can only remove access,
// so both are ignored. A missing DACL grants everyone everything, and an entry whose trustee can't
// be read the plain way (an object ACE) can't be evaluated: both are refused.
func verifyTrustedOnly(security winSecurity, fullPath, item string, guarded uint32, trusted []string, accountName accountNameFunc) error {
	if security.owner == "" || !slices.Contains(trusted, security.owner) {
		return untrustedWindows(fullPath, "'%s' is owned by %s, not SYSTEM, Administrators, TrustedInstaller or a trusted deployer",
			item, describePrincipal(security.owner, accountName))
	}
	if security.daclAbsent {
		return untrustedWindows(fullPath, "'%s' has no DACL, which grants every user full control", item)
	}

	for _, ace := range security.aces {
		if ace.flags&inheritOnlyACE != 0 {
			continue
		}
		switch ace.aceType {
		case aceDenied, aceDeniedObject, aceDeniedCallback, aceDeniedCallbackObject:
			continue // can only remove access
		case aceAllowed, aceAllowedCallback:
			if ace.mask&guarded != 0 && (ace.sid == "" || !slices.Contains(trusted, ace.sid)) {
				return untrustedWindows(fullPath, "'%s' grants %s to %s", item, describeRights(ace.mask), describePrincipal(ace.sid, accountName))
			}
		default:
			return untrustedWindows(fullPath, "'%s' has an access control entry of type 0x%02X, which this check can't evaluate", item, ace.aceType)
		}
	}
	return nil
}

// rightNames names an access mask's bits, as describeRights does: .NET's FileSystemRights names,
// then the generic bits.
var rightNames = [32]string{
	"ReadData", "WriteData", "AppendData", "ReadExtendedAttributes", "WriteExtendedAttributes", "ExecuteFile",
	"DeleteSubdirectoriesAndFiles", "ReadAttributes", "WriteAttributes", "", "", "", "", "", "", "",
	"Delete", "ReadPermissions", "ChangePermissions", "TakeOwnership", "Synchronize", "", "", "",
	"AccessSystemSecurity", "MaximumAllowed", "", "", "GenericAll", "GenericExecute", "GenericWrite", "GenericRead",
}

// describeRights is an access mask as hex, then the names of its bits, such as
// "0x00000116 (WriteData, AppendData, ...)".
func describeRights(mask uint32) string {
	var names []string
	for bit := range 32 {
		flag := uint32(1) << bit
		if mask&flag == 0 {
			continue
		}
		if rightNames[bit] != "" {
			names = append(names, rightNames[bit])
		} else {
			names = append(names, fmt.Sprintf("0x%08X", flag))
		}
	}
	if len(names) == 0 {
		return fmt.Sprintf("0x%08X", mask)
	}
	return fmt.Sprintf("0x%08X (%s)", mask, strings.Join(names, ", "))
}

// untrustedWindows is the refusal of a key file whose location isn't trusted.
func untrustedWindows(path, format string, args ...any) *KeyFileError {
	return keyFileError(ErrUntrusted, path, "Key file '%s' is not trusted: %s. Keep key files in a folder of their own that only administrators "+
		"(or a trusted deployer, see KeyFileTrust) can modify, with inherited permissions removed.", path, fmt.Sprintf(format, args...))
}

func describePrincipal(sid string, accountName accountNameFunc) string {
	if sid == "" {
		return "an unknown principal"
	}
	if name := accountName(sid); name != "" {
		return name + " (" + sid + ")"
	}
	return sid
}

// expandShortNames is what .NET's Path.GetFullPath does after GetFullPathNameW: it expands the
// longest leading part of full that exists, since GetLongPathNameW fails outright for a path whose
// last component is missing. longPath is GetLongPathNameW, false when it fails.
func expandShortNames(full string, longPath func(string) (string, bool)) string {
	prefix, rest := full, ""
	for {
		if expanded, ok := longPath(prefix); ok {
			return expanded + rest
		}
		separator := strings.LastIndexByte(prefix, '\\')
		// Stop at the root ("C:\" or "\\server\share\"): nothing left to expand.
		if separator <= 2 {
			return full
		}
		rest = prefix[separator:] + rest
		prefix = prefix[:separator]
	}
}

// equalsIgnoreCase is ordinal comparison ignoring case, character by character with simple case
// mapping, as .NET's OrdinalIgnoreCase and NTFS compare names: unlike strings.ToUpper on the whole
// string, it never turns one character into several ("ß" is not "SS"), and unlike strings.EqualFold
// it maps case only, never folding other characters together.
func equalsIgnoreCase(first, second string) bool {
	if utf8.RuneCountInString(first) != utf8.RuneCountInString(second) {
		return false
	}
	for len(first) > 0 {
		a, sizeA := utf8.DecodeRuneInString(first)
		b, sizeB := utf8.DecodeRuneInString(second)
		if a != b && unicode.ToUpper(a) != unicode.ToUpper(b) {
			return false
		}
		first, second = first[sizeA:], second[sizeB:]
	}
	return true
}
