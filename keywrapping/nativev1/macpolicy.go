package nativev1

import (
	"slices"
	"strconv"
	"strings"
)

// The macOS loader's decisions, kept free of system calls (they are passed in) so they can be
// checked against simulated filesystems on any platform. The loader (kms_darwin.go) loads the
// library from one of its two install locations and nowhere else:
//
//  1. Location. The system install, macSystemDirectory, is used whenever it exists; the per-user
//     install, ~/.hkdfguard/v1, only when there is no system install. Anything running as the user
//     can write to the user's home, so a per-user file must never override a root-owned system
//     one. If the system install exists but fails a check, loading fails - it never falls back.
//     Nor does it fall back when the system install merely can't be examined: only "nothing is
//     there" (ENOENT, ENOTDIR) counts as "not installed".
//  2. Path integrity. No component of the path, from the file up to /, may be a symbolic link, or
//     writable by anyone other than its owner - except that the system directories above an
//     install (/, /Library, /Library/Application Support, /Users) may also be writable by the
//     wheel or admin group when root owns them. Every component of a system install must be owned
//     by root; of a user install, by root or the current user.
//  3. Code signature. The file's signature must be valid and satisfy macCodeRequirement.
//  4. What dyld loaded. dlopen of an absolute path first looks for its leaf name in every
//     DYLD_LIBRARY_PATH directory, so the loader refuses before dlopen if one holds a
//     macFileName, and after dlopen asks dyld (dladdr) which file it mapped; anything but the
//     verified path is unloaded and refused.

const (
	macFileName               = "libhkdfguard_v1.dylib"
	macSystemDirectory        = "/Library/Application Support/HkdfGuard/v1"
	macUserDirectoryUnderHome = ".hkdfguard/v1"
	macSystemPath             = macSystemDirectory + "/" + macFileName

	// macTeamID is the Apple team ID the library must be signed by: the certificate's subject OU
	// (and codesign's TeamIdentifier).
	macTeamID = "MFW3T8R8J3"

	// macCodeRequirement matches the release build's own designated requirement: this library's
	// identifier, signed with a Developer ID Application certificate (not Apple Development)
	// issued to the HkdfGuard team. So a development build, or any other binary the team signs
	// (such as hkdfguard-v1-initialize), is refused.
	macCodeRequirement = `identifier "libhkdfguard_v1" and anchor apple generic` +
		` and certificate 1[field.1.2.840.113635.100.6.2.6] exists` + // Developer ID CA
		` and certificate leaf[field.1.2.840.113635.100.6.1.13] exists` + // Developer ID Application leaf
		` and certificate leaf[subject.OU] = "` + macTeamID + `"`

	// macMinimumMajorVersion is the library's own minimum (its LC_BUILD_VERSION minos).
	macMinimumMajorVersion = 13

	// probeExport is an export every genuine build has; its address tells dladdr which file was
	// loaded. Shared with the Linux loader.
	probeExport = "hkdfguard_wrap_dek"
)

// gid 0 (wheel) and 80 (admin): on macOS, root-owned system directories such as
// /Library/Application Support may be writable by these groups. Both are administrators.
var macAdministrativeGroups = []uint32{0, 80}

// The only directories that exception applies to: the system ones above the two installs, which
// macOS - not the HkdfGuard installer - owns and permissions.
var macSharedSystemDirectories = []string{"/", "/Library", "/Library/Application Support", "/Users"}

// macUserPath is the per-user install's full path under homeDirectory.
func macUserPath(homeDirectory string) string {
	return strings.TrimRight(homeDirectory, "/") + "/" + macUserDirectoryUnderHome + "/" + macFileName
}

// macRequireSupportedPlatform requires what the library itself requires: an arm64 process (the
// library is built for Apple silicon only, and needs its Secure Enclave) on macOS 13 or later.
// Checked first, so an unsupported Mac gets this explanation rather than dyld's.
func macRequireSupportedPlatform(goarch, osVersion string) error {
	if goarch != "arm64" {
		detail := "."
		if goarch == "amd64" {
			detail = " - an Intel Mac, or an amd64 Go binary running under Rosetta; on Apple silicon, build for darwin/arm64."
		}
		return unsupported("The HkdfGuard native KMS library requires Apple silicon: an arm64 process on an arm64 Mac. This process is %s%s", goarch, detail)
	}

	majorText, _, _ := strings.Cut(osVersion, ".")
	major, err := strconv.Atoi(majorText)
	if err != nil {
		return unsupported("Could not determine the macOS version (got %q); the HkdfGuard native KMS library requires macOS %d or later.", osVersion, macMinimumMajorVersion)
	}
	if major < macMinimumMajorVersion {
		return unsupported("The HkdfGuard native KMS library requires macOS %d or later; this is macOS %s.", macMinimumMajorVersion, osVersion)
	}
	return nil
}

// macChoosePath returns the system install if it exists, otherwise the user install if that
// exists. probe is lstat's result for a path: 0 if it exists, else the errno.
func macChoosePath(probe func(string) int, homeDirectory string) (path string, isSystem bool, err error) {
	present, err := macIsPresent(macSystemPath, probe, "system-wide")
	if err != nil {
		return "", false, err
	}
	if present {
		return macSystemPath, true, nil
	}

	user := macUserPath(homeDirectory)
	// Only an absolute home: a relative one would resolve against the working directory.
	if strings.HasPrefix(homeDirectory, "/") {
		present, err := macIsPresent(user, probe, "per-user")
		if err != nil {
			return "", false, err
		}
		if present {
			return user, false, nil
		}
	}

	return "", false, notInstalled("The HkdfGuard native KMS library is not installed. Install it at '%s' (system-wide) or '%s' (this user); it is never loaded from anywhere else.", macSystemPath, user)
}

// macIsPresent: ENOENT and ENOTDIR mean nothing is installed there. Anything else (EACCES, ELOOP,
// EIO, ...) means something may well be there that this process isn't allowed to see; a system
// install hidden that way must not let the per-user one take its place.
func macIsPresent(path string, probe func(string) int, kind string) (bool, error) {
	switch errno := probe(path); errno {
	case 0:
		return true, nil
	case errnoENOENT, errnoENOTDIR:
		return false, nil
	default:
		return false, untrusted("Could not tell whether the %s HkdfGuard native library '%s' exists (lstat failed with errno %d); refusing to guess or to fall back to another location.", kind, path, errno)
	}
}

// macRefuseShadowing refuses, before anything is loaded, if a DYLD_LIBRARY_PATH directory
// contains a file named macFileName: dyld would load that in place of the verified path.
func macRefuseShadowing(getenv func(string) string, exists func(string) bool) error {
	searchPath := getenv("DYLD_LIBRARY_PATH")
	for _, directory := range strings.Split(searchPath, ":") {
		if directory == "" {
			continue
		}
		candidate := strings.TrimRight(directory, "/") + "/" + macFileName
		if exists(candidate) {
			return untrusted("'%s' is on DYLD_LIBRARY_PATH and would be loaded in place of the verified HkdfGuard native library; refusing to load. Remove it from DYLD_LIBRARY_PATH.", candidate)
		}
	}
	return nil
}

// macVerifyLoadedImage requires that the file dyld reports having loaded (via dladdr on
// probeExport; "" if there is no such export or dyld can't say) is the one that was verified.
func macVerifyLoadedImage(expectedPath, loadedPath string) error {
	if loadedPath == "" {
		return untrusted("The library loaded for '%s' has no '%s' export, or dyld cannot say where it came from; it is not the HkdfGuard native library and has been unloaded.", expectedPath, probeExport)
	}
	if loadedPath != expectedPath {
		return untrusted("dyld loaded '%s' in place of the verified '%s' (DYLD_LIBRARY_PATH, most likely); it has been unloaded and the HkdfGuard native library was not loaded.", loadedPath, expectedPath)
	}
	return nil
}

// macVerifyLocation checks the file and every parent directory up to /: not a symbolic link,
// owned by one of trustedOwners, and not writable by anyone else.
func macVerifyLocation(path string, getStatus func(string) (fileStatus, error), trustedOwners []uint32) error {
	file, err := getStatus(path)
	if err != nil {
		return err
	}
	if file.typ != fileRegular {
		return untrusted("'%s' is not a regular file (it is a %s).", path, file.typ)
	}
	if err := macVerifyComponent(path, file, trustedOwners); err != nil {
		return err
	}

	for directory, ok := macParentOf(path); ok; directory, ok = macParentOf(directory) {
		status, err := getStatus(directory)
		if err != nil {
			return err
		}
		if status.typ != fileDirectory {
			return untrusted("'%s' is not a directory (it is a %s); the library is only loaded through a real path.", directory, status.typ)
		}
		if err := macVerifyComponent(directory, status, trustedOwners); err != nil {
			return err
		}
	}
	return nil
}

func macVerifyComponent(path string, status fileStatus, trustedOwners []uint32) error {
	// Root owns the system directories above every install (/, /Library, /Users).
	if status.uid != 0 && !slices.Contains(trustedOwners, status.uid) {
		owners := "root or the current user"
		if len(trustedOwners) == 1 {
			owners = "root"
		}
		return untrusted("'%s' is owned by uid %d; the HkdfGuard native library is only loaded from a location owned by %s.", path, status.uid, owners)
	}

	if status.perm&permOtherWrite != 0 {
		return untrusted("'%s' is writable by every user; the HkdfGuard native library is only loaded from a location only its owner can modify.", path)
	}

	if status.perm&permGroupWrite != 0 &&
		!(status.uid == 0 && slices.Contains(macAdministrativeGroups, status.gid) && slices.Contains(macSharedSystemDirectories, path)) {
		return untrusted("'%s' is writable by group %d; the HkdfGuard native library is only loaded from a location only its owner can modify (administrators may also write only to the system directories above an install: %s).",
			path, status.gid, strings.Join(macSharedSystemDirectories, ", "))
	}
	return nil
}

// macVerifySignature requires a valid code signature that satisfies macCodeRequirement.
// checkSignature returns 0 (errSecSuccess) when the signature is valid and satisfies the
// requirement, else the OSStatus.
func macVerifySignature(path string, checkSignature func(path, requirement string) int32) error {
	if status := checkSignature(path, macCodeRequirement); status != 0 {
		return untrusted("'%s' is not validly signed by the HkdfGuard team (%s); code signature check failed with OSStatus %d.", path, macTeamID, status)
	}
	return nil
}

// macParentOf returns path's parent ('/'-separated), and false above /.
func macParentOf(path string) (string, bool) {
	if path == "/" {
		return "", false
	}
	slash := strings.LastIndexByte(strings.TrimRight(path, "/"), '/')
	if slash <= 0 {
		return "/", true
	}
	return path[:slash], true
}
