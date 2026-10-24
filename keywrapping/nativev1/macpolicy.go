package nativev1

import (
	"encoding/binary"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// The macOS loader's decisions, kept free of system calls (they are passed in) so they can be
// checked against simulated filesystems on any platform. The loader (kms_darwin.go) loads the
// library from one of its two install locations and nowhere else:
//
//  1. Location. The system install, macSystemDirectory, is used whenever it exists; the per-user
//     install, ~/.hkdfguard/v1, only when there is no system install. The home folder comes from
//     the account database (getpwuid), never from $HOME, so whoever sets the process's
//     environment can't choose where the library is loaded from. Anything running as the user
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
//     Its version - LC_ID_DYLIB's current_version, which the signature covers - must be at
//     least macMinimumLibraryVersion, so an older genuine release can't be planted in its place.
//  4. What dyld loaded. dlopen of an absolute path first looks for its leaf name in every
//     DYLD_LIBRARY_PATH directory, so the loader refuses before dlopen if one holds a
//     macFileName, and after dlopen asks dyld (dladdr) which file it mapped; anything but the
//     verified path is unloaded and refused.

const (
	macFileName               = "libhkdfguard.dylib"
	macSystemDirectory        = "/Library/Application Support/HkdfGuard/v1"
	macUserDirectoryUnderHome = ".hkdfguard/v1"
	macSystemPath             = macSystemDirectory + "/" + macFileName

	// macTeamID is the Apple team ID the library must be signed by: the certificate's subject OU
	// (and codesign's TeamIdentifier).
	macTeamID = "MFW3T8R8J3"

	// macCodeRequirement matches the release build's own designated requirement: this library's
	// identifier, signed with a Developer ID Application certificate (not Apple Development)
	// issued to the HkdfGuard team. So a development build, or any other binary the team signs
	// (such as the hkdfguard tool), is refused.
	macCodeRequirement = `identifier "libhkdfguard" and anchor apple generic` +
		` and certificate 1[field.1.2.840.113635.100.6.2.6] exists` + // Developer ID CA
		` and certificate leaf[field.1.2.840.113635.100.6.1.13] exists` + // Developer ID Application leaf
		` and certificate leaf[subject.OU] = "` + macTeamID + `"`

	// macMinimumMajorVersion is the library's own minimum (its LC_BUILD_VERSION minos).
	macMinimumMajorVersion = 13

	// macMinimumLibraryVersion is the oldest native library release this package loads, in
	// Mach-O's packed form (major<<16 | minor<<8 | patch): 0.9.0. A release that fixes a security
	// problem in the library raises it, so an older, genuinely signed copy can't be put back in
	// its place.
	macMinimumLibraryVersion uint32 = 0<<16 | 9<<8 | 0

	// macVersionReadLimit bounds how much of the file is read to find its version.
	macVersionReadLimit = 64 * 1024

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

// macRefusedDyldVariables are the dyld variables whose presence alone refuses the load: each makes
// dyld inject code into this process, or load another file in place of a library it names -
// including the frameworks the HkdfGuard native library calls with every DEK. None is set on a
// production host.
var macRefusedDyldVariables = []string{
	"DYLD_INSERT_LIBRARIES", "DYLD_FRAMEWORK_PATH", "DYLD_VERSIONED_LIBRARY_PATH", "DYLD_VERSIONED_FRAMEWORK_PATH", "DYLD_IMAGE_SUFFIX",
}

// macRefuseShadowing refuses, before anything is loaded, if one of macRefusedDyldVariables is set,
// or a DYLD_LIBRARY_PATH directory contains a file named macFileName: dyld would load that in place
// of the verified path.
//
// A guard against a misconfigured environment, not against whoever controls it: dyld acts on these
// variables when the process starts, so code they injected has already run - and can hide - by the
// time this looks. Running the host with the Hardened Runtime, which makes dyld ignore them, is what
// keeps that code out.
func macRefuseShadowing(getenv func(string) string, exists func(string) bool) error {
	for _, name := range macRefusedDyldVariables {
		if getenv(name) != "" {
			return untrusted("%s is set, so dyld may inject code into this process or substitute a library the HkdfGuard native library uses; refusing to load it. Unset %s.", name, name)
		}
	}

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

// Mach-O constants the version check needs.
const (
	machoMagic64   uint32 = 0xfeedfacf // MH_MAGIC_64, little-endian on arm64
	machoFatMagic  uint32 = 0xcafebabe // FAT_MAGIC, big-endian
	machoFatMagic6 uint32 = 0xcafebabf // FAT_MAGIC_64, big-endian
	machoCPUARM64  uint32 = 0x0100000c // CPU_TYPE_ARM64
	machoLCIDDylib uint32 = 0xd        // LC_ID_DYLIB
)

// macFormatVersion renders a packed Mach-O version as major.minor.patch.
func macFormatVersion(v uint32) string {
	return fmt.Sprintf("%d.%d.%d", v>>16, (v>>8)&0xff, v&0xff)
}

// macDylibCurrentVersion reads LC_ID_DYLIB's current_version from the start of a Mach-O file:
// a thin arm64 image, or the arm64 slice of a fat one. data is at most the first
// macVersionReadLimit bytes; anything malformed, truncated, or not arm64 is an error.
func macDylibCurrentVersion(data []byte) (uint32, error) {
	if len(data) < 4 {
		return 0, fmt.Errorf("too short to be a Mach-O file")
	}
	switch magic := binary.BigEndian.Uint32(data); magic {
	case machoFatMagic, machoFatMagic6:
		return macFatArm64Version(data, magic == machoFatMagic6)
	}
	return macThinArm64Version(data)
}

func macFatArm64Version(data []byte, wide bool) (uint32, error) {
	if len(data) < 8 {
		return 0, fmt.Errorf("truncated fat header")
	}
	count := binary.BigEndian.Uint32(data[4:])
	entrySize := uint64(20) // fat_arch: cputype, cpusubtype, offset, size, align
	if wide {
		entrySize = 32 // fat_arch_64: cputype, cpusubtype, offset(8), size(8), align, reserved
	}
	if uint64(count)*entrySize+8 > uint64(len(data)) {
		return 0, fmt.Errorf("fat header lists %d architectures, more than were read", count)
	}
	for i := uint64(0); i < uint64(count); i++ {
		entry := data[8+i*entrySize:]
		if binary.BigEndian.Uint32(entry) != machoCPUARM64 {
			continue
		}
		var offset uint64
		if wide {
			offset = binary.BigEndian.Uint64(entry[8:])
		} else {
			offset = uint64(binary.BigEndian.Uint32(entry[8:]))
		}
		if offset >= uint64(len(data)) {
			return 0, fmt.Errorf("the arm64 slice starts at %d, beyond the %d bytes read", offset, len(data))
		}
		return macThinArm64Version(data[offset:])
	}
	return 0, fmt.Errorf("no arm64 slice")
}

func macThinArm64Version(data []byte) (uint32, error) {
	const headerSize = 32 // mach_header_64
	if len(data) < headerSize {
		return 0, fmt.Errorf("truncated Mach-O header")
	}
	le := binary.LittleEndian
	if le.Uint32(data) != machoMagic64 {
		return 0, fmt.Errorf("not a 64-bit Mach-O file")
	}
	if le.Uint32(data[4:]) != machoCPUARM64 {
		return 0, fmt.Errorf("not an arm64 image")
	}
	ncmds := le.Uint32(data[16:])
	sizeofcmds := uint64(le.Uint32(data[20:]))
	end := headerSize + sizeofcmds
	if end > uint64(len(data)) {
		return 0, fmt.Errorf("load commands run past the bytes read")
	}
	at := uint64(headerSize)
	for i := uint32(0); i < ncmds; i++ {
		if at+8 > end {
			return 0, fmt.Errorf("load command %d runs past the load commands", i)
		}
		cmd := le.Uint32(data[at:])
		size := uint64(le.Uint32(data[at+4:]))
		if size < 8 || size%8 != 0 || at+size > end {
			return 0, fmt.Errorf("load command %d has an invalid size %d", i, size)
		}
		if cmd == machoLCIDDylib {
			if size < 24 { // cmd, cmdsize, name offset, timestamp, current_version, compatibility_version
				return 0, fmt.Errorf("LC_ID_DYLIB is too short")
			}
			return le.Uint32(data[at+16:]), nil
		}
		at += size
	}
	return 0, fmt.Errorf("no LC_ID_DYLIB load command")
}

// macRequireMinimumVersion refuses a library whose version, read from data (the start of the
// verified file at path), is missing, unreadable or below macMinimumLibraryVersion.
func macRequireMinimumVersion(path string, data []byte) error {
	version, err := macDylibCurrentVersion(data)
	if err != nil {
		return untrusted("Could not read the version of the HkdfGuard native library '%s' (%v); refusing to load it.", path, err)
	}
	if version < macMinimumLibraryVersion {
		return untrusted("'%s' is HkdfGuard native library version %s, older than the minimum this package accepts (%s); install a current release.",
			path, macFormatVersion(version), macFormatVersion(macMinimumLibraryVersion))
	}
	return nil
}

// macHomeFromAccount is the per-user install's base: the home folder the account database gives
// this process's effective user, or "" - no per-user install - if the lookup failed or gave
// anything but an absolute path.
func macHomeFromAccount(home string, ok bool) string {
	if !ok || !strings.HasPrefix(home, "/") {
		return ""
	}
	return home
}
