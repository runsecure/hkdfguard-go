//go:build darwin

package securefile

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// aclReadWhateverTheMode is true on macOS: an extended ACL is independent of the mode bits, so it
// is read for every component, whatever its mode.
const aclReadWhateverTheMode = true

// darwinACLTypeExtended is ACL_TYPE_EXTENDED, the only ACL type macOS has.
const darwinACLTypeExtended = 0x00000100

// darwinACLFirstEntry and darwinACLNextEntry are acl_get_entry's ACL_FIRST_ENTRY and ACL_NEXT_ENTRY.
const (
	darwinACLFirstEntry = 0
	darwinACLNextEntry  = -1
)

// darwinACLPermissions are the acl_perm_t bits read from each entry's permission set; anything
// else in it grants nothing darwinACLWriters looks at.
var darwinACLPermissions = [...]uint32{
	darwinACLReadData, darwinACLWriteData, darwinACLExecute, darwinACLDelete, darwinACLAppendData,
	darwinACLDeleteChild, darwinACLReadAttributes, darwinACLWriteAttributes, darwinACLReadExtAttributes,
	darwinACLWriteExtAttributes, darwinACLReadSecurity, darwinACLWriteSecurity, darwinACLChangeOwner,
}

// darwinACLFlags are the acl_flag_t bits read from each entry's flag set.
var darwinACLFlags = [...]uint32{
	darwinACLEntryInherited, darwinACLEntryFileInherit, darwinACLEntryDirectoryInherit,
	darwinACLEntryLimitInherit, darwinACLEntryOnlyInherit,
}

// accessACLWriters is the users and groups path's extended ACL lets write it (see
// darwinACLWriters), read without following a symbolic link; none when it has no ACL, or its
// filesystem has none. An entry that can't be read or evaluated refuses the location.
func accessACLWriters(path string) ([]aclWriter, error) {
	acl, err := aclGetLinkNP(path)
	if err != nil {
		switch {
		case errors.Is(err, unix.ENOENT), errors.Is(err, unix.ENOTSUP), errors.Is(err, unix.EOPNOTSUPP):
			return nil, nil // no extended ACL: the mode bits are the whole story
		case errors.Is(err, unix.EACCES):
			return nil, keyFileError(err, path, "This account may not read the access ACL of '%s' (EACCES).", path)
		default:
			return nil, keyFileError(err, path, "Could not read the access ACL of '%s' (%s).", path, errnoName(err))
		}
	}
	defer aclFree(acl)

	entries, err := readDarwinACL(acl)
	if err != nil {
		return nil, keyFileError(ErrUntrusted, path, "The location '%s' is not trusted: %s.", path, err)
	}
	writers, err := darwinACLWriters(entries)
	if err != nil {
		return nil, keyFileError(ErrUntrusted, path, "The location '%s' is not trusted: %s.", path, err)
	}
	return writers, nil
}

// readDarwinACL reads every entry of acl. acl_get_entry ends the list with EINVAL; any other
// failure is an error, never taken for the end of the list.
func readDarwinACL(acl uintptr) ([]darwinACLEntry, error) {
	var entries []darwinACLEntry
	for which := darwinACLFirstEntry; ; which = darwinACLNextEntry {
		entry, err := aclGetEntry(acl, which)
		if err != nil {
			if errors.Is(err, unix.EINVAL) {
				return entries, nil
			}
			return nil, describeACLFailure("acl_get_entry", len(entries), err)
		}
		read, err := readDarwinACLEntry(entry, len(entries))
		if err != nil {
			return nil, err
		}
		entries = append(entries, read)
	}
}

// readDarwinACLEntry reads one entry's tag, flags, permissions and - for an allow entry - the
// uid or gid its qualifier maps to; a qualifier that can't be read or mapped is reported as
// darwinIDTypeUnmapped, which darwinACLWriters refuses if the entry grants write.
func readDarwinACLEntry(entry uintptr, index int) (darwinACLEntry, error) {
	var result darwinACLEntry
	tag, err := aclGetTagType(entry)
	if err != nil {
		return result, describeACLFailure("acl_get_tag_type", index, err)
	}
	result.tag = tag
	if tag != darwinACLExtendedAllow {
		return result, nil // a deny entry is ignored, and another tag refused, whatever it holds
	}

	flagset, err := aclGetFlagsetNP(entry)
	if err != nil {
		return result, describeACLFailure("acl_get_flagset_np", index, err)
	}
	for _, flag := range darwinACLFlags {
		set, err := aclGetFlagNP(flagset, flag)
		if err != nil {
			return result, describeACLFailure("acl_get_flag_np", index, err)
		}
		if set {
			result.flags |= flag
		}
	}

	permset, err := aclGetPermset(entry)
	if err != nil {
		return result, describeACLFailure("acl_get_permset", index, err)
	}
	for _, permission := range darwinACLPermissions {
		set, err := aclGetPermNP(permset, permission)
		if err != nil {
			return result, describeACLFailure("acl_get_perm_np", index, err)
		}
		if set {
			result.permissions |= permission
		}
	}

	result.idType = darwinIDTypeUnmapped
	qualifier, err := aclGetQualifier(entry)
	if err != nil {
		return result, nil
	}
	defer aclFree(qualifier)
	if id, idType, ok := mbrUUIDToID(qualifier); ok {
		result.id, result.idType = id, idType
	}
	return result, nil
}

// describeACLFailure is a libc ACL call that failed reading entry index, for the refusal's message.
func describeACLFailure(call string, index int, err error) error {
	return fmt.Errorf("its access ACL's entry %d could not be read (%s: %s)", index, call, errnoName(err))
}

// The libc ACL calls, made the way golang.org/x/sys/unix calls libc on macOS: without cgo, through
// a trampoline (acl_darwin_*.s) that jumps to the function libSystem exports. Every unsafe.Pointer
// conversion is in the call expression, as the unsafe rules require.

// aclGetLinkNP is acl_get_link_np(path, ACL_TYPE_EXTENDED): path's own ACL, a symbolic link's
// never followed; NULL with ENOENT when it has none. The acl_t must be freed with aclFree.
func aclGetLinkNP(path string) (uintptr, error) {
	pathBytes, err := unix.BytePtrFromString(path)
	if err != nil {
		return 0, err
	}
	acl, _, errno := syscall_syscallPtr(libc_acl_get_link_np_trampoline_addr, uintptr(unsafe.Pointer(pathBytes)), darwinACLTypeExtended, 0)
	runtime.KeepAlive(pathBytes)
	if acl == 0 {
		return 0, errnoOrEINVAL(errno)
	}
	return acl, nil
}

// aclGetEntry is acl_get_entry: the entry which (ACL_FIRST_ENTRY or ACL_NEXT_ENTRY) names.
func aclGetEntry(acl uintptr, which int) (uintptr, error) {
	var entry uintptr
	result, _, errno := syscall_syscall(libc_acl_get_entry_trampoline_addr, acl, uintptr(which), uintptr(unsafe.Pointer(&entry)))
	runtime.KeepAlive(&entry)
	if int32(result) != 0 {
		return 0, errnoOrEINVAL(errno)
	}
	return entry, nil
}

// aclGetTagType is acl_get_tag_type: ACL_EXTENDED_ALLOW, ACL_EXTENDED_DENY or another acl_tag_t.
func aclGetTagType(entry uintptr) (uint32, error) {
	var tag uint32 // acl_tag_t, a C enum: an int
	result, _, errno := syscall_syscall(libc_acl_get_tag_type_trampoline_addr, entry, uintptr(unsafe.Pointer(&tag)), 0)
	runtime.KeepAlive(&tag)
	if int32(result) != 0 {
		return 0, errnoOrEINVAL(errno)
	}
	return tag, nil
}

// aclGetFlagsetNP is acl_get_flagset_np on an entry: its flag set, which points into the entry.
func aclGetFlagsetNP(entry uintptr) (uintptr, error) {
	var flagset uintptr
	result, _, errno := syscall_syscall(libc_acl_get_flagset_np_trampoline_addr, entry, uintptr(unsafe.Pointer(&flagset)), 0)
	runtime.KeepAlive(&flagset)
	if int32(result) != 0 {
		return 0, errnoOrEINVAL(errno)
	}
	return flagset, nil
}

// aclGetFlagNP is acl_get_flag_np: 1 if flag is set, 0 if not, -1 on an error.
func aclGetFlagNP(flagset uintptr, flag uint32) (bool, error) {
	return oneZeroOrError(syscall_syscall(libc_acl_get_flag_np_trampoline_addr, flagset, uintptr(flag), 0))
}

// aclGetPermset is acl_get_permset: the entry's permission set, which points into the entry.
func aclGetPermset(entry uintptr) (uintptr, error) {
	var permset uintptr
	result, _, errno := syscall_syscall(libc_acl_get_permset_trampoline_addr, entry, uintptr(unsafe.Pointer(&permset)), 0)
	runtime.KeepAlive(&permset)
	if int32(result) != 0 {
		return 0, errnoOrEINVAL(errno)
	}
	return permset, nil
}

// aclGetPermNP is acl_get_perm_np: 1 if permission is set, 0 if not, -1 on an error.
func aclGetPermNP(permset uintptr, permission uint32) (bool, error) {
	return oneZeroOrError(syscall_syscall(libc_acl_get_perm_np_trampoline_addr, permset, uintptr(permission), 0))
}

func oneZeroOrError(result, _ uintptr, errno unix.Errno) (bool, error) {
	switch int32(result) {
	case 1:
		return true, nil
	case 0:
		return false, nil
	default:
		return false, errnoOrEINVAL(errno)
	}
}

// aclGetQualifier is acl_get_qualifier on an extended entry: a copy of its guid_t (16 bytes), to
// be freed with aclFree; NULL on an error.
func aclGetQualifier(entry uintptr) (uintptr, error) {
	qualifier, _, errno := syscall_syscallPtr(libc_acl_get_qualifier_trampoline_addr, entry, 0, 0)
	if qualifier == 0 {
		return 0, errnoOrEINVAL(errno)
	}
	return qualifier, nil
}

// mbrUUIDToID is mbr_uuid_to_id: the uid or gid (with its ID_TYPE_*) a GUID maps to. It returns
// 0 on success or an errno value - not -1 - so ok is false on any other result. guid is C memory
// (acl_get_qualifier's copy), passed on as it is.
func mbrUUIDToID(guid uintptr) (id uint32, idType int32, ok bool) {
	var mapped uint32 // id_t
	var mappedType int32
	result, _, _ := syscall_syscall(libc_mbr_uuid_to_id_trampoline_addr, guid, uintptr(unsafe.Pointer(&mapped)), uintptr(unsafe.Pointer(&mappedType)))
	runtime.KeepAlive(&mapped)
	runtime.KeepAlive(&mappedType)
	if int32(result) != 0 {
		return 0, 0, false
	}
	return mapped, mappedType, true
}

// aclFree is acl_free, for an acl_t or a qualifier.
func aclFree(object uintptr) {
	_, _, _ = syscall_syscall(libc_acl_free_trampoline_addr, object, 0, 0)
}

// errnoOrEINVAL is errno, or EINVAL if a call reported failure without setting it - so a failure
// is never mistaken for success.
func errnoOrEINVAL(errno unix.Errno) error {
	if errno == 0 {
		return unix.EINVAL
	}
	return errno
}

var libc_acl_get_link_np_trampoline_addr uintptr

//go:cgo_import_dynamic libc_acl_get_link_np acl_get_link_np "/usr/lib/libSystem.B.dylib"

var libc_acl_get_entry_trampoline_addr uintptr

//go:cgo_import_dynamic libc_acl_get_entry acl_get_entry "/usr/lib/libSystem.B.dylib"

var libc_acl_get_tag_type_trampoline_addr uintptr

//go:cgo_import_dynamic libc_acl_get_tag_type acl_get_tag_type "/usr/lib/libSystem.B.dylib"

var libc_acl_get_flagset_np_trampoline_addr uintptr

//go:cgo_import_dynamic libc_acl_get_flagset_np acl_get_flagset_np "/usr/lib/libSystem.B.dylib"

var libc_acl_get_flag_np_trampoline_addr uintptr

//go:cgo_import_dynamic libc_acl_get_flag_np acl_get_flag_np "/usr/lib/libSystem.B.dylib"

var libc_acl_get_permset_trampoline_addr uintptr

//go:cgo_import_dynamic libc_acl_get_permset acl_get_permset "/usr/lib/libSystem.B.dylib"

var libc_acl_get_perm_np_trampoline_addr uintptr

//go:cgo_import_dynamic libc_acl_get_perm_np acl_get_perm_np "/usr/lib/libSystem.B.dylib"

var libc_acl_get_qualifier_trampoline_addr uintptr

//go:cgo_import_dynamic libc_acl_get_qualifier acl_get_qualifier "/usr/lib/libSystem.B.dylib"

var libc_acl_free_trampoline_addr uintptr

//go:cgo_import_dynamic libc_acl_free acl_free "/usr/lib/libSystem.B.dylib"

var libc_mbr_uuid_to_id_trampoline_addr uintptr

//go:cgo_import_dynamic libc_mbr_uuid_to_id mbr_uuid_to_id "/usr/lib/libSystem.B.dylib"

// Implemented in the runtime and syscall packages, as golang.org/x/sys/unix links them
// (syscall_darwin_libSystem.go). syscall_syscall reports errno when the call returns -1;
// syscall_syscallPtr, for a function that returns NULL on an error, when it returns 0.
func syscall_syscall(fn, a1, a2, a3 uintptr) (r1, r2 uintptr, err unix.Errno)
func syscall_syscallPtr(fn, a1, a2, a3 uintptr) (r1, r2 uintptr, err unix.Errno)

//go:linkname syscall_syscall syscall.syscall
//go:linkname syscall_syscallPtr syscall.syscallPtr
