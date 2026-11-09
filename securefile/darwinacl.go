package securefile

import "fmt"

// The macOS extended-ACL rules, kept free of system calls (and of a build constraint) so the tests
// run them on every platform. acl_darwin.go reads each entry's tag, flags, permissions and
// qualifier through libc and hands them here.
//
// A macOS extended ACL (chmod +a) is independent of the mode bits: an entry can let anyone write a
// file or directory whose mode shows no group or other write. So, unlike a Linux POSIX ACL, it is
// read for every component whatever the mode (see aclReadWhateverTheMode).

// macOS sys/acl.h values (Libc include/sys/acl.h; the same bits as xnu's KAUTH_VNODE_* and
// KAUTH_ACE_* in sys/kauth.h).
const (
	// acl_tag_t
	darwinACLExtendedAllow = 1 // ACL_EXTENDED_ALLOW
	darwinACLExtendedDeny  = 2 // ACL_EXTENDED_DENY

	// acl_perm_t
	darwinACLReadData           = 1 << 1  // ACL_READ_DATA, ACL_LIST_DIRECTORY
	darwinACLWriteData          = 1 << 2  // ACL_WRITE_DATA, ACL_ADD_FILE
	darwinACLExecute            = 1 << 3  // ACL_EXECUTE, ACL_SEARCH
	darwinACLDelete             = 1 << 4  // ACL_DELETE
	darwinACLAppendData         = 1 << 5  // ACL_APPEND_DATA, ACL_ADD_SUBDIRECTORY
	darwinACLDeleteChild        = 1 << 6  // ACL_DELETE_CHILD
	darwinACLReadAttributes     = 1 << 7  // ACL_READ_ATTRIBUTES
	darwinACLWriteAttributes    = 1 << 8  // ACL_WRITE_ATTRIBUTES
	darwinACLReadExtAttributes  = 1 << 9  // ACL_READ_EXTATTRIBUTES
	darwinACLWriteExtAttributes = 1 << 10 // ACL_WRITE_EXTATTRIBUTES
	darwinACLReadSecurity       = 1 << 11 // ACL_READ_SECURITY
	darwinACLWriteSecurity      = 1 << 12 // ACL_WRITE_SECURITY
	darwinACLChangeOwner        = 1 << 13 // ACL_CHANGE_OWNER

	// acl_flag_t, on an entry
	darwinACLEntryInherited        = 1 << 4 // ACL_ENTRY_INHERITED
	darwinACLEntryFileInherit      = 1 << 5 // ACL_ENTRY_FILE_INHERIT
	darwinACLEntryDirectoryInherit = 1 << 6 // ACL_ENTRY_DIRECTORY_INHERIT
	darwinACLEntryLimitInherit     = 1 << 7 // ACL_ENTRY_LIMIT_INHERIT
	darwinACLEntryOnlyInherit      = 1 << 8 // ACL_ENTRY_ONLY_INHERIT

	// membership.h id types (mbr_uuid_to_id)
	darwinIDTypeUID = 0 // ID_TYPE_UID
	darwinIDTypeGID = 1 // ID_TYPE_GID
	// darwinEveryoneGID is the gid macOS maps the "everyone" group's GUID to: every account, like the
	// mode's other bits.
	darwinEveryoneGID = 12

	// darwinIDTypeUnmapped marks an entry whose qualifier (a GUID) could not be read or mapped to a
	// uid or gid: it is refused if it would let its principal write.
	darwinIDTypeUnmapped = -1
)

// darwinACLWriteRights are the rights that let an entry's principal change what a file or a
// directory holds, or take control of it:
//
//   - WRITE_DATA (ADD_FILE on a directory) and APPEND_DATA (ADD_SUBDIRECTORY): change a file's
//     contents, or add an entry to a directory - a replacement key file, say.
//   - DELETE and DELETE_CHILD: remove the item, or any entry of a directory, so it can be replaced.
//   - WRITE_SECURITY: rewrite the ACL, and so grant itself any of the others.
//   - CHANGE_OWNER: take ownership, and so the right to change everything.
//
// WRITE_ATTRIBUTES and WRITE_EXTATTRIBUTES are not among them: they set the basic attributes
// (timestamps, BSD flags the owner may set) and extended attributes, neither of which changes a
// file's contents, mode, owner or ACL - the mode and owner need the owner or CHANGE_OWNER, the ACL
// WRITE_SECURITY. The read, execute and read-attribute rights grant no write at all.
const darwinACLWriteRights = darwinACLWriteData | darwinACLAppendData | darwinACLDelete | darwinACLDeleteChild |
	darwinACLWriteSecurity | darwinACLChangeOwner

// darwinACLEntry is one entry of a macOS extended ACL, as libc reports it: its tag (allow or deny),
// its flags, its permission bits, and the uid or gid its qualifier (a GUID) maps to.
type darwinACLEntry struct {
	tag         uint32
	flags       uint32
	permissions uint32
	// idType is darwinIDTypeUID, darwinIDTypeGID, darwinIDTypeUnmapped, or another membership.h
	// ID_TYPE_* mbr_uuid_to_id reported; id is the uid or gid.
	idType int32
	id     uint32
}

// darwinACLWriters returns the users and groups a macOS extended ACL's entries let write the item
// they're on, for requireTrusted to check like a Linux access ACL's named entries. An entry it
// can't evaluate is an error: what it grants can't be known.
//
//   - Deny entries are ignored: a deny can only take access away, so ignoring one can only refuse
//     more - as the Windows rules ignore deny ACEs.
//   - An allow entry carrying ACL_ENTRY_ONLY_INHERIT is skipped: it is only passed on to new
//     children, and grants nothing on the item itself (as Windows skips INHERIT_ONLY). An inherited
//     entry (ACL_ENTRY_INHERITED) applies like any other.
//   - An allow entry granting any of darwinACLWriteRights is a writer: its uid or gid, which must
//     map to a user or group. An entry letting "everyone" (gid 12) write is refused outright,
//     whatever the trust names, as an other-writable mode is: it is every account.
func darwinACLWriters(entries []darwinACLEntry) ([]aclWriter, error) {
	var writers []aclWriter
	for i, entry := range entries {
		switch entry.tag {
		case darwinACLExtendedDeny:
			continue
		case darwinACLExtendedAllow:
		default:
			return nil, fmt.Errorf("its access ACL's entry %d has tag %d, neither allow nor deny", i, entry.tag)
		}
		if entry.flags&darwinACLEntryOnlyInherit != 0 || entry.permissions&darwinACLWriteRights == 0 {
			continue
		}
		switch entry.idType {
		case darwinIDTypeUID:
			writers = append(writers, aclWriter{id: entry.id})
		case darwinIDTypeGID:
			if entry.id == darwinEveryoneGID {
				return nil, fmt.Errorf("its access ACL's entry %d lets everyone write, which is never trusted", i)
			}
			writers = append(writers, aclWriter{group: true, id: entry.id})
		case darwinIDTypeUnmapped:
			return nil, fmt.Errorf("its access ACL's entry %d lets a principal write that could not be mapped to a user or group", i)
		default:
			return nil, fmt.Errorf("its access ACL's entry %d lets a principal of id type %d write, neither a user nor a group", i, entry.idType)
		}
	}
	return writers, nil
}
