package securefile

import (
	"fmt"
	"strings"
	"testing"
)

// The macOS extended-ACL rules, checked on every platform. acl_darwin_test.go runs them against a
// real ACL (chmod +a) on a Mac.

const gidEveryone = 12 // macOS's "everyone" group, which an everyone entry's GUID maps to

func allowUser(uid uint32, permissions uint32) darwinACLEntry {
	return darwinACLEntry{tag: darwinACLExtendedAllow, permissions: permissions, idType: darwinIDTypeUID, id: uid}
}

func allowGroup(gid uint32, permissions uint32) darwinACLEntry {
	return darwinACLEntry{tag: darwinACLExtendedAllow, permissions: permissions, idType: darwinIDTypeGID, id: gid}
}

func requireDarwinWriters(t *testing.T, entries []darwinACLEntry, want ...aclWriter) {
	t.Helper()
	got, err := darwinACLWriters(entries)
	if err != nil {
		t.Fatalf("darwinACLWriters: %v", err)
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("writers = %v, want %v", got, want)
	}
}

func requireDarwinRefusal(t *testing.T, entries []darwinACLEntry, contains string) {
	t.Helper()
	got, err := darwinACLWriters(entries)
	if err == nil {
		t.Fatalf("darwinACLWriters = %v, nil; want an error", got)
	}
	if !strings.Contains(err.Error(), contains) {
		t.Fatalf("%q lacks %q", err, contains)
	}
}

func TestDarwinACL_NoEntriesNoWriters(t *testing.T) {
	requireDarwinWriters(t, nil)
}

func TestDarwinACL_EachGuardedRightMakesAWriter(t *testing.T) {
	for name, right := range map[string]uint32{
		"write_data/add_file":             darwinACLWriteData,
		"append_data/add_subdirectory":    darwinACLAppendData,
		"delete":                          darwinACLDelete,
		"delete_child":                    darwinACLDeleteChild,
		"writesecurity (rewrite the ACL)": darwinACLWriteSecurity,
		"chown":                           darwinACLChangeOwner,
	} {
		t.Run(name, func(t *testing.T) {
			requireDarwinWriters(t, []darwinACLEntry{allowUser(uidApp, right)}, aclWriter{id: uidApp})
			requireDarwinWriters(t, []darwinACLEntry{allowGroup(3003, right|darwinACLReadData)}, aclWriter{group: true, id: 3003})
		})
	}
}

func TestDarwinACL_ReadExecuteAndAttributeRightsAreNotWrite(t *testing.T) {
	for name, right := range map[string]uint32{
		"read_data":         darwinACLReadData,
		"execute":           darwinACLExecute,
		"readattr":          darwinACLReadAttributes,
		"writeattr":         darwinACLWriteAttributes,
		"readextattr":       darwinACLReadExtAttributes,
		"writeextattr":      darwinACLWriteExtAttributes,
		"readsecurity":      darwinACLReadSecurity,
		"synchronize (bit)": 1 << 20,
		"all of them": darwinACLReadData | darwinACLExecute | darwinACLReadAttributes | darwinACLWriteAttributes |
			darwinACLReadExtAttributes | darwinACLWriteExtAttributes | darwinACLReadSecurity,
	} {
		t.Run(name, func(t *testing.T) {
			requireDarwinWriters(t, []darwinACLEntry{allowUser(uidApp, right), allowGroup(gidEveryone, right)})
		})
	}
}

func TestDarwinACL_IgnoreDenyEntries(t *testing.T) {
	deny := darwinACLEntry{tag: darwinACLExtendedDeny, permissions: darwinACLWriteRights, idType: darwinIDTypeGID, id: gidEveryone}
	requireDarwinWriters(t, []darwinACLEntry{deny})
	// Nor does a deny take away a write another entry allows: ignoring it can only refuse more.
	requireDarwinWriters(t, []darwinACLEntry{deny, allowGroup(gidDeployers, darwinACLWriteData)}, aclWriter{group: true, id: gidDeployers})
	// A deny's qualifier doesn't matter, even one that couldn't be mapped.
	requireDarwinWriters(t, []darwinACLEntry{{tag: darwinACLExtendedDeny, permissions: darwinACLWriteData, idType: darwinIDTypeUnmapped}})
}

func TestDarwinACL_SkipOnlyInheritEntries_ButApplyInheritedOnes(t *testing.T) {
	onlyInherit := allowGroup(gidEveryone, darwinACLWriteRights)
	onlyInherit.flags = darwinACLEntryOnlyInherit | darwinACLEntryFileInherit | darwinACLEntryDirectoryInherit
	requireDarwinWriters(t, []darwinACLEntry{onlyInherit})

	inherited := allowUser(uidApp, darwinACLDeleteChild)
	inherited.flags = darwinACLEntryInherited | darwinACLEntryFileInherit | darwinACLEntryDirectoryInherit | darwinACLEntryLimitInherit
	requireDarwinWriters(t, []darwinACLEntry{inherited}, aclWriter{id: uidApp})

	inheritable := allowUser(uidApp, darwinACLWriteData)
	inheritable.flags = darwinACLEntryFileInherit | darwinACLEntryDirectoryInherit // applies here, and is passed on
	requireDarwinWriters(t, []darwinACLEntry{inheritable}, aclWriter{id: uidApp})
}

func TestDarwinACL_RefuseAnEntryWithAnUnknownTag(t *testing.T) {
	for _, tag := range []uint32{0, 3, 0xFFFFFFFF} {
		requireDarwinRefusal(t, []darwinACLEntry{{tag: tag, permissions: darwinACLReadData, idType: darwinIDTypeUID}}, fmt.Sprintf("tag %d", tag))
	}
	// Even after entries it could evaluate.
	requireDarwinRefusal(t, []darwinACLEntry{allowUser(uidRoot, darwinACLWriteData), {tag: 7}}, "entry 1 has tag 7")
}

func TestDarwinACL_RefuseAWriterThatIsNeitherAUserNorAGroup(t *testing.T) {
	requireDarwinRefusal(t, []darwinACLEntry{{tag: darwinACLExtendedAllow, permissions: darwinACLWriteData, idType: darwinIDTypeUnmapped}},
		"could not be mapped to a user or group")
	requireDarwinRefusal(t, []darwinACLEntry{{tag: darwinACLExtendedAllow, permissions: darwinACLWriteSecurity, idType: 6, id: 1}}, "id type 6")
	// An unmapped principal that may only read is no writer.
	requireDarwinWriters(t, []darwinACLEntry{{tag: darwinACLExtendedAllow, permissions: darwinACLReadData, idType: darwinIDTypeUnmapped}})
	// Nor is one on an entry only passed on to children.
	requireDarwinWriters(t, []darwinACLEntry{{tag: darwinACLExtendedAllow, flags: darwinACLEntryOnlyInherit, permissions: darwinACLWriteData, idType: darwinIDTypeUnmapped}})
}

func TestDarwinACL_ConstantsMatchSysACLH(t *testing.T) {
	// Libc include/sys/acl.h (the same bits as xnu bsd/sys/kauth.h) and Libinfo membership.h.
	for _, c := range []struct {
		name      string
		got, want uint32
	}{
		{"ACL_READ_DATA", darwinACLReadData, 1 << 1}, {"ACL_WRITE_DATA", darwinACLWriteData, 1 << 2},
		{"ACL_EXECUTE", darwinACLExecute, 1 << 3}, {"ACL_DELETE", darwinACLDelete, 1 << 4},
		{"ACL_APPEND_DATA", darwinACLAppendData, 1 << 5}, {"ACL_DELETE_CHILD", darwinACLDeleteChild, 1 << 6},
		{"ACL_READ_ATTRIBUTES", darwinACLReadAttributes, 1 << 7}, {"ACL_WRITE_ATTRIBUTES", darwinACLWriteAttributes, 1 << 8},
		{"ACL_READ_EXTATTRIBUTES", darwinACLReadExtAttributes, 1 << 9}, {"ACL_WRITE_EXTATTRIBUTES", darwinACLWriteExtAttributes, 1 << 10},
		{"ACL_READ_SECURITY", darwinACLReadSecurity, 1 << 11}, {"ACL_WRITE_SECURITY", darwinACLWriteSecurity, 1 << 12},
		{"ACL_CHANGE_OWNER", darwinACLChangeOwner, 1 << 13},
		{"ACL_ENTRY_INHERITED", darwinACLEntryInherited, 1 << 4}, {"ACL_ENTRY_FILE_INHERIT", darwinACLEntryFileInherit, 1 << 5},
		{"ACL_ENTRY_DIRECTORY_INHERIT", darwinACLEntryDirectoryInherit, 1 << 6},
		{"ACL_ENTRY_LIMIT_INHERIT", darwinACLEntryLimitInherit, 1 << 7}, {"ACL_ENTRY_ONLY_INHERIT", darwinACLEntryOnlyInherit, 1 << 8},
	} {
		if c.got != c.want {
			t.Errorf("%s = %#x, want %#x", c.name, c.got, c.want)
		}
	}
	if darwinACLExtendedAllow != 1 || darwinACLExtendedDeny != 2 || darwinIDTypeUID != 0 || darwinIDTypeGID != 1 {
		t.Error("an acl_tag_t or ID_TYPE_* value is wrong")
	}
}

// The writers, checked by the same rules as a Linux access ACL's named entries - but on items whose
// mode shows no group or other write, as a macOS extended ACL can be.

// An everyone entry is refused before any trust is consulted - as an other-writable mode is on
// Linux, whatever the trust names: everyone is every account.
func TestDarwinACL_RefuseEveryoneAllowWrite_WhateverTheTrust(t *testing.T) {
	for _, rights := range []uint32{darwinACLWriteData | darwinACLAppendData, darwinACLDeleteChild, darwinACLWriteSecurity, darwinACLChangeOwner} {
		requireDarwinRefusal(t, []darwinACLEntry{allowGroup(gidEveryone, rights)}, "lets everyone write")
	}
	// Inherited from a parent, it still applies to the item.
	inherited := allowGroup(gidEveryone, darwinACLWriteData)
	inherited.flags = darwinACLEntryInherited
	requireDarwinRefusal(t, []darwinACLEntry{inherited}, "lets everyone write")
	// Reading is still fine.
	requireDarwinWriters(t, []darwinACLEntry{allowGroup(gidEveryone, darwinACLReadData|darwinACLExecute)})
}

func TestDarwinACL_RefuseAnUntrustedUserAllowedToRewriteTheACL(t *testing.T) {
	writers, err := darwinACLWriters([]darwinACLEntry{allowUser(uidApp, darwinACLWriteSecurity|darwinACLReadData)})
	if err != nil {
		t.Fatal(err)
	}
	fs := standardFileSystem().file(unixKeyFile).withACL("/etc", writers...)
	requireRefusedWith(t, fs, unixKeyFile, deployerTrust, ErrUntrusted, "access ACL", "uid 1002", "'/etc'", "not root or a trusted user")
}

func TestDarwinACL_AcceptTrustedUsersAndGroups(t *testing.T) {
	writers, err := darwinACLWriters([]darwinACLEntry{
		allowUser(uidRoot, darwinACLWriteRights),
		allowUser(uidDeployer, darwinACLWriteData|darwinACLDeleteChild),
		allowGroup(gidDeployers, darwinACLAppendData),
		allowGroup(gidEveryone, darwinACLReadData|darwinACLExecute), // everyone may read
		{tag: darwinACLExtendedDeny, permissions: darwinACLDelete, idType: darwinIDTypeGID, id: gidEveryone},
	})
	if err != nil {
		t.Fatal(err)
	}
	fs := standardFileSystem().file(unixKeyFile, owned{owner: uidDeployer, group: uidDeployer}).
		withACL("/etc/hkdfguard/keys", writers...).withACL(unixKeyFile, writers...)
	requireResolved(t, fs, unixKeyFile, unixKeyFile, deployerTrust)
	// The deployer and its group are trusted only when the trust names them.
	requireRefusedWith(t, fs, unixKeyFile, AdministratorsOnly(), ErrUntrusted)
}
