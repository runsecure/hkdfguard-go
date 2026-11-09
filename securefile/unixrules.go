package securefile

import (
	"encoding/binary"
	"fmt"
	"io/fs"
	"strings"
)

// The Linux and macOS location rules for a key file - or any file ReadTrustedFile reads - kept free
// of system calls: they take lstat and readlink as arguments, so the tests run them against
// simulated filesystems on every platform. read_unix.go wires them to the real calls.

// unixFileType is what kind of file lstat reports.
type unixFileType int

const (
	unixOther unixFileType = iota
	unixRegularFile
	unixDirectory
	unixSymbolicLink
)

func (t unixFileType) String() string {
	switch t {
	case unixRegularFile:
		return "regular file"
	case unixDirectory:
		return "directory"
	case unixSymbolicLink:
		return "symbolic link"
	default:
		return "other"
	}
}

// unixFileStatus is what lstat reports about one path: who owns it, its permissions, and its type.
type unixFileStatus struct {
	ownerID uint32
	groupID uint32
	// mode holds the permission bits of st_mode: the low twelve (set-id, sticky, and read, write
	// and execute for owner, group and others).
	mode uint32
	// fileType is what kind of file it is - a symbolic link is reported as such, never followed.
	fileType unixFileType
	// aclWriters is every named user and group its ACL lets write it. On Linux that is a POSIX
	// access ACL, read only when the group-write bit is set: with an ACL that bit is the ACL's
	// mask, which caps every named entry, so when it is clear no named entry can write and nothing
	// needs reading. On macOS it is an extended ACL (darwinACLWriters), which is independent of the
	// mode bits and so is read whatever the mode.
	aclWriters []aclWriter
}

// aclWriter is a user or group an ACL entry lets write: a named entry of a POSIX access ACL
// (Linux), or an allow entry of an extended ACL (macOS).
type aclWriter struct {
	group bool // a group (ACL_GROUP; a GID qualifier on macOS), not a user (ACL_USER; a UID)
	id    uint32
}

// POSIX ACL extended-attribute layout (system.posix_acl_access): a little-endian 4-byte version,
// then 8-byte entries of tag (2 bytes), permissions (2) and id (4).
const (
	posixACLVersion    = 2
	posixACLHeaderSize = 4
	posixACLEntrySize  = 8
	posixACLUser       = 0x02 // ACL_USER: a named user
	posixACLGroup      = 0x08 // ACL_GROUP: a named group
	posixACLWrite      = 0x02 // ACL_WRITE
)

// parsePOSIXAccessACL returns the named user and group entries of a system.posix_acl_access value
// that grant write; the owner, owning group, mask and other entries are what st_mode already shows.
// A value that isn't a well-formed version-2 ACL is an error: what it grants can't be known.
func parsePOSIXAccessACL(value []byte) ([]aclWriter, error) {
	if len(value) < posixACLHeaderSize || (len(value)-posixACLHeaderSize)%posixACLEntrySize != 0 {
		return nil, fmt.Errorf("an access ACL of %d bytes is not a whole number of entries", len(value))
	}
	if version := binary.LittleEndian.Uint32(value); version != posixACLVersion {
		return nil, fmt.Errorf("an access ACL of version %d, not %d", version, posixACLVersion)
	}
	var writers []aclWriter
	for entry := value[posixACLHeaderSize:]; len(entry) > 0; entry = entry[posixACLEntrySize:] {
		tag := binary.LittleEndian.Uint16(entry)
		perm := binary.LittleEndian.Uint16(entry[2:])
		id := binary.LittleEndian.Uint32(entry[4:])
		if perm&posixACLWrite != 0 && (tag == posixACLUser || tag == posixACLGroup) {
			writers = append(writers, aclWriter{group: tag == posixACLGroup, id: id})
		}
	}
	return writers, nil
}

const (
	// groupWrite is S_IWGRP: writable by the file's group.
	groupWrite = 0o020
	// otherWrite is S_IWOTH: writable by every other user.
	otherWrite = 0o002
	// maxSymbolicLinks is the kernel's own limit on symbolic links followed in one lookup.
	maxSymbolicLinks = 40
)

// unixStatusFunc is lstat: the status of a path, found false if nothing is there (ENOENT or
// ENOTDIR), or an error (a *KeyFileError) when it can't be examined.
type unixStatusFunc func(path string) (status unixFileStatus, found bool, err error)

// unixReadLinkFunc is readlink: a symbolic link's stored target, ok false if it can't be read as
// one, or an error (a *KeyFileError) when this account may not read it.
type unixReadLinkFunc func(path string) (target string, ok bool, err error)

// resolveTrusted decides whether a key file's path on Linux or macOS can be trusted: it resolves
// the path the way the kernel would, from "/", checking everything it passes through, and returns
// the resolved path, which contains no symbolic links. Every directory and the file itself must be
// owned by root or a KeyFileTrust user, must not be writable by others, and may be writable by its
// group only if that is a KeyFileTrust group. On Linux, a group-writable one may also carry a POSIX
// access ACL only if every named user and group it lets write is trusted too (the group-write bit is
// then the ACL's mask, so a write grant there would otherwise go unseen). On macOS, any of them may
// carry an extended ACL (chmod +a) only if every user and group an allow entry lets write is
// trusted too: "everyone" is gid 12, so "everyone allow write" is refused unless that group is
// listed. A symbolic link is followed only if a trusted user owns it, and its target is then checked in turn - so macOS's root-owned /etc to private/etc
// works, and a link anyone else made doesn't. Nothing under /tmp, /var/tmp or another
// world-writable directory passes, sticky or not.
//
// The path is checked before it is opened, not through the opened descriptor. That is enough:
// nobody untrusted can write to any directory on the resolved path, or to the file, so nobody
// untrusted can change what it resolves to between the check and the open.
//
// It returns a *KeyFileError unwrapping to fs.ErrNotExist when nothing is at the path or a
// directory on it is missing, and to ErrUntrusted when a component is not trusted or the path isn't
// a regular file; an error wrapping fs.ErrInvalid when path is not absolute.
func resolveTrusted(path string, trust KeyFileTrust, getStatus unixStatusFunc, readLink unixReadLinkFunc) (string, error) {
	if !strings.HasPrefix(path, "/") {
		return "", fmt.Errorf("securefile: '%s' is not an absolute path: %w", path, fs.ErrInvalid)
	}

	root, found, err := getStatus("/")
	if err != nil {
		return "", err
	}
	if !found {
		return "", keyFileError(ErrUntrusted, path, "'/' could not be examined.")
	}
	if err := requireTrusted("/", root, trust, path); err != nil {
		return "", err
	}

	// A stack of the components still to resolve, the next one last.
	var pending []string
	pending = pushComponents(pending, path)
	resolved := "/"
	resolvedType := unixDirectory
	linksFollowed := 0

	for len(pending) > 0 {
		name := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if name == "" || name == "." {
			continue
		}

		if resolvedType != unixDirectory {
			return "", keyFileError(fs.ErrNotExist, path, "'%s' runs through '%s', which is not a directory.", path, resolved)
		}

		if name == ".." {
			// resolved never contains a symbolic link, so its parent is its lexical parent.
			resolved = parentOf(resolved)
			continue
		}

		candidate := "/" + name
		if resolved != "/" {
			candidate = resolved + "/" + name
		}
		status, found, err := getStatus(candidate)
		if err != nil {
			return "", err
		}
		if !found {
			return "", keyFileError(fs.ErrNotExist, path, "'%s' was not found ('%s' does not exist).", path, candidate)
		}

		if status.fileType == unixSymbolicLink {
			if !trust.isTrustedUser(status.ownerID) {
				return "", untrustedUnix(path, "'%s' is a symbolic link owned by uid %d, and only links owned by root or a trusted user are followed",
					candidate, status.ownerID)
			}
			linksFollowed++
			if linksFollowed > maxSymbolicLinks {
				return "", untrustedUnix(path, "it follows more than %d symbolic links", maxSymbolicLinks)
			}

			target, ok, err := readLink(candidate)
			if err != nil {
				return "", err
			}
			if !ok {
				return "", untrustedUnix(path, "'%s' could not be read as a symbolic link", candidate)
			}
			if strings.HasPrefix(target, "/") {
				resolved = "/"
			}
			pending = pushComponents(pending, target)
			continue
		}

		if err := requireTrusted(candidate, status, trust, path); err != nil {
			return "", err
		}
		resolved = candidate
		resolvedType = status.fileType
	}

	if resolvedType != unixRegularFile {
		return "", untrustedUnix(path, "it resolves to '%s', which is not a regular file", resolved)
	}
	return resolved, nil
}

func requireTrusted(candidate string, status unixFileStatus, trust KeyFileTrust, path string) error {
	if !trust.isTrustedUser(status.ownerID) {
		return untrustedUnix(path, "'%s' is owned by uid %d, not root or a trusted user", candidate, status.ownerID)
	}
	if status.mode&otherWrite != 0 {
		return untrustedUnix(path, "'%s' is writable by every user", candidate)
	}
	if status.mode&groupWrite != 0 && !trust.isTrustedGroup(status.groupID) {
		return untrustedUnix(path, "'%s' is writable by group %d, which is not a trusted group", candidate, status.groupID)
	}
	// An ACL entry can grant write that the owner and group alone don't show (on Linux, a named
	// entry under a group-write mask; on macOS, an extended ACL's allow entry): each must be
	// trusted too.
	for _, writer := range status.aclWriters {
		if writer.group && !trust.isTrustedGroup(writer.id) {
			return untrustedUnix(path, "its access ACL lets group %d write '%s', and that is not a trusted group", writer.id, candidate)
		}
		if !writer.group && !trust.isTrustedUser(writer.id) {
			return untrustedUnix(path, "its access ACL lets uid %d write '%s', and that is not root or a trusted user", writer.id, candidate)
		}
	}
	return nil
}

// untrustedUnix is the refusal of a file - a key file, or one ReadTrustedFile reads - whose location
// isn't trusted.
func untrustedUnix(path, format string, args ...any) *KeyFileError {
	return keyFileError(ErrUntrusted, path,
		"'%s' is not trusted: %s. Keep it where only root (or a trusted deployer, see KeyFileTrust) can write, all the way up from /.",
		path, fmt.Sprintf(format, args...))
}

// pushComponents pushes path's components onto the stack, the first one last. Empty components
// (from "//" or a trailing "/") are kept, as .NET's Split keeps them, and skipped like ".".
func pushComponents(pending []string, path string) []string {
	components := strings.Split(path, "/")
	for i := len(components) - 1; i >= 0; i-- {
		pending = append(pending, components[i])
	}
	return pending
}

// parentOf is the lexical parent of an absolute path with no symbolic links; "/" is its own parent.
func parentOf(path string) string {
	slash := strings.LastIndexByte(path, '/')
	if slash <= 0 {
		return "/"
	}
	return path[:slash]
}
