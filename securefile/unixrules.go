package securefile

import (
	"fmt"
	"io/fs"
	"strings"
)

// The Linux and macOS key-file location rules, kept free of system calls: they take lstat and
// readlink as arguments, so the tests run them against simulated filesystems on every platform.
// read_unix.go wires them to the real calls.

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
// group only if that is a KeyFileTrust group. A symbolic link is followed only if a trusted user
// owns it, and its target is then checked in turn - so macOS's root-owned /etc to private/etc
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
			return "", keyFileError(fs.ErrNotExist, path, "Key file '%s' runs through '%s', which is not a directory.", path, resolved)
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
			return "", keyFileError(fs.ErrNotExist, path, "Key file '%s' was not found ('%s' does not exist).", path, candidate)
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
	return nil
}

// untrustedUnix is the refusal of a key file whose location isn't trusted.
func untrustedUnix(path, format string, args ...any) *KeyFileError {
	return keyFileError(ErrUntrusted, path,
		"Key file '%s' is not trusted: %s. Keep key files where only root (or a trusted deployer, see KeyFileTrust) can write, all the way up from /.",
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
