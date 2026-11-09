//go:build linux

package securefile

import (
	"errors"

	"golang.org/x/sys/unix"
)

// posixACLAccessAttribute is the extended attribute holding a file's POSIX access ACL.
const posixACLAccessAttribute = "system.posix_acl_access"

// aclReadWhateverTheMode is false on Linux: the access ACL is read only when the group-write bit
// is set, because with an ACL that bit is its mask, which caps every named entry.
const aclReadWhateverTheMode = false

// accessACLWriters is the named users and groups path's POSIX access ACL lets write it, read
// without following a symbolic link; none when it has no ACL, or its filesystem has none.
func accessACLWriters(path string) ([]aclWriter, error) {
	for size := 128; ; size *= 2 {
		buffer := make([]byte, size)
		count, err := unix.Lgetxattr(path, posixACLAccessAttribute, buffer)
		switch {
		case err == nil:
			writers, parseErr := parsePOSIXAccessACL(buffer[:count])
			if parseErr != nil {
				return nil, keyFileError(ErrUntrusted, path, "The location '%s' is not trusted: %s.", path, parseErr)
			}
			return writers, nil
		case errors.Is(err, unix.ERANGE) && size < 1<<20:
			continue
		case errors.Is(err, unix.ENODATA), errors.Is(err, unix.ENOTSUP), errors.Is(err, unix.EOPNOTSUPP):
			return nil, nil // no ACL: the mode bits are the whole story
		case errors.Is(err, unix.EINTR):
			size /= 2
			continue
		default:
			return nil, keyFileError(err, path, "Could not read the access ACL of '%s' (%s).", path, errnoName(err))
		}
	}
}
