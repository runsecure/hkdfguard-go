//go:build linux || darwin

package securefile

import (
	"errors"
	"strings"

	"golang.org/x/sys/unix"
)

// readOnPlatform wires the unixrules.go rules to real files; exercised by the Unix-only real-file
// tests.
func readOnPlatform(path string, trust KeyFileTrust) ([]byte, error) {
	absolute := path
	if !strings.HasPrefix(path, "/") {
		// getcwd(2): already a resolved path (os.Getwd may return $PWD, which can hold links).
		// resolveTrusted handles ".." itself.
		workingDirectory, err := unix.Getwd()
		if err != nil {
			return nil, keyFileError(err, path, "Could not find the working directory to resolve key file '%s' (%s).", path, errnoName(err))
		}
		if strings.HasSuffix(workingDirectory, "/") {
			absolute = workingDirectory + path
		} else {
			absolute = workingDirectory + "/" + path
		}
	}
	resolved, err := resolveTrusted(absolute, trust, lstatStatus, readLink)
	if err != nil {
		return nil, err
	}

	// resolved holds no symbolic link, so O_NOFOLLOW changes nothing for a file that passed; it
	// only makes certain the last component is still not one when it is opened.
	descriptor, err := openNoFollow(resolved)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, untrustedUnix(path, "'%s' became a symbolic link after it was checked", resolved)
		}
		return nil, keyFileError(err, path, "Could not open key file '%s' (%s).", path, errnoName(err))
	}
	defer unix.Close(descriptor)

	// The descriptor itself is still a regular file: never a FIFO or device swapped in, which an
	// untrusted account can't do here anyway.
	var status unix.Stat_t
	if err := unix.Fstat(descriptor, &status); err != nil {
		return nil, keyFileError(err, path, "Could not examine key file '%s' (%s).", path, errnoName(err))
	}
	if uint32(status.Mode)&unix.S_IFMT != unix.S_IFREG {
		return nil, untrustedUnix(path, "'%s' is no longer a regular file", resolved)
	}

	return readContents(func(buffer []byte) (int, error) {
		for {
			count, err := unix.Read(descriptor, buffer)
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if err != nil {
				return 0, keyFileError(err, path, "Could not read key file '%s' (%s).", path, errnoName(err))
			}
			return count, nil
		}
	}, path)
}

func openNoFollow(path string) (int, error) {
	for {
		descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if !errors.Is(err, unix.EINTR) {
			return descriptor, err
		}
	}
}

// lstatStatus is lstat: it describes the path itself, never what a symbolic link points to; found
// is false when nothing is there (ENOENT or ENOTDIR).
func lstatStatus(path string) (unixFileStatus, bool, error) {
	var status unix.Stat_t
	if err := unix.Lstat(path, &status); err != nil {
		switch {
		case errors.Is(err, unix.ENOENT), errors.Is(err, unix.ENOTDIR):
			return unixFileStatus{}, false, nil
		case errors.Is(err, unix.EACCES):
			return unixFileStatus{}, false, keyFileError(err, path, "This account may not look up '%s' (EACCES).", path)
		default:
			return unixFileStatus{}, false, keyFileError(err, path, "Could not look up '%s' (%s).", path, errnoName(err))
		}
	}

	mode := uint32(status.Mode)
	fileType := unixOther
	switch mode & unix.S_IFMT {
	case unix.S_IFREG:
		fileType = unixRegularFile
	case unix.S_IFDIR:
		fileType = unixDirectory
	case unix.S_IFLNK:
		fileType = unixSymbolicLink
	}
	return unixFileStatus{ownerID: status.Uid, groupID: status.Gid, mode: mode & 0o7777, fileType: fileType}, true, nil
}

// readLink is readlink: a symbolic link's target, exactly as stored (possibly relative); ok is
// false if the path isn't a symbolic link or isn't there.
func readLink(path string) (string, bool, error) {
	for size := 256; ; size *= 2 {
		buffer := make([]byte, size)
		count, err := unix.Readlink(path, buffer)
		if err != nil {
			switch {
			case errors.Is(err, unix.EINTR):
				size /= 2
				continue
			case errors.Is(err, unix.EINVAL), errors.Is(err, unix.ENOENT), errors.Is(err, unix.ENOTDIR):
				return "", false, nil
			case errors.Is(err, unix.EACCES):
				return "", false, keyFileError(err, path, "This account may not read the symbolic link '%s' (EACCES).", path)
			default:
				return "", false, keyFileError(err, path, "readlink('%s') failed (%s).", path, errnoName(err))
			}
		}
		if count < size {
			return string(buffer[:count]), true, nil
		}
		if size >= 1<<20 {
			return "", false, keyFileError(unix.ENAMETOOLONG, path, "readlink('%s') failed (ENAMETOOLONG).", path)
		}
	}
}

// errnoName is an errno's symbolic name ("ENOENT"), or the error's text.
func errnoName(err error) string {
	var errno unix.Errno
	if errors.As(err, &errno) {
		if name := unix.ErrnoName(errno); name != "" {
			return name
		}
	}
	return err.Error()
}
