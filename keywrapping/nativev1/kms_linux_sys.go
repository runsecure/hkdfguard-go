//go:build linux

package nativev1

import (
	"os"

	"golang.org/x/sys/unix"
)

// The Linux loader's plain system calls - statx and readlink - which need no cgo, so the
// loader's path checks can run against the real filesystem in any Linux build. The
// dynamic-linker calls (dlopen, dladdr, dlinfo) are in kms_linux.go and need cgo.

// linuxTrustedFile resolves path to a regular file, failing unless it passes the path checks.
func linuxTrustedFile(path string) (string, error) {
	resolved, _, err := linuxResolveTrusted(path, fileRegular, linuxStatus, linuxReadLink, false)
	return resolved, err
}

// The statx fields the checks need.
const linuxStatxRequired = unix.STATX_TYPE | unix.STATX_MODE | unix.STATX_UID | unix.STATX_GID

// linuxStatus is statx without following symbolic links. found is false when nothing is there
// (ENOENT or ENOTDIR); any other failure, such as EACCES, is an error.
func linuxStatus(path string) (fileStatus, bool, error) {
	var stx unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, path, unix.AT_SYMLINK_NOFOLLOW, linuxStatxRequired, &stx); err != nil {
		if errno := errnoOf(err); errno == errnoENOENT || errno == errnoENOTDIR {
			return fileStatus{}, false, nil
		}
		return fileStatus{}, false, untrustedCause(err, "statx('%s') failed", path)
	}
	if stx.Mask&linuxStatxRequired != linuxStatxRequired {
		return fileStatus{}, false, untrusted("statx('%s') did not report the file's type, mode and owner.", path)
	}
	return statusFromMode(stx.Uid, stx.Gid, uint32(stx.Mode)), true, nil
}

// linuxProbe is statx's errno for a path whose existence is only being probed; 0 if it exists.
func linuxProbe(path string) int {
	var stx unix.Statx_t
	return errnoOf(unix.Statx(unix.AT_FDCWD, path, unix.AT_SYMLINK_NOFOLLOW, linuxStatxRequired, &stx))
}

// linuxReadLink is a symbolic link's target, exactly as stored (possibly relative).
func linuxReadLink(path string) (string, bool) {
	target, err := os.Readlink(path)
	return target, err == nil
}
