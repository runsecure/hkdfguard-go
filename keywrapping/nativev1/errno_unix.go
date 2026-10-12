//go:build darwin || linux

package nativev1

import (
	"errors"

	"golang.org/x/sys/unix"
)

// errnoOf is the errno a failed system call reported, 0 for success, or -1 for an error that
// carries none (so it is never mistaken for "not there").
func errnoOf(err error) int {
	if err == nil {
		return 0
	}
	var errno unix.Errno
	if errors.As(err, &errno) {
		return int(errno)
	}
	return -1
}
