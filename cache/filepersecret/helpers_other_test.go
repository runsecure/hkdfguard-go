//go:build !windows && !linux && !darwin

package filepersecret

import (
	"testing"

	"github.com/runsecure/hkdfguard-go/securefile"
)

// trustedFolder skips the test: securefile reads files on Windows, Linux and macOS only.
func trustedFolder(t *testing.T) (string, securefile.KeyFileTrust) {
	t.Helper()
	t.Skip("Trusted files are read on Windows, Linux and macOS only.")
	return "", securefile.AdministratorsOnly()
}

func runningAsRoot() bool { return false }
