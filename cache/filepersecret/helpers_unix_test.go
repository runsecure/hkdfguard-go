//go:build linux || darwin

package filepersecret

import (
	"os"
	"runtime"
	"testing"

	"github.com/runsecure/hkdfguard-go/internal/keyfiledir"
	"github.com/runsecure/hkdfguard-go/securefile"
)

// trustedFolder is a fresh folder securefile accepts once this user is trusted, and that trust: a
// private directory whose whole chain is root's or this user's (see keyfiledir.New) - never under
// /tmp, which is writable by everyone and so never trusted. It skips the test, saying why, when
// there is none on this host, or on an Intel Mac, where securefile reads nothing.
func trustedFolder(t *testing.T) (string, securefile.KeyFileTrust) {
	t.Helper()
	if runtime.GOOS == "darwin" && runtime.GOARCH != "arm64" {
		t.Skip("Trusted files are read on Apple silicon Macs only.")
	}
	return keyfiledir.New(t, "filepersecret-"), securefile.NewKeyFileTrust(securefile.KeyFileTrustOptions{
		UnixUserIDs: []uint32{uint32(os.Geteuid())}, UnixGroupIDs: []uint32{uint32(os.Getegid())}})
}

// runningAsRoot reports whether the tests run as root, whose files are trusted.
func runningAsRoot() bool { return os.Geteuid() == 0 }
