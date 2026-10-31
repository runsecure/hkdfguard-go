//go:build linux || darwin

package hashicorpvault

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/runsecure/hkdfguard-go/internal/keyfiledir"
	"github.com/runsecure/hkdfguard-go/internal/kmstest"
	"github.com/runsecure/hkdfguard-go/securefile"
)

// A key file this user writes must be in a directory whose whole chain is root's or this user's and
// writable by neither group nor others - so never under /tmp, /var/tmp or /dev/shm. keyFileDirectory
// finds one (see keyfiledir.New), or skips the test saying why.
func keyFileDirectory(t *testing.T) string {
	t.Helper()
	return keyfiledir.New(t, "hashicorpvault-")
}

func TestReadKeyFile_ReadsAFileInADirectoryOnlyItsTrustedOwnerCanWrite_AndItReveals_Unix(t *testing.T) {
	directory := keyFileDirectory(t)
	wrapper := newWrapper(t, newFakeTransit(t).newClient(t), Options{
		KeyFileTrust: securefile.NewKeyFileTrust(securefile.KeyFileTrustOptions{UnixUserIDs: []uint32{uint32(os.Geteuid())}}),
	})
	kmstest.ReadAndReveal(t, wrapper, filepath.Join(directory, "v1.key"))
}

func TestReadKeyFile_RefusesAFileItsOwnersAccountIsNotTrustedFor_Unix(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("Running as root, whose files are trusted.")
	}
	_, err := newWrapper(t, newFakeTransit(t).newClient(t)).ReadKeyFile(t.Context(), kmstest.RandomKeyFile(t, keyFileDirectory(t)))
	requireNotTrusted(t, err)
}
