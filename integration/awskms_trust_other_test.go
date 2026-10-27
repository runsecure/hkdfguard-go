//go:build !windows

package integration

import (
	"os"
	"testing"

	"github.com/runsecure/hkdfguard-go/securefile"
)

// trustThisAccount trusts the user running the tests, who owns the private directory
// keyFileDirectory puts key files in.
func trustThisAccount(t *testing.T) securefile.KeyFileTrust {
	t.Helper()
	return securefile.NewKeyFileTrust(securefile.KeyFileTrustOptions{UnixUserIDs: []uint32{uint32(os.Geteuid())}})
}
