//go:build linux

package integration

import (
	"testing"

	"github.com/runsecure/hkdfguard-go/internal/keyfiledir"
)

// keyFileDirectory is a fresh private directory for the files these tests hand to the native library, which refuses a key file under any group- or other-writable directory (so never under t.TempDir() on Linux): see keyfiledir.New.
func keyFileDirectory(t *testing.T) string {
	t.Helper()
	return keyfiledir.New(t, "keys-")
}
