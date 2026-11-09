//go:build windows

package jsonsecretsfile

import (
	"syscall"
	"testing"

	"github.com/runsecure/hkdfguard-go/securefile"
)

// trustedFolder is a fresh folder securefile accepts once trustThisAccount is trusted, and that
// trust: one under the user's temp folder - owned by, and modifiable by, the account running the
// tests - by its long path, since Windows can hand out %TEMP% in 8.3 short form, which the
// final-path check refuses.
func trustedFolder(t *testing.T) (string, securefile.KeyFileTrust) {
	t.Helper()
	directory := t.TempDir()
	short, err := syscall.UTF16PtrFromString(directory)
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]uint16, 32767)
	n, err := syscall.GetLongPathName(short, &buffer[0], uint32(len(buffer)))
	if err != nil || n == 0 || int(n) >= len(buffer) {
		t.Fatalf("GetLongPathName(%s) = %d, %v", directory, n, err)
	}
	return syscall.UTF16ToString(buffer[:n]), trustThisAccount(t)
}

// trustThisAccount trusts the account running the tests, by its SID.
func trustThisAccount(t *testing.T) securefile.KeyFileTrust {
	t.Helper()
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid, err := user.User.Sid.String()
	if err != nil {
		t.Fatal(err)
	}
	return securefile.NewKeyFileTrust(securefile.KeyFileTrustOptions{WindowsPrincipals: []string{sid}})
}

// runningAsRoot is false: every Windows account's own temp folder is refused by default.
func runningAsRoot() bool { return false }
