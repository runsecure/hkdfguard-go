//go:build windows

package integration

import (
	"syscall"
	"testing"

	"github.com/runsecure/hkdfguard-go/securefile"
)

// trustThisAccount trusts the account running the tests, which owns, and may modify, its own temp
// folder - where keyFileDirectory puts key files.
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
