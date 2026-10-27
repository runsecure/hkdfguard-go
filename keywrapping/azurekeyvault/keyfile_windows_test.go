//go:build windows

package azurekeyvault

import (
	"errors"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/runsecure/hkdfguard-go/securefile"
)

func currentUserSID(t *testing.T) string {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	return user.User.Sid.String()
}

func TestReadKeyFile_ReadsAFileTheWritersAccountIsTrustedFor_AndItReveals_Windows(t *testing.T) {
	wrapper := newWrapper(t, newFakeVault(t), Options{
		Context:      "hkdfguard.test",
		KeyFileTrust: securefile.NewKeyFileTrust(securefile.KeyFileTrustOptions{WindowsPrincipals: []string{currentUserSID(t)}}),
	})
	readAndReveal(t, wrapper, userWritableKeyFile(t))
}

func TestReadKeyFile_RefusesToTrustEveryone_Windows(t *testing.T) {
	wrapper := newWrapper(t, newFakeVault(t), Options{
		KeyFileTrust: securefile.NewKeyFileTrust(securefile.KeyFileTrustOptions{WindowsPrincipals: []string{"S-1-1-0"}}),
	})
	if _, err := wrapper.ReadKeyFile(t.Context(), userWritableKeyFile(t)); !errors.Is(err, securefile.ErrInvalidTrust) {
		t.Fatalf("got %v; want securefile.ErrInvalidTrust", err)
	}
}
