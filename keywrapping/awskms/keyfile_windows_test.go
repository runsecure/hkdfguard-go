//go:build windows

package awskms

import (
	"errors"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/runsecure/hkdfguard-go/internal/kmstest"
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
	wrapper := newWrapper(t, newFakeKMS(t), Options{
		EncryptionContext: testContext,
		KeyFileTrust:      securefile.NewKeyFileTrust(securefile.KeyFileTrustOptions{WindowsPrincipals: []string{currentUserSID(t)}}),
	})
	kmstest.ReadAndReveal(t, wrapper, kmstest.UserWritableKeyFile(t))
}

func TestReadKeyFile_RefusesToTrustEveryone_Windows(t *testing.T) {
	wrapper := newWrapper(t, newFakeKMS(t), Options{
		KeyFileTrust: securefile.NewKeyFileTrust(securefile.KeyFileTrustOptions{WindowsPrincipals: []string{"S-1-1-0"}}),
	})
	if _, err := wrapper.ReadKeyFile(t.Context(), kmstest.UserWritableKeyFile(t)); !errors.Is(err, securefile.ErrInvalidTrust) {
		t.Fatalf("got %v; want securefile.ErrInvalidTrust", err)
	}
}
