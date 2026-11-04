//go:build linux

package systemdcredentials

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"testing"
)

// The real systemd-creds: on Linux, and only when HKDFGUARD_TEST_SYSTEMD_CREDS is 1, as root or
// with --user credentials (systemd 256 or later).
func TestARealCredential_RoundTripsThroughSystemdCreds_AndOnlyUnderItsName(t *testing.T) {
	if os.Getenv("HKDFGUARD_TEST_SYSTEMD_CREDS") != "1" {
		t.Skip("runs the real systemd-creds: set HKDFGUARD_TEST_SYSTEMD_CREDS to 1 on Linux, as root or with --user credentials")
	}
	account, _ := user.Current()
	credentials, err := New(Options{Key: KeyHost, UserScope: account == nil || account.Username != "root"})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "tls-password.cred")
	ctx := context.Background()

	if err := credentials.Encrypt(ctx, "tls-password", []byte("pässwörd"), path); err != nil {
		t.Fatal(err)
	}
	value, err := credentials.Decrypt(ctx, "tls-password", path)
	if err != nil {
		t.Fatal(err)
	}
	defer value.Close()

	if got, _ := value.Value(); string(got) != "pässwörd" {
		t.Fatalf("%q", got)
	}
	encrypted, _ := os.ReadFile(path)
	if bytes.Contains(encrypted, []byte("pässwörd")) {
		t.Fatal("the plaintext is in the credential file")
	}
	if _, err := credentials.Decrypt(ctx, "db-password", path); !errors.Is(err, ErrCommandFailed) {
		t.Fatalf("decrypting under another name: %v", err)
	}
}
