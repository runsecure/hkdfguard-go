package systemdcredentials

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/runsecure/hkdfguard-go"
)

// The port of the .NET SystemdCredentialSourceTests.

type sourceFixture struct {
	folder, loaded string
	creds          *fakeCreds
	credentials    *Credentials
}

func newSourceFixture(t *testing.T) *sourceFixture {
	t.Helper()
	folder := t.TempDir()
	loaded := filepath.Join(folder, "loaded")
	if err := os.Mkdir(loaded, 0o700); err != nil {
		t.Fatal(err)
	}
	creds := &fakeCreds{}
	return &sourceFixture{folder: folder, loaded: loaded, creds: creds, credentials: newCredentials(t, Options{}, creds)}
}

func (f *sourceFixture) encryptedFile(t *testing.T, name, value string) string {
	t.Helper()
	path := filepath.Join(f.folder, name+".cred")
	if err := f.credentials.Encrypt(context.Background(), name, []byte(value), path); err != nil {
		t.Fatal(err)
	}
	return path
}

func (f *sourceFixture) decryptRuns() int {
	n := 0
	for _, r := range f.creds.runs {
		if slices.Contains(r.arguments, "decrypt") {
			n++
		}
	}
	return n
}

func newSource(t *testing.T, credentials *Credentials, files map[string]string, directory string) *Source {
	t.Helper()
	source, err := NewSource(credentials, files, directory)
	if err != nil {
		t.Fatal(err)
	}
	return source
}

func TestAnEncryptedFile_IsDecryptedBySystemdCreds_ForEveryLookup(t *testing.T) {
	f := newSourceFixture(t)
	source := newSource(t, f.credentials, map[string]string{"tls-password": f.encryptedFile(t, "tls-password", "pässwörd")}, f.loaded)
	ctx := context.Background()

	maxLength, ok, err := source.MaxDecryptedLength(ctx, "tls-password")
	if err != nil || !ok {
		t.Fatalf("%d, %v, %v", maxLength, ok, err)
	}
	for range 2 {
		buffer := make([]byte, maxLength)
		n, err := source.Decrypt(ctx, "tls-password", buffer)
		if err != nil || string(buffer[:n]) != "pässwörd" || n != 10 {
			t.Fatalf("%q, %v", buffer[:n], err)
		}
		hkdfguard.Wipe(buffer)
	}

	// Every value read is a systemd-creds run; a length isn't.
	if runs := f.decryptRuns(); runs != 2 {
		t.Fatalf("%d decrypt runs", runs)
	}
}

func TestALoadedCredential_IsReadFirst_WithoutSystemdCreds(t *testing.T) {
	f := newSourceFixture(t)
	_ = os.WriteFile(filepath.Join(f.loaded, "tls-password"), []byte("from-systemd"), 0o600)
	source := newSource(t, f.credentials, map[string]string{"tls-password": f.encryptedFile(t, "tls-password", "from-file")}, f.loaded)

	buffer := make([]byte, 64)
	n, err := source.Decrypt(context.Background(), "tls-password", buffer)
	if err != nil || string(buffer[:n]) != "from-systemd" {
		t.Fatalf("%q, %v", buffer[:n], err)
	}
	if f.decryptRuns() != 0 {
		t.Fatal("systemd-creds ran")
	}
}

func TestOnlyLoadedCredentials_NeedNoCredentials(t *testing.T) {
	f := newSourceFixture(t)
	_ = os.WriteFile(filepath.Join(f.loaded, "tls-password"), []byte("s3cret"), 0o600)
	source := newSource(t, nil, nil, f.loaded)

	maxLength, ok, _ := source.MaxDecryptedLength(context.Background(), "tls-password")
	if !ok {
		t.Fatal("not found")
	}
	if n, err := source.Decrypt(context.Background(), "tls-password", make([]byte, maxLength)); n != 6 || err != nil {
		t.Fatalf("%d, %v", n, err)
	}
}

func TestAMissingOrInvalidName_IsReportedMissing(t *testing.T) {
	f := newSourceFixture(t)
	source := newSource(t, f.credentials, map[string]string{"gone": filepath.Join(f.folder, "gone.cred")}, f.loaded)
	_ = os.WriteFile(filepath.Join(f.loaded, "empty"), nil, 0o600)
	ctx := context.Background()

	for _, name := range []string{"absent", "gone", "../etc", ""} {
		if maxLength, ok, err := source.MaxDecryptedLength(ctx, name); ok || maxLength != 0 || err != nil {
			t.Errorf("%q: %d, %v, %v", name, maxLength, ok, err)
		}
		if n, err := source.Decrypt(ctx, name, make([]byte, 8)); n != 0 || err != nil {
			t.Errorf("%q: %d, %v", name, n, err)
		}
	}
	if _, ok, _ := source.MaxDecryptedLength(ctx, "empty"); ok {
		t.Error("an empty credential has a length")
	}
}

func TestAResultTooSmall_IsRefused(t *testing.T) {
	f := newSourceFixture(t)
	source := newSource(t, f.credentials, map[string]string{"item": f.encryptedFile(t, "item", "s3cret")}, f.loaded)

	if _, err := source.Decrypt(context.Background(), "item", make([]byte, 3)); !errors.Is(err, ErrResultTooSmall) {
		t.Fatalf("got %v", err)
	}
}

func TestAFailingDecrypt_IsReported(t *testing.T) {
	f := newSourceFixture(t)
	path := f.encryptedFile(t, "item", "s3cret")
	source := newSource(t, f.credentials, map[string]string{"item": path}, f.loaded)
	f.creds.fail = &struct {
		exitCode int
		stderr   string
	}{1, "no access to the host key"}

	if _, err := source.Decrypt(context.Background(), "item", make([]byte, 64)); !errors.Is(err, ErrCommandFailed) {
		t.Fatalf("got %v", err)
	}
}

func TestTheEncryptedFiles_AreChecked(t *testing.T) {
	f := newSourceFixture(t)
	for _, c := range []struct {
		credentials *Credentials
		files       map[string]string
	}{
		{f.credentials, map[string]string{"a b": filepath.Join(f.folder, "x")}},
		{f.credentials, map[string]string{"item": "relative.cred"}},
		{f.credentials, map[string]string{"item": ""}},
		{nil, map[string]string{"item": filepath.Join(f.folder, "x")}},
	} {
		if _, err := NewSource(c.credentials, c.files, ""); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("%v: %v", c.files, err)
		}
	}
}
