package hashicorpvault

import (
	"errors"
	"io/fs"
	"testing"

	"github.com/runsecure/hkdfguard-go/internal/kmstest"
	"github.com/runsecure/hkdfguard-go/securefile"
)

func requireNotTrusted(t *testing.T, err error) {
	t.Helper()
	kmstest.RequireNotTrusted[*securefile.KeyFileError](t, err, securefile.ErrUntrusted)
}

func TestReadKeyFile_RefusesByDefaultAFileTheCurrentUserCouldHaveReplaced(t *testing.T) {
	if !kmstest.KeyFilesRead() {
		t.Skip("Key files are read on Windows, Linux and Apple silicon macOS only.")
	}
	_, err := newWrapper(t, newFakeTransit(t).newClient(t), withContext()).ReadKeyFile(t.Context(), kmstest.UserWritableKeyFile(t))
	requireNotTrusted(t, err)
}

func TestReadKeyFile_TrustsAdministratorsOnly_WhenGivenNoTrust(t *testing.T) {
	if !kmstest.KeyFilesRead() {
		t.Skip("Key files are read on Windows, Linux and Apple silicon macOS only.")
	}
	// The same refusal as the default: a zero KeyFileTrust is AdministratorsOnly, never "anyone".
	_, err := newWrapper(t, newFakeTransit(t).newClient(t), Options{KeyFileTrust: securefile.KeyFileTrust{}}).ReadKeyFile(t.Context(), kmstest.UserWritableKeyFile(t))
	requireNotTrusted(t, err)
}

func TestReadKeyFile_RefusesAMissingPath(t *testing.T) {
	for _, path := range []string{"", "v1\x00.key"} {
		if _, err := newWrapper(t, newFakeTransit(t).newClient(t)).ReadKeyFile(t.Context(), path); !errors.Is(err, fs.ErrInvalid) {
			t.Errorf("%q: %v; want fs.ErrInvalid", path, err)
		}
	}
}
