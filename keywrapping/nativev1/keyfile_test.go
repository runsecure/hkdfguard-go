package nativev1

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"

	"github.com/runsecure/hkdfguard-go"
)

// Reading key files through hkdfguard_open_file, against a fake library: what the binding passes
// in, and how each refusal comes back. keyfile_windows_test.go runs the same paths against the real
// native library.

func TestReadKeyFile_ReturnsExactlyTheBytesTheLibraryRead(t *testing.T) {
	payload := bytes.Repeat([]byte{0x5A}, 132)
	library := &fakeLibrary{openFilePayload: payload}
	w := mustWrapper(t, "service.k", library)

	read, err := w.ReadKeyFile(context.Background(), `C:\keys\v1.bin`)

	if err != nil || !bytes.Equal(read, payload) || len(read) != 132 || cap(read) != 132 {
		t.Fatalf("ReadKeyFile = %d bytes (cap %d), %v; want the 132-byte payload", len(read), cap(read), err)
	}
	if len(library.openFilePaths) != 1 || library.openFilePaths[0] != `C:\keys\v1.bin` {
		t.Errorf("the library was asked for %v", library.openFilePaths)
	}
	if library.openFileCaps[0] != hkdfguard.MaxWrappedKeyBytes {
		t.Errorf("the library was offered %d bytes, want hkdfguard.MaxWrappedKeyBytes", library.openFileCaps[0])
	}
}

func TestReadKeyFile_EachRefusal_MapsToTheErrorACallerActsOn(t *testing.T) {
	cases := []struct {
		status int32
		is     error // nil: matches none of the sentinels
	}{
		{errFileNotFound, fs.ErrNotExist},
		{errFileAccessDenied, fs.ErrPermission},
		{errFileUntrusted, fs.ErrPermission},
		{errFileTooShort, hkdfguard.ErrInvalidKeyFile},
		{errFileTooLong, hkdfguard.ErrInvalidKeyFile},
		{errFilePlaintextKey, hkdfguard.ErrInvalidKeyFile},
		{errFileMalformed, hkdfguard.ErrInvalidKeyFile},
		{errInvalidArgument, fs.ErrInvalid},
		{errFileIO, nil},
		{errInternalError, nil},
	}
	sentinels := []error{fs.ErrNotExist, fs.ErrPermission, hkdfguard.ErrInvalidKeyFile, fs.ErrInvalid}
	const path = "/srv/app/keys/v1.bin"

	for _, c := range cases {
		library := &fakeLibrary{openFileStatus: c.status, describe: describeStatus}
		w := mustWrapper(t, "service.k", library)

		read, err := w.ReadKeyFile(context.Background(), path)

		if read != nil || err == nil {
			t.Fatalf("%d: ReadKeyFile = %v, %v; want an error", c.status, read, err)
		}
		var keyFileErr *KeyFileError
		if !errors.As(err, &keyFileErr) || keyFileErr.Status != c.status || keyFileErr.Path != path {
			t.Errorf("%d: error = %#v; want a *KeyFileError with the status and path", c.status, err)
		}
		for _, sentinel := range sentinels {
			if got := errors.Is(err, sentinel); got != (sentinel == c.is) {
				t.Errorf("%d: errors.Is(err, %v) = %v", c.status, sentinel, got)
			}
		}
		want := fmt.Sprintf("Key file '%s' was refused by the native library with status %d (%s).", path, c.status, describeStatus(c.status))
		if err.Error() != want {
			t.Errorf("%d: message = %q, want %q", c.status, err.Error(), want)
		}
	}
}

func TestReadKeyFile_AStatusTheLibraryCannotDescribe_SaysSo(t *testing.T) {
	w := mustWrapper(t, "service.k", &fakeLibrary{openFileStatus: -50, describe: describeStatus})

	_, err := w.ReadKeyFile(context.Background(), "key.bin")

	want := "Key file 'key.bin' was refused by the native library with status -50 (unknown status)."
	if err == nil || err.Error() != want {
		t.Errorf("error = %v, want %q", err, want)
	}
}

func TestReadKeyFile_APlaintextKey_IsReportedAsAKeyExposure_WithThePlatformsDescription(t *testing.T) {
	for platform, describe := range map[string]func(int32) string{"windows": describeWindowsStatus, "linux": describeLinuxStatus, "darwin": describeMacStatus} {
		w := mustWrapper(t, "service.k", &fakeLibrary{openFileStatus: errFilePlaintextKey, describe: describe})

		_, err := w.ReadKeyFile(context.Background(), "dek.txt")

		if err == nil || !strings.Contains(err.Error(), "status -37") || !strings.Contains(err.Error(), "key exposure") || !strings.Contains(err.Error(), "'dek.txt'") {
			t.Errorf("%s: error = %v", platform, err)
		}
	}
}

func TestReadKeyFile_AnEmptyOrNULPath_NeverReachesTheLibrary(t *testing.T) {
	library := &fakeLibrary{openFilePayload: []byte{1}}
	w := mustWrapper(t, "service.k", library)

	for _, path := range []string{"", "key\x00.bin"} {
		if _, err := w.ReadKeyFile(context.Background(), path); !errors.Is(err, fs.ErrInvalid) {
			t.Errorf("%q: error = %v; want fs.ErrInvalid", path, err)
		}
	}
	if len(library.openFilePaths) != 0 {
		t.Errorf("the library was asked for %q", library.openFilePaths)
	}
}

func TestReadKeyFile_ACancelledContext_NeverReachesTheLibrary(t *testing.T) {
	library := &fakeLibrary{openFilePayload: []byte{1}}
	w := mustWrapper(t, "service.k", library)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := w.ReadKeyFile(ctx, "key.bin"); !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v; want context.Canceled", err)
	}
	if len(library.openFilePaths) != 0 {
		t.Error("the library was called")
	}
}

func TestReadKeyFile_ASuccessReportingAnImpossibleCount_IsRefused(t *testing.T) {
	for _, read := range []int32{-1, 0, hkdfguard.MaxWrappedKeyBytes + 1} {
		read := read
		w := mustWrapper(t, "service.k", &fakeLibrary{openFilePayload: []byte{1, 2, 3}, openFileRead: &read})

		if got, err := w.ReadKeyFile(context.Background(), "key.bin"); err == nil {
			t.Errorf("%d bytes read: ReadKeyFile = %v, nil; want an error", read, got)
		}
	}
}

func TestReadKeyFile_ALibraryWithoutTheCall_IsUnsupported_NotReadAnotherWay(t *testing.T) {
	w := mustWrapper(t, "service.k", &fakeLibrary{openFileErr: unsupported("no hkdfguard_open_file")})

	if _, err := w.ReadKeyFile(context.Background(), "key.bin"); !errors.Is(err, ErrUnsupportedPlatform) {
		t.Errorf("error = %v; want ErrUnsupportedPlatform", err)
	}
}

func TestTheKeyWrapper_ReadsKeyFilesForAKeyRing(t *testing.T) {
	// hkdfguard.ReadKeyFile - what dek.Build calls for each key file - goes through the wrapper,
	// and surfaces its refusals unchanged.
	payload := bytes.Repeat([]byte{0x42}, 132)
	library := &fakeLibrary{openFilePayload: payload}
	w := mustWrapper(t, "service.k", library)

	read, err := hkdfguard.ReadKeyFile(context.Background(), w, "/nowhere/v1.bin")
	if err != nil || !bytes.Equal(read, payload) || len(library.openFilePaths) != 1 {
		t.Errorf("ReadKeyFile = %d bytes, %v after %d native calls", len(read), err, len(library.openFilePaths))
	}

	library.openFileStatus = errFileUntrusted
	if _, err := hkdfguard.ReadKeyFile(context.Background(), w, "/nowhere/v1.bin"); !errors.Is(err, fs.ErrPermission) {
		t.Errorf("a refusal: %v; want fs.ErrPermission", err)
	}
}
