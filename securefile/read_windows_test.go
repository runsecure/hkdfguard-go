//go:build windows

package securefile

import (
	"bytes"
	"encoding/hex"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/runsecure/hkdfguard-go"
	"golang.org/x/sys/windows"
)

// ReadTrustedKeyFile against real files on Windows. Each test's key file is in a fresh folder under
// the temp folder, which inherits the user's own permissions: owned by, and modifiable by, the
// account running the tests - so it is refused by default, and read once that account is trusted.

// windowsKeyDirectory is a fresh folder under the temp folder, by its long path: Windows can hand
// out %TEMP% in 8.3 short form, which the final-path check refuses.
func windowsKeyDirectory(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	long, ok := longPath(directory)
	if !ok {
		t.Fatalf("GetLongPathNameW failed for %s", directory)
	}
	return long
}

// currentUserSID is the SID of the account running the tests.
func currentUserSID(t *testing.T) string {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	return user.User.Sid.String()
}

// trustCurrentUser trusts the account running the tests, which owns, and may modify, its own temp
// folder.
func trustCurrentUser(t *testing.T) KeyFileTrust {
	return NewKeyFileTrust(KeyFileTrustOptions{WindowsPrincipals: []string{currentUserSID(t)}})
}

// system32 runs a System32 tool by its full path, never one found on PATH.
func system32(t *testing.T, tool string, args ...string) {
	t.Helper()
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	output, err := exec.Command(filepath.Join(root, "System32", tool), args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", tool, args, err, output)
	}
}

func writeKeyFile(t *testing.T, path string, contents []byte) {
	t.Helper()
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readKeyFile(t *testing.T, path string, trust KeyFileTrust) ([]byte, error) {
	t.Helper()
	return ReadTrustedKeyFile(t.Context(), path, trust)
}

func TestWindowsKeyFile_RefusesAFileInTheUsersOwnFolderByDefault(t *testing.T) {
	path := filepath.Join(windowsKeyDirectory(t), "v1.key")
	writeKeyFile(t, path, wrapped())

	_, err := readKeyFile(t, path, AdministratorsOnly())
	requireKeyFileError(t, err, ErrUntrusted, "not trusted", "is owned by")
	if !strings.Contains(err.Error(), currentUserSID(t)) {
		t.Errorf("%q doesn't name the owner", err)
	}
	requireKeyFileError(t, err, fs.ErrPermission)
}

func TestWindowsKeyFile_ReadsTheFileWithTheUserTrusted(t *testing.T) {
	key := wrapped()
	path := filepath.Join(windowsKeyDirectory(t), "v1.key")
	writeKeyFile(t, path, key)

	for _, spelling := range []string{path, strings.ReplaceAll(path, `\`, "/")} {
		got, err := readKeyFile(t, spelling, trustCurrentUser(t))
		if err != nil || !bytes.Equal(got, key) {
			t.Errorf("%s: %x, %v; want the key", spelling, got, err)
		}
	}
}

func TestWindowsKeyFile_ReadsARelativePathFromTheWorkingDirectory(t *testing.T) {
	key := wrapped()
	directory := windowsKeyDirectory(t)
	writeKeyFile(t, filepath.Join(directory, "v1.key"), key)
	t.Chdir(directory)

	got, err := readKeyFile(t, "v1.key", trustCurrentUser(t))
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("%x, %v; want the key", got, err)
	}
}

func TestWindowsKeyFile_RefusesAFileOthersMayWrite_EvenWithTheUserTrusted(t *testing.T) {
	path := filepath.Join(windowsKeyDirectory(t), "v1.key")
	writeKeyFile(t, path, wrapped())
	system32(t, "icacls.exe", path, "/grant", "*S-1-5-32-545:(W)") // Users: Write

	_, err := readKeyFile(t, path, trustCurrentUser(t))
	requireKeyFileError(t, err, ErrUntrusted, "grants", `BUILTIN\Users`)
}

func TestWindowsKeyFile_RefusesAFolderOthersMayWrite_EvenWithTheUserTrusted(t *testing.T) {
	directory := windowsKeyDirectory(t)
	path := filepath.Join(directory, "v1.key")
	writeKeyFile(t, path, wrapped())
	system32(t, "icacls.exe", directory, "/grant", "*S-1-5-32-545:(AD)") // Users: create subfolders, on the folder only

	_, err := readKeyFile(t, path, trustCurrentUser(t))
	requireKeyFileError(t, err, ErrUntrusted, "'"+directory+"' grants")
}

func TestWindowsKeyFile_RefusesAPathThroughAJunction(t *testing.T) {
	directory := windowsKeyDirectory(t)
	real := filepath.Join(directory, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	writeKeyFile(t, filepath.Join(real, "v1.key"), wrapped())
	junction := filepath.Join(directory, "junction")
	system32(t, "cmd.exe", "/c", "mklink", "/J", junction, real)

	_, err := readKeyFile(t, filepath.Join(junction, "v1.key"), trustCurrentUser(t))
	requireKeyFileError(t, err, ErrUntrusted, "it opens", filepath.Join(real, "v1.key"))
}

func TestWindowsKeyFile_ExpandsAShortName_AndChecksTheRealPath(t *testing.T) {
	key := wrapped()
	path := filepath.Join(windowsKeyDirectory(t), "a-long-key-file-name.key")
	writeKeyFile(t, path, key)
	short := shortPath(t, path)
	if short == path {
		t.Skip("8.3 short names are turned off on this volume.")
	}

	// The full path expands 8.3 names, so the folders checked are the real ones.
	got, err := readKeyFile(t, short, trustCurrentUser(t))
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("%s: %x, %v; want the key", short, got, err)
	}
	_, err = readKeyFile(t, short, AdministratorsOnly())
	requireKeyFileError(t, err, ErrUntrusted, filepath.Base(path))
}

func TestWindowsKeyFile_ReportsAMissingFileOrFolderAsNotFound(t *testing.T) {
	directory := windowsKeyDirectory(t)
	for _, path := range []string{filepath.Join(directory, "missing.key"), filepath.Join(directory, "missing", "v1.key")} {
		_, err := readKeyFile(t, path, trustCurrentUser(t))
		requireKeyFileError(t, err, fs.ErrNotExist, "was not found")
	}
}

func TestWindowsKeyFile_RefusesAFolder(t *testing.T) {
	_, err := readKeyFile(t, windowsKeyDirectory(t), trustCurrentUser(t))
	requireKeyFileError(t, err, fs.ErrPermission)
}

func TestWindowsKeyFile_RefusesAFileAnotherProcessHasOpenForWriting(t *testing.T) {
	path := filepath.Join(windowsKeyDirectory(t), "v1.key")
	writeKeyFile(t, path, wrapped())
	writer, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()

	_, err = readKeyFile(t, path, trustCurrentUser(t))
	requireKeyFileError(t, err, ErrBusy, "open for writing by another process")
}

func TestWindowsKeyFile_RefusesAUncOrDevicePath_WithoutOpeningIt(t *testing.T) {
	for _, path := range []string{`\\hkdfguard-no-such-server.invalid\share\v1.key`, "//hkdfguard-no-such-server.invalid/share/v1.key",
		`\\?\C:\HkdfGuardKeys\v1.key`} {
		_, err := readKeyFile(t, path, AdministratorsOnly())
		requireKeyFileError(t, err, ErrUntrusted, "UNC or device path")
	}
}

func TestWindowsKeyFile_RefusesToTrustEveryone(t *testing.T) {
	path := filepath.Join(windowsKeyDirectory(t), "v1.key")
	writeKeyFile(t, path, wrapped())
	_, err := readKeyFile(t, path, NewKeyFileTrust(KeyFileTrustOptions{WindowsPrincipals: []string{"S-1-1-0"}}))
	requireErrorContaining(t, err, ErrInvalidTrust, "every account")
}

func TestWindowsKeyFile_RefusesAPlaintextKeyOnceItsLocationPasses(t *testing.T) {
	path := filepath.Join(windowsKeyDirectory(t), "v1.key")
	writeKeyFile(t, path, []byte(hex.EncodeToString(random(32))))
	_, err := readKeyFile(t, path, trustCurrentUser(t))
	requireKeyFileError(t, err, hkdfguard.ErrInvalidKeyFile, "unwrapped")
}

// shortPath is the 8.3 short form of an existing path, or the path itself when the volume has
// short names turned off.
func shortPath(t *testing.T, path string) string {
	t.Helper()
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]uint16, maxPathChars)
	length, err := windows.GetShortPathName(pointer, &buffer[0], uint32(len(buffer)))
	if err != nil {
		t.Fatal(err)
	}
	return windows.UTF16ToString(buffer[:length])
}
