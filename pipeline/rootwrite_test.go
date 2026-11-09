package pipeline

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// outside is a file and a folder outside the folder a test writes to, which no write may change.
type outside struct {
	file, folder, contents string
}

func newOutside(t *testing.T) outside {
	t.Helper()
	dir := t.TempDir()
	o := outside{file: filepath.Join(dir, "target.txt"), folder: filepath.Join(dir, "folder"), contents: "must not change"}
	if err := os.WriteFile(o.file, []byte(o.contents), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(o.folder, 0o700); err != nil {
		t.Fatal(err)
	}
	return o
}

func (o outside) requireUnchanged(t *testing.T) {
	t.Helper()
	if got, err := os.ReadFile(o.file); err != nil || string(got) != o.contents {
		t.Errorf("the file outside the folder is now %q, %v", got, err)
	}
	if entries, err := os.ReadDir(o.folder); err != nil || len(entries) != 0 {
		t.Errorf("the folder outside now holds %v, %v", entries, err)
	}
}

// plantFileLink makes name in folder a symbolic link to target, or skips the test where this account
// can't make one (Windows without Developer Mode or the privilege).
func plantFileLink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("can't create a symbolic link here: %v", err)
	}
}

// plantFolderLink makes link a link to the folder target: a junction on Windows, which any account
// can make, and a symbolic link elsewhere.
func plantFolderLink(t *testing.T, target, link string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
			t.Skipf("can't create a junction here: %v: %s", err, out)
		}
		return
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

func requireOnlyFiles(t *testing.T, folder string, want ...string) {
	t.Helper()
	entries, err := os.ReadDir(folder)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Errorf("the folder holds %v; want %v (no temporary file left behind)", names, want)
	}
}

func TestWriteProtectedSecretFiles_ReplacesALinkToAFileOutside_RatherThanWritingThroughIt(t *testing.T) {
	o := newOutside(t)
	folder := t.TempDir()
	plantFileLink(t, o.file, filepath.Join(folder, "item"))

	if err := pulledWriter(map[string]string{"item": "encrypted"}).WriteProtectedSecretFiles(folder); err != nil {
		t.Fatal(err)
	}

	o.requireUnchanged(t)
	info, err := os.Lstat(filepath.Join(folder, "item"))
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("the link wasn't replaced by a file: %v, %v", info, err)
	}
	if got, _ := os.ReadFile(filepath.Join(folder, "item")); string(got) != "encrypted" {
		t.Errorf("item = %q", got)
	}
}

func TestWriteProtectedSecretFiles_NeverWritesThroughALinkToAFolderOutside(t *testing.T) {
	o := newOutside(t)
	folder := t.TempDir()
	plantFolderLink(t, o.folder, filepath.Join(folder, "item"))

	// Whether the write fails (a folder is in the way) or replaces the link, nothing outside changes.
	_ = pulledWriter(map[string]string{"item": "encrypted"}).WriteProtectedSecretFiles(folder)
	o.requireUnchanged(t)
}

func TestWriteJSONSecrets_ReplacesALinkToAFileOutside_RatherThanWritingThroughIt(t *testing.T) {
	o := newOutside(t)
	folder := t.TempDir()
	path := filepath.Join(folder, "secrets.json")
	plantFileLink(t, o.file, path)

	if err := pulledWriter(map[string]string{"item": "encrypted"}).WriteJSONSecrets(path); err != nil {
		t.Fatal(err)
	}

	o.requireUnchanged(t)
	if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("the link wasn't replaced by a file: %v, %v", info, err)
	}
}

func TestWrites_ReplaceAnExistingFile_LeavingNoTemporaryFile(t *testing.T) {
	folder := t.TempDir()
	if err := os.WriteFile(filepath.Join(folder, "item"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	w := pulledWriter(map[string]string{"item": "new", "other": "value"})
	if err := w.WriteProtectedSecretFiles(folder); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteJSONSecrets(filepath.Join(folder, "secrets.json")); err != nil {
		t.Fatal(err)
	}

	if got, _ := os.ReadFile(filepath.Join(folder, "item")); string(got) != "new" {
		t.Errorf("item = %q", got)
	}
	requireOnlyFiles(t, folder, "item", "other", "secrets.json")
}

func TestWrites_KeepAReplacedFilesPermissionBits(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no permission bits beyond read-only.")
	}
	folder := t.TempDir()
	path := filepath.Join(folder, "item")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := pulledWriter(map[string]string{"item": "new"}).WriteProtectedSecretFiles(folder); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o640 {
		t.Errorf("mode %v, %v; want 0640 kept", info.Mode().Perm(), err)
	}
}

func TestWrites_AFailedWrite_LeavesThePreviousFileWhole(t *testing.T) {
	folder := t.TempDir()
	path := filepath.Join(folder, "item")
	if err := os.WriteFile(path, []byte("previous"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A folder named as the temporary file would be makes no failure; a read-only folder does, on
	// Unix. On Windows a folder in the way of the final rename does.
	if runtime.GOOS == "windows" {
		blocked := filepath.Join(folder, "blocked")
		if err := os.Mkdir(blocked, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := pulledWriter(map[string]string{"blocked": "x", "item": "new"}).WriteProtectedSecretFiles(folder); err == nil {
			t.Fatal("writing over a folder succeeded")
		}
		requireOnlyFiles(t, folder, "blocked", "item")
		if got, _ := os.ReadFile(path); string(got) != "previous" {
			t.Errorf("item = %q; the failed write touched it", got)
		}
		return
	}
	if os.Geteuid() == 0 {
		t.Skip("root writes into a read-only folder")
	}
	if err := os.Chmod(folder, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(folder, 0o700) })
	if err := pulledWriter(map[string]string{"item": "new"}).WriteProtectedSecretFiles(folder); err == nil {
		t.Fatal("writing into a read-only folder succeeded")
	}
	if got, _ := os.ReadFile(path); string(got) != "previous" {
		t.Errorf("item = %q; the failed write touched it", got)
	}
}
