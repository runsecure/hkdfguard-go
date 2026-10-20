//go:build linux

package nativev1

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

// The Linux loader's path checks against this machine's real filesystem, and the
// installed libhkdfguard1 package where there is one. These need no cgo; the dynamic-linker
// checks and the native round trips are in kms_linux_cgo_test.go.

// installedLinuxLibraryPath is where the package installed the library, skipping the test if it
// isn't installed.
func installedLinuxLibraryPath(t *testing.T) string {
	t.Helper()
	candidates, err := linuxCandidatePaths(runtime.GOARCH)
	if err != nil {
		t.Skipf("no package for this architecture: %v", err)
	}
	for _, candidate := range candidates {
		if linuxProbe(candidate) == 0 {
			return candidate
		}
	}
	t.Skip("the libhkdfguard1 package is not installed")
	return ""
}

func resolveReal(path string, expected fileType, allowMissing bool) (string, bool, error) {
	return linuxResolveTrusted(path, expected, linuxStatus, linuxReadLink, allowMissing)
}

func TestLinuxSystem_TheRootAndSystemLibraryDirectories_AreTrusted(t *testing.T) {
	for _, directory := range []string{"/", "/usr/lib"} {
		resolved, found, err := resolveReal(directory, fileDirectory, false)
		if err != nil || !found || resolved != directory {
			t.Errorf("%s resolves to %q, %v, %v", directory, resolved, found, err)
		}
	}
}

func TestLinuxSystem_ADirectoryThisUserCreated_IsNotTrusted_ForTheLibraryPath(t *testing.T) {
	// The attack this loader exists to stop: a directory the service's own user (or anyone)
	// can write, put on LD_LIBRARY_PATH so a dependency is found there first.
	directory := t.TempDir()

	err := linuxVerifyEnvironment(map[string][]string{envLibraryPath: {directory}}, func(p string, expected fileType) error {
		_, _, err := resolveReal(p, expected, true)
		return err
	})

	requireUntrusted(t, err, directory)
}

func TestLinuxSystem_TheLinkersVariables_AreReadFromProcEnviron(t *testing.T) {
	// Whatever this process started with, /proc/self/environ must be readable for the loader to
	// see it - and parse to the same three variables.
	block, err := os.ReadFile("/proc/self/environ")
	if err != nil {
		t.Fatal(err)
	}

	values := linuxReadEnvironment(func(string) (string, bool) { return "", false }, block)

	var names []string
	for name := range values {
		names = append(names, name)
	}
	slices.Sort(names)
	if want := []string{envAudit, envLibraryPath, envPreload}; !slices.Equal(names, want) {
		t.Errorf("variables = %v, want %v", names, want)
	}
}

func TestLinuxSystem_ProbeDistinguishesMissingFromPresent(t *testing.T) {
	if errno := linuxProbe("/"); errno != 0 {
		t.Errorf("probe('/') = %d", errno)
	}
	if errno := linuxProbe("/definitely/not/here"); errno != errnoENOENT {
		t.Errorf("probe(missing) = %d, want ENOENT", errno)
	}
}

func TestLinuxSystem_StatusAndReadLink_DescribeThisUsersFiles(t *testing.T) {
	directory := t.TempDir()
	file := filepath.Join(directory, "file")
	link := filepath.Join(directory, "link")
	if err := os.WriteFile(file, []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("file", link); err != nil {
		t.Fatal(err)
	}

	status, found, err := linuxStatus(file)
	if err != nil || !found || status.typ != fileRegular || status.uid != uint32(os.Getuid()) || status.perm&0o777 != 0o640 {
		t.Errorf("status(file) = %+v, %v, %v", status, found, err)
	}
	status, found, err = linuxStatus(link)
	if err != nil || !found || status.typ != fileSymlink || status.uid != uint32(os.Getuid()) {
		t.Errorf("status(link) = %+v, %v, %v; want a symbolic link owned by this user", status, found, err)
	}
	if target, ok := linuxReadLink(link); !ok || target != "file" {
		t.Errorf("readLink(link) = %q, %v", target, ok)
	}
	if _, found, err := linuxStatus(filepath.Join(directory, "missing")); found || err != nil {
		t.Errorf("status(missing) = found %v, %v", found, err)
	}

	// Owned by this user, so the loader refuses it - however it is reached.
	if _, _, err := resolveReal(file, fileRegular, false); err == nil {
		t.Error("a file this user owns was trusted")
	}
}

func TestLinuxSystem_TheInstalledLibrary_IsInATrustedLocation(t *testing.T) {
	path := installedLinuxLibraryPath(t)

	if _, err := linuxTrustedFile(path); err != nil {
		t.Fatalf("location: %v", err)
	}
}

func TestLinuxSystem_TheInstalledLibrary_NeedsTPM2TSSAndLibc(t *testing.T) {
	path := installedLinuxLibraryPath(t)

	needed, err := elfReadNeededFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"libtss2-esys.so.0", "libc.so.6"} {
		if !slices.Contains(needed, want) {
			t.Errorf("DT_NEEDED = %v; want %s among them", needed, want)
		}
	}
}
