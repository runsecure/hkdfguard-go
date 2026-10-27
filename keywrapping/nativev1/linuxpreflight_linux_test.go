//go:build linux

package nativev1

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// These run the real dynamic linker in list mode, against files every Linux system has.

func listingFor(t *testing.T, target string, environment []string) []string {
	t.Helper()
	interpreter, err := elfReadInterpreterFile("/proc/self/exe")
	if err != nil || interpreter == "" {
		t.Fatalf("PT_INTERP of /proc/self/exe = %q, %v", interpreter, err)
	}
	output, err := linuxListDependencies(interpreter, target, environment)
	if err != nil {
		t.Fatal(err)
	}
	paths, err := linuxParseListing(target, output)
	if err != nil {
		t.Fatalf("%v\n%s", err, output)
	}
	return paths
}

func TestLinuxListing_OfASystemBinary_NamesLibcAndPassesThePathChecks(t *testing.T) {
	paths := listingFor(t, "/bin/sh", nil)
	if !slices.ContainsFunc(paths, func(p string) bool { return strings.Contains(filepath.Base(p), "libc.so") }) {
		t.Errorf("listing of /bin/sh names no libc: %v", paths)
	}
	if err := linuxVerifyListing("/bin/sh", paths, linuxTrustedFile); err != nil {
		t.Error(err)
	}
}

func TestLinuxListing_ADependencyFoundInAWritableFolder_IsRefusedBeforeAnythingLoads(t *testing.T) {
	// The real dynamic linker, told by LD_LIBRARY_PATH to look in a folder anyone can write, finds
	// a copy of libc there; the check refuses it whoever owns it, since the folder is 0777.
	libc := ""
	for _, p := range listingFor(t, "/bin/sh", nil) {
		if strings.HasPrefix(filepath.Base(p), "libc.so") {
			libc = p
		}
	}
	if libc == "" {
		t.Skip("no libc in /bin/sh's listing")
	}
	folder := t.TempDir()
	if err := os.Chmod(folder, 0o777); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(libc)
	if err != nil {
		t.Fatal(err)
	}
	planted := filepath.Join(folder, filepath.Base(libc))
	if err := os.WriteFile(planted, data, 0o755); err != nil {
		t.Fatal(err)
	}

	paths := listingFor(t, "/bin/sh", []string{"LD_LIBRARY_PATH=" + folder})
	if !slices.Contains(paths, planted) {
		t.Fatalf("the linker did not pick up the planted copy: %v", paths)
	}
	requireUntrusted(t, linuxVerifyListing("/bin/sh", paths, linuxTrustedFile), planted, "nothing was loaded")
}

func TestLinuxListing_OfAFileThatDoesNotExist_Fails(t *testing.T) {
	interpreter, err := elfReadInterpreterFile("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := linuxListDependencies(interpreter, "/nonexistent/libhkdfguard.so.1", nil); err == nil {
		t.Error("listing a file that doesn't exist succeeded")
	}
}

func TestLinuxListing_OfASharedLibrary_NamesTheDynamicLinker(t *testing.T) {
	// libhkdfguard.so.1 is a shared object, not an executable; list mode works on those too.
	libc := ""
	for _, p := range listingFor(t, "/bin/sh", nil) {
		if strings.HasPrefix(filepath.Base(p), "libc.so") {
			libc = p
		}
	}
	if libc == "" {
		t.Skip("no libc in /bin/sh's listing")
	}
	paths := listingFor(t, libc, nil)
	if !slices.ContainsFunc(paths, func(p string) bool { return strings.Contains(filepath.Base(p), "ld-linux") }) {
		t.Errorf("listing of %s names no dynamic linker: %v", libc, paths)
	}
	if err := linuxVerifyListing(libc, paths, linuxTrustedFile); err != nil {
		t.Error(err)
	}
}
