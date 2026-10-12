package nativev1

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// The macOS loader's decisions, checked against simulated filesystems so they run on every
// platform. kms_darwin_test.go runs the real loader on a Mac.

const (
	macRoot      uint32 = 0
	macUser      uint32 = 501
	macOtherUser uint32 = 502
	macWheel     uint32 = 0
	macAdmin     uint32 = 80
	macStaff     uint32 = 20
	macHome             = "/Users/dev"
)

var (
	macSystemOwners = []uint32{macRoot}
	macUserOwners   = []uint32{macRoot, macUser}
)

func dirStatus(owner, group, perm uint32) fileStatus {
	return fileStatus{uid: owner, gid: group, perm: perm, typ: fileDirectory}
}

func regularStatus(owner, group, perm uint32) fileStatus {
	return fileStatus{uid: owner, gid: group, perm: perm, typ: fileRegular}
}

// A standard system install: /Library/Application Support is root:admin and group-writable.
func macSystemInstall() map[string]fileStatus {
	return map[string]fileStatus{
		"/":                                      dirStatus(macRoot, macWheel, 0o755),
		"/Library":                               dirStatus(macRoot, macWheel, 0o755),
		"/Library/Application Support":           dirStatus(macRoot, macAdmin, 0o775),
		"/Library/Application Support/HkdfGuard": dirStatus(macRoot, macWheel, 0o755),
		macSystemDirectory:                       dirStatus(macRoot, macWheel, 0o755),
		macSystemPath:                            regularStatus(macRoot, macWheel, 0o644),
	}
}

// A standard per-user install under a user-owned home.
func macUserInstall() map[string]fileStatus {
	return map[string]fileStatus{
		"/":                        dirStatus(macRoot, macWheel, 0o755),
		"/Users":                   dirStatus(macRoot, macAdmin, 0o755),
		macHome:                    dirStatus(macUser, macStaff, 0o755),
		macHome + "/.hkdfguard":    dirStatus(macUser, macStaff, 0o700),
		macHome + "/.hkdfguard/v1": dirStatus(macUser, macStaff, 0o700),
		macUserPath(macHome):       regularStatus(macUser, macStaff, 0o644),
	}
}

func macVerify(fs map[string]fileStatus, path string, owners []uint32) error {
	return macVerifyLocation(path, func(p string) (fileStatus, error) {
		status, ok := fs[p]
		if !ok {
			return fileStatus{}, fmt.Errorf("lstat('%s') failed with errno 2", p)
		}
		return status, nil
	}, owners)
}

func requireUntrusted(t *testing.T, err error, contains ...string) {
	t.Helper()
	if !errors.Is(err, ErrUntrusted) {
		t.Fatalf("error = %v, want ErrUntrusted", err)
	}
	for _, s := range contains {
		if !strings.Contains(err.Error(), s) {
			t.Errorf("error %q does not contain %q", err, s)
		}
	}
}

// --- Platform -------------------------------------------------------------------------------

func TestMacRequireSupportedPlatform_AcceptsArm64OnMacOS13OrLater(t *testing.T) {
	for _, version := range []string{"13.0", "15.4", "26.6.2"} {
		if err := macRequireSupportedPlatform("arm64", version); err != nil {
			t.Errorf("%s: %v", version, err)
		}
	}
}

func TestMacRequireSupportedPlatform_RefusesAmd64_NamingRosetta(t *testing.T) {
	err := macRequireSupportedPlatform("amd64", "15.0")

	if !errors.Is(err, ErrUnsupportedPlatform) || !strings.Contains(err.Error(), "Apple silicon") || !strings.Contains(err.Error(), "Rosetta") {
		t.Errorf("error = %v", err)
	}
}

func TestMacRequireSupportedPlatform_RefusesEveryOtherArchitecture(t *testing.T) {
	for _, goarch := range []string{"386", "arm"} {
		if err := macRequireSupportedPlatform(goarch, "15.0"); !errors.Is(err, ErrUnsupportedPlatform) || !strings.Contains(err.Error(), goarch) {
			t.Errorf("%s: error = %v", goarch, err)
		}
	}
}

func TestMacRequireSupportedPlatform_RefusesMacOSOlderThan13_OrAnUnknownVersion(t *testing.T) {
	err := macRequireSupportedPlatform("arm64", "12.7.6")
	if !errors.Is(err, ErrUnsupportedPlatform) || !strings.Contains(err.Error(), "macOS 13") || !strings.Contains(err.Error(), "12.7.6") {
		t.Errorf("error = %v", err)
	}

	if err := macRequireSupportedPlatform("arm64", ""); !errors.Is(err, ErrUnsupportedPlatform) {
		t.Errorf("unknown version: error = %v", err)
	}
}

// --- Locations ------------------------------------------------------------------------------

func TestMacTheTwoLocations_AreTheAgreedPaths(t *testing.T) {
	if macSystemPath != "/Library/Application Support/HkdfGuard/v1/libhkdfguard_v1.dylib" {
		t.Errorf("macSystemPath = %q", macSystemPath)
	}
	for _, home := range []string{"/Users/dev", "/Users/dev/"} {
		if got := macUserPath(home); got != "/Users/dev/.hkdfguard/v1/libhkdfguard_v1.dylib" {
			t.Errorf("macUserPath(%q) = %q", home, got)
		}
	}
}

const (
	present = 0
	eACCES  = 13
)

func TestMacChoosePath_PrefersTheSystemInstall_EvenWhenAUserInstallExists(t *testing.T) {
	path, isSystem, err := macChoosePath(func(string) int { return present }, macHome)

	if err != nil || path != macSystemPath || !isSystem {
		t.Errorf("got %q, %v, %v", path, isSystem, err)
	}
}

func TestMacChoosePath_UsesTheUserInstall_OnlyWhenThereIsNoSystemInstall(t *testing.T) {
	user := macUserPath(macHome)
	for _, systemErrno := range []int{errnoENOENT, errnoENOTDIR} {
		path, isSystem, err := macChoosePath(func(p string) int {
			if p == user {
				return present
			}
			return systemErrno
		}, macHome)

		if err != nil || path != user || isSystem {
			t.Errorf("errno %d: got %q, %v, %v", systemErrno, path, isSystem, err)
		}
	}
}

func TestMacChoosePath_WhenTheSystemInstallCannotBeExamined_RefusesInsteadOfFallingBack(t *testing.T) {
	for _, errno := range []int{eACCES, 62 /* ELOOP */, 5 /* EIO */} {
		var probed []string
		_, _, err := macChoosePath(func(p string) int { probed = append(probed, p); return errno }, macHome)

		requireUntrusted(t, err, macSystemPath, fmt.Sprintf("errno %d", errno))
		if !slices.Equal(probed, []string{macSystemPath}) {
			t.Errorf("probed %v; the user install must never be considered", probed)
		}
	}
}

func TestMacChoosePath_WhenTheUserInstallCannotBeExamined_Refuses(t *testing.T) {
	_, _, err := macChoosePath(func(p string) int {
		if p == macSystemPath {
			return errnoENOENT
		}
		return eACCES
	}, macHome)

	requireUntrusted(t, err, macUserPath(macHome))
}

func TestMacChoosePath_WithNeitherInstallUsable_ReportsNotInstalledNamingBothLocations(t *testing.T) {
	for _, home := range []string{macHome, "", "relative/home"} {
		_, _, err := macChoosePath(func(p string) int {
			if !strings.HasPrefix(p, "/") && strings.HasSuffix(p, ".dylib") {
				return present // a relative home's install must never be used
			}
			return errnoENOENT
		}, home)

		if !errors.Is(err, ErrNotInstalled) || !strings.Contains(err.Error(), macSystemPath) || !strings.Contains(err.Error(), ".hkdfguard/v1/libhkdfguard_v1.dylib") {
			t.Errorf("home %q: error = %v", home, err)
		}
	}
}

func TestMacParentOf_WalksSlashSeparatedPathsUpToRoot(t *testing.T) {
	cases := []struct {
		path, parent string
		ok           bool
	}{
		{"/a/b/c.dylib", "/a/b", true},
		{"/a/b/", "/a", true},
		{"/a", "/", true},
		{"/", "", false},
	}
	for _, c := range cases {
		if parent, ok := macParentOf(c.path); parent != c.parent || ok != c.ok {
			t.Errorf("macParentOf(%q) = %q, %v", c.path, parent, ok)
		}
	}
}

// --- Path integrity -------------------------------------------------------------------------

func TestMacAStandardSystemInstall_Passes(t *testing.T) {
	if err := macVerify(macSystemInstall(), macSystemPath, macSystemOwners); err != nil {
		t.Error(err)
	}
}

func TestMacAStandardUserInstall_Passes(t *testing.T) {
	if err := macVerify(macUserInstall(), macUserPath(macHome), macUserOwners); err != nil {
		t.Error(err)
	}
}

func TestMacASystemInstallOwnedByAUser_IsRefused(t *testing.T) {
	fs := macSystemInstall()
	fs[macSystemDirectory] = dirStatus(macUser, macStaff, 0o755)

	requireUntrusted(t, macVerify(fs, macSystemPath, macSystemOwners), "owned by uid 501", "owned by root.")
}

func TestMacAUserInstallOwnedByAnotherUser_IsRefused(t *testing.T) {
	fs := macUserInstall()
	fs[macUserPath(macHome)] = regularStatus(macOtherUser, macStaff, 0o644)

	requireUntrusted(t, macVerify(fs, macUserPath(macHome), macUserOwners), "owned by uid 502", "root or the current user")
}

func TestMacAnyWorldWritableComponent_IsRefused(t *testing.T) {
	fs := macUserInstall()
	fs[macHome+"/.hkdfguard"] = dirStatus(macUser, macStaff, 0o702)

	requireUntrusted(t, macVerify(fs, macUserPath(macHome), macUserOwners), "writable by every user")
}

func TestMacAGroupWritableComponentOwnedByAUser_IsRefused(t *testing.T) {
	fs := macUserInstall()
	fs[macHome] = dirStatus(macUser, macStaff, 0o775)

	requireUntrusted(t, macVerify(fs, macUserPath(macHome), macUserOwners), "writable by group 20")
}

func TestMacAGroupWritableRootDirectory_IsRefused_UnlessTheGroupIsWheelOrAdmin(t *testing.T) {
	fs := macSystemInstall()
	fs["/Library/Application Support"] = dirStatus(macRoot, macStaff, 0o775)
	requireUntrusted(t, macVerify(fs, macSystemPath, macSystemOwners))

	fs["/Library/Application Support"] = dirStatus(macRoot, macWheel, 0o775)
	if err := macVerify(fs, macSystemPath, macSystemOwners); err != nil {
		t.Error(err)
	}
}

func TestMacTheSystemDirectoriesAboveAnInstall_MayBeAdminWritable(t *testing.T) {
	for _, directory := range []string{"/", "/Library", "/Library/Application Support"} {
		fs := macSystemInstall()
		fs[directory] = dirStatus(macRoot, macAdmin, 0o775)
		if err := macVerify(fs, macSystemPath, macSystemOwners); err != nil {
			t.Errorf("%s: %v", directory, err)
		}
	}

	fs := macUserInstall()
	fs["/Users"] = dirStatus(macRoot, macAdmin, 0o775)
	if err := macVerify(fs, macUserPath(macHome), macUserOwners); err != nil {
		t.Errorf("/Users: %v", err)
	}
}

func TestMacTheInstallsOwnDirectories_AreNeverAdminWritable(t *testing.T) {
	for _, directory := range []string{"/Library/Application Support/HkdfGuard", macSystemDirectory} {
		for _, group := range []uint32{macWheel, macAdmin} {
			fs := macSystemInstall()
			fs[directory] = dirStatus(macRoot, group, 0o775)

			requireUntrusted(t, macVerify(fs, macSystemPath, macSystemOwners), fmt.Sprintf("'%s' is writable by group %d", directory, group))
		}
	}
}

func TestMacTheLibraryFile_IsNeverAdminWritable(t *testing.T) {
	fs := macSystemInstall()
	fs[macSystemPath] = regularStatus(macRoot, macAdmin, 0o664)

	requireUntrusted(t, macVerify(fs, macSystemPath, macSystemOwners))
}

func TestMacAnotherRootOwnedDirectory_GetsNoAdminException(t *testing.T) {
	// The exception is by exact path: a root-owned, admin-writable home gets none.
	fs := macUserInstall()
	fs[macHome] = dirStatus(macRoot, macAdmin, 0o775)

	requireUntrusted(t, macVerify(fs, macUserPath(macHome), macUserOwners))
}

func TestMacASymbolicLinkedDirectory_IsRefused(t *testing.T) {
	fs := macUserInstall()
	fs[macHome+"/.hkdfguard"] = fileStatus{uid: macUser, gid: macStaff, perm: 0o755, typ: fileSymlink}

	requireUntrusted(t, macVerify(fs, macUserPath(macHome), macUserOwners), "is not a directory (it is a symbolic link)")
}

func TestMacTheLibraryItself_MustBeARegularFile(t *testing.T) {
	for typ, described := range map[fileType]string{fileSymlink: "symbolic link", fileDirectory: "directory", fileOther: "special file"} {
		fs := macSystemInstall()
		fs[macSystemPath] = fileStatus{uid: macRoot, gid: macWheel, perm: 0o644, typ: typ}

		requireUntrusted(t, macVerify(fs, macSystemPath, macSystemOwners), "(it is a "+described+")")
	}
}

func TestMacADirectoryThatIsARegularFile_IsDescribedAsSuch(t *testing.T) {
	fs := macSystemInstall()
	fs["/Library/Application Support/HkdfGuard"] = regularStatus(macRoot, macWheel, 0o755)

	requireUntrusted(t, macVerify(fs, macSystemPath, macSystemOwners), "(it is a regular file)")
}

// --- Code signature -------------------------------------------------------------------------

func TestMacTheCodeRequirement_PinsTheHkdfGuardTeam(t *testing.T) {
	want := `identifier "libhkdfguard_v1" and anchor apple generic` +
		` and certificate 1[field.1.2.840.113635.100.6.2.6] exists` +
		` and certificate leaf[field.1.2.840.113635.100.6.1.13] exists` +
		` and certificate leaf[subject.OU] = "MFW3T8R8J3"`
	if macTeamID != "MFW3T8R8J3" || macCodeRequirement != want {
		t.Errorf("macCodeRequirement = %q", macCodeRequirement)
	}
}

func TestMacVerifySignature_PassesTheRequirement_AndAcceptsSuccess(t *testing.T) {
	var checked string
	err := macVerifySignature("/x.dylib", func(_, requirement string) int32 { checked = requirement; return 0 })

	if err != nil || checked != macCodeRequirement {
		t.Errorf("error = %v, requirement = %q", err, checked)
	}
}

func TestMacVerifySignature_RefusesAnyFailure(t *testing.T) {
	for _, status := range []int32{-67050 /* errSecCSReqFailed */, -67062 /* errSecCSUnsigned */} {
		err := macVerifySignature("/x.dylib", func(string, string) int32 { return status })

		requireUntrusted(t, err, "MFW3T8R8J3", fmt.Sprint(status))
	}
}

// --- What dyld loads ------------------------------------------------------------------------

func TestMacRefuseShadowing_Allows_WhenNothingOnDyldLibraryPathHasTheLibrarysName(t *testing.T) {
	for _, searchPath := range []string{"", "/opt/lib:/usr/local/lib"} {
		if err := macRefuseShadowing(func(string) string { return searchPath }, func(string) bool { return false }); err != nil {
			t.Errorf("%q: %v", searchPath, err)
		}
	}
}

func TestMacRefuseShadowing_Refuses_WhenADyldLibraryPathDirectoryHoldsTheLibrarysName(t *testing.T) {
	const decoy = "/tmp/decoy/libhkdfguard_v1.dylib"
	for _, searchPath := range []string{"/tmp/decoy", "/opt/lib:/tmp/decoy/:/usr/local/lib"} {
		err := macRefuseShadowing(func(string) string { return searchPath }, func(p string) bool { return p == decoy })

		requireUntrusted(t, err, decoy, "DYLD_LIBRARY_PATH")
	}
}

func TestMacRefuseShadowing_OnlyConsultsDyldLibraryPath(t *testing.T) {
	var asked []string
	_ = macRefuseShadowing(func(name string) string { asked = append(asked, name); return "" }, func(string) bool { return true })

	if !slices.Equal(asked, []string{"DYLD_LIBRARY_PATH"}) {
		t.Errorf("asked %v", asked)
	}
}

func TestMacVerifyLoadedImage(t *testing.T) {
	if err := macVerifyLoadedImage(macSystemPath, macSystemPath); err != nil {
		t.Errorf("the verified path: %v", err)
	}
	requireUntrusted(t, macVerifyLoadedImage(macSystemPath, "/tmp/decoy/libhkdfguard_v1.dylib"),
		"/tmp/decoy/libhkdfguard_v1.dylib", macSystemPath, "unloaded")
	requireUntrusted(t, macVerifyLoadedImage(macSystemPath, ""), probeExport)
}

func TestTheProbeExport_IsOneTheBindingCalls(t *testing.T) {
	if probeExport != "hkdfguard_wrap_dek" {
		t.Errorf("probeExport = %q", probeExport)
	}
}
