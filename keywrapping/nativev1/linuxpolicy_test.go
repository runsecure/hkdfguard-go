package nativev1

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
)

// The Linux loader's decisions, checked against simulated filesystems so they run on every
// platform.

const (
	linuxRoot    uint32 = 0
	linuxUser    uint32 = 1000
	linuxLibDir         = "/usr/lib/x86_64-linux-gnu"
	linuxLibrary        = linuxLibDir + "/libhkdfguard.so.1"
	linuxEsys           = linuxLibDir + "/libtss2-esys.so.0.0.1"
)

// simFS is a simulated filesystem: what lstat sees, and what each symbolic link holds.
type simFS struct {
	entries map[string]fileStatus
	links   map[string]string
}

func newSimFS() *simFS {
	return &simFS{entries: map[string]fileStatus{}, links: map[string]string{}}
}

func (fs *simFS) dir(path string, owner uint32, perm uint32) *simFS {
	fs.entries[path] = fileStatus{uid: owner, gid: owner, perm: perm, typ: fileDirectory}
	return fs
}

func (fs *simFS) file(path string, owner uint32, perm uint32) *simFS {
	fs.entries[path] = fileStatus{uid: owner, gid: owner, perm: perm, typ: fileRegular}
	return fs
}

func (fs *simFS) link(path, target string, owner uint32) *simFS {
	fs.entries[path] = fileStatus{uid: owner, gid: owner, perm: 0o777, typ: fileSymlink}
	fs.links[path] = target
	return fs
}

func (fs *simFS) status(path string) (fileStatus, bool, error) {
	status, ok := fs.entries[path]
	return status, ok, nil
}

func (fs *simFS) readLink(path string) (string, bool) {
	target, ok := fs.links[path]
	return target, ok
}

func (fs *simFS) resolve(path string, expected fileType, allowMissing bool) (string, bool, error) {
	return linuxResolveTrusted(path, expected, fs.status, fs.readLink, allowMissing)
}

func (fs *simFS) resolveFile(path string) (string, error) {
	resolved, _, err := fs.resolve(path, fileRegular, false)
	return resolved, err
}

// A standard Debian/Ubuntu host with merged /usr: /lib is a root-owned link to usr/lib.
func linuxStandardHost() *simFS {
	return newSimFS().
		dir("/", linuxRoot, 0o755).dir("/usr", linuxRoot, 0o755).dir("/usr/lib", linuxRoot, 0o755).
		dir(linuxLibDir, linuxRoot, 0o755).dir("/usr/lib64", linuxRoot, 0o755).dir("/opt", linuxRoot, 0o755).
		link("/lib", "usr/lib", linuxRoot).
		link("/lib64", "usr/lib64", linuxRoot).
		file(linuxLibrary, linuxRoot, 0o644).
		link(linuxLibDir+"/libtss2-esys.so.0", "libtss2-esys.so.0.0.1", linuxRoot).
		file(linuxEsys, linuxRoot, 0o644).
		file(linuxLibDir+"/libc.so.6", linuxRoot, 0o644).
		dir("/home", linuxRoot, 0o755).dir("/home/dev", linuxUser, 0o755).dir("/home/dev/lib", linuxUser, 0o755).
		file("/home/dev/lib/libtss2-esys.so.0", linuxUser, 0o644).
		dir("/tmp", linuxRoot, 0o1777)
}

// --- Platform and location ------------------------------------------------------------------

func TestLinuxCandidatePaths_AreThePackagesInstallLocations(t *testing.T) {
	amd64, _ := linuxCandidatePaths("amd64")
	arm64, _ := linuxCandidatePaths("arm64")

	if !slices.Equal(amd64, []string{"/usr/lib/x86_64-linux-gnu/libhkdfguard.so.1", "/usr/lib64/libhkdfguard.so.1"}) {
		t.Errorf("amd64: %v", amd64)
	}
	if !slices.Equal(arm64, []string{"/usr/lib/aarch64-linux-gnu/libhkdfguard.so.1", "/usr/lib64/libhkdfguard.so.1"}) {
		t.Errorf("arm64: %v", arm64)
	}
}

func TestLinuxCandidatePaths_RefuseEveryOtherArchitecture(t *testing.T) {
	for _, goarch := range []string{"386", "arm", "riscv64"} {
		if _, err := linuxCandidatePaths(goarch); !errors.Is(err, ErrUnsupportedPlatform) || !strings.Contains(err.Error(), goarch) {
			t.Errorf("%s: error = %v", goarch, err)
		}
	}
}

func linuxCandidates() []string {
	candidates, _ := linuxCandidatePaths("amd64")
	return candidates
}

func TestLinuxChoosePath_PrefersTheMultiarchDirectory(t *testing.T) {
	if path, err := linuxChoosePath(linuxCandidates(), func(string) int { return present }); err != nil || path != linuxCandidates()[0] {
		t.Errorf("got %q, %v", path, err)
	}
}

func TestLinuxChoosePath_UsesLib64_OnlyWhenThereIsNothingInTheMultiarchDirectory(t *testing.T) {
	candidates := linuxCandidates()
	for _, errno := range []int{errnoENOENT, errnoENOTDIR} {
		path, err := linuxChoosePath(candidates, func(p string) int {
			if p == candidates[0] {
				return errno
			}
			return present
		})
		if err != nil || path != candidates[1] {
			t.Errorf("errno %d: got %q, %v", errno, path, err)
		}
	}
}

func TestLinuxChoosePath_WhenALocationCannotBeExamined_RefusesInsteadOfFallingBack(t *testing.T) {
	var asked []string
	_, err := linuxChoosePath(linuxCandidates(), func(p string) int { asked = append(asked, p); return eACCES })

	requireUntrusted(t, err, "errno 13")
	if !slices.Equal(asked, linuxCandidates()[:1]) {
		t.Errorf("asked %v", asked)
	}
}

func TestLinuxChoosePath_WithNothingInstalled_ReportsNotInstalledNamingThePackageAndEveryLocation(t *testing.T) {
	_, err := linuxChoosePath(linuxCandidates(), func(string) int { return errnoENOENT })

	if !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("error = %v", err)
	}
	for _, s := range append([]string{"libhkdfguard1"}, linuxCandidates()...) {
		if !strings.Contains(err.Error(), s) {
			t.Errorf("error %q does not name %q", err, s)
		}
	}
}

// --- Path integrity -------------------------------------------------------------------------

func requireResolves(t *testing.T, fs *simFS, path string, expected fileType, want string) {
	t.Helper()
	got, found, err := fs.resolve(path, expected, false)
	if err != nil || !found || got != want {
		t.Errorf("resolve(%q) = %q, %v, %v; want %q", path, got, found, err, want)
	}
}

func TestLinuxAStandardInstall_ResolvesToItself(t *testing.T) {
	requireResolves(t, linuxStandardHost(), linuxLibrary, fileRegular, linuxLibrary)
}

func TestLinuxARootOwnedLink_IsFollowed_AndItsTargetChecked(t *testing.T) {
	fs := linuxStandardHost()
	fs.link(linuxLibDir+"/HkdfGuard.Kms.Linux.v1.so", "libhkdfguard.so.1", linuxRoot)

	requireResolves(t, fs, "/lib/x86_64-linux-gnu/libtss2-esys.so.0", fileRegular, linuxEsys)
	requireResolves(t, fs, linuxLibDir+"/HkdfGuard.Kms.Linux.v1.so", fileRegular, linuxLibrary)
	requireResolves(t, fs, "/lib/x86_64-linux-gnu/", fileDirectory, linuxLibDir)
}

func TestLinuxDotDot_IsResolvedAgainstTheRealDirectory_NotTheLinkThatLedThere(t *testing.T) {
	// /opt/app -> ../usr/lib: "/opt/app/.." is /usr, not /opt.
	fs := linuxStandardHost().link("/opt/app", "../usr/lib", linuxRoot)

	requireResolves(t, fs, "/opt/app/x86_64-linux-gnu/libhkdfguard.so.1", fileRegular, linuxLibrary)
	requireResolves(t, fs, "/opt/app/..", fileDirectory, "/usr")
	requireResolves(t, fs, "/..", fileDirectory, "/")
	requireResolves(t, fs, "/usr/./lib/x86_64-linux-gnu//libhkdfguard.so.1", fileRegular, linuxLibrary)
}

func TestLinuxARelativePath_IsRefused(t *testing.T) {
	for _, path := range []string{"usr/lib/x86_64-linux-gnu/libhkdfguard.so.1", "./libhkdfguard.so.1", ""} {
		_, err := linuxStandardHost().resolveFile(path)
		requireUntrusted(t, err, "not an absolute path")
	}
}

func TestLinuxAFileOwnedByAUser_IsRefused(t *testing.T) {
	_, err := linuxStandardHost().file(linuxLibrary, linuxUser, 0o644).resolveFile(linuxLibrary)
	requireUntrusted(t, err, "uid 1000")
}

func TestLinuxADirectoryOwnedByAUser_IsRefused_WhereverItIsOnThePath(t *testing.T) {
	_, err := linuxStandardHost().dir("/usr/lib", linuxUser, 0o755).resolveFile(linuxLibrary)
	requireUntrusted(t, err, "'/usr/lib'")
}

func TestLinuxAnythingWritableByGroupOrOthers_IsRefused_EvenWhenRootOwned(t *testing.T) {
	cases := []struct {
		path string
		perm uint32
	}{{"/", 0o775}, {"/usr", 0o775}, {linuxLibDir, 0o775}, {linuxLibDir, 0o777}, {linuxLibrary, 0o664}}
	for _, c := range cases {
		fs := linuxStandardHost()
		entry := fs.entries[c.path]
		entry.perm = c.perm
		fs.entries[c.path] = entry

		_, err := fs.resolveFile(linuxLibrary)
		requireUntrusted(t, err, fmt.Sprintf("'%s' is writable", c.path))
	}
}

func TestLinuxAStickyWorldWritableDirectory_IsRefused(t *testing.T) {
	_, err := linuxStandardHost().file("/tmp/libtss2-esys.so.0", linuxRoot, 0o644).resolveFile("/tmp/libtss2-esys.so.0")
	requireUntrusted(t, err)
}

func TestLinuxALinkOwnedByAUser_IsRefused_EvenWhenItPointsSomewhereTrusted(t *testing.T) {
	_, err := linuxStandardHost().link("/opt/lib", "/usr/lib", linuxUser).resolveFile("/opt/lib/x86_64-linux-gnu/libhkdfguard.so.1")
	requireUntrusted(t, err, "symbolic link owned by uid 1000")
}

func TestLinuxARootOwnedLinkIntoAUsersDirectory_IsRefused(t *testing.T) {
	_, err := linuxStandardHost().link("/opt/lib", "/home/dev/lib", linuxRoot).resolveFile("/opt/lib/libtss2-esys.so.0")
	requireUntrusted(t, err, "'/home/dev'")
}

func TestLinuxALinkLoop_IsRefused(t *testing.T) {
	fs := linuxStandardHost().link("/opt/a", "/opt/b", linuxRoot).link("/opt/b", "/opt/a", linuxRoot)

	_, err := fs.resolveFile("/opt/a/x")
	requireUntrusted(t, err, fmt.Sprintf("%d symbolic links", linuxMaxSymbolicLinks))
}

func TestLinuxALinkThatCannotBeRead_IsRefused(t *testing.T) {
	fs := linuxStandardHost()
	fs.entries["/opt/broken"] = fileStatus{uid: linuxRoot, perm: 0o777, typ: fileSymlink}

	_, err := fs.resolveFile("/opt/broken/x")
	requireUntrusted(t, err, "could not be read")
}

func TestLinuxAMissingPath_IsRefused_UnlessMissingIsAllowed(t *testing.T) {
	fs := linuxStandardHost()

	_, err := fs.resolveFile(linuxLibDir + "/nothing.so")
	requireUntrusted(t, err, "does not exist")

	for _, c := range []struct {
		path string
		typ  fileType
	}{{linuxLibDir + "/nothing.so", fileRegular}, {"/opt/not/yet/created", fileDirectory}} {
		if _, found, err := fs.resolve(c.path, c.typ, true); err != nil || found {
			t.Errorf("%s: found = %v, err = %v; want missing", c.path, found, err)
		}
	}
}

func TestLinuxAMissingPathUnderAnUntrustedDirectory_IsStillRefused(t *testing.T) {
	// Something missing is only harmless if nobody but root could create it.
	_, _, err := linuxStandardHost().resolve("/home/dev/lib/nothing.so", fileRegular, true)
	requireUntrusted(t, err)
}

func TestLinuxTheWrongKindOfObject_IsRefused(t *testing.T) {
	fs := linuxStandardHost()
	fs.entries["/opt/fifo"] = fileStatus{uid: linuxRoot, perm: 0o644, typ: fileOther}

	_, err := fs.resolveFile(linuxLibDir)
	requireUntrusted(t, err, "is a directory, not a regular file")
	_, _, err = fs.resolve(linuxLibrary, fileDirectory, false)
	requireUntrusted(t, err, "is a regular file, not a directory")
	_, err = fs.resolveFile("/opt/fifo")
	requireUntrusted(t, err, "is a special file")
}

func TestLinuxAPathThroughAFile_IsRefused(t *testing.T) {
	_, err := linuxStandardHost().resolveFile(linuxLibrary + "/x")
	requireUntrusted(t, err, "not a directory")
}

func TestLinuxAnUnexaminableRoot_IsRefused(t *testing.T) {
	_, _, err := linuxResolveTrusted(linuxLibrary, fileRegular,
		func(string) (fileStatus, bool, error) { return fileStatus{}, false, nil },
		func(string) (string, bool) { return "", false }, false)
	requireUntrusted(t, err, "'/'")
}

func TestLinuxParentOf_WalksUpToRoot(t *testing.T) {
	for path, parent := range map[string]string{"/": "/", "/usr": "/", "/usr/lib": "/usr"} {
		if got := linuxParentOf(path); got != parent {
			t.Errorf("linuxParentOf(%q) = %q, want %q", path, got, parent)
		}
	}
}

// --- Environment ----------------------------------------------------------------------------

func environBlock(entries ...string) []byte {
	return []byte(strings.Join(entries, "\x00") + "\x00")
}

func lookupIn(env map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		value, ok := env[name]
		return value, ok
	}
}

func TestLinuxReadEnvironment_CollectsTheInitialAndCurrentValues_OfTheLinkersVariablesOnly(t *testing.T) {
	values := linuxReadEnvironment(
		lookupIn(map[string]string{"LD_LIBRARY_PATH": "/now", "LD_PRELOAD": "/same.so"}),
		environBlock("PATH=/usr/bin", "LD_LIBRARY_PATH=/at/exec", "LD_PRELOAD=/same.so", "LD_AUDIT=/a.so=b", "=junk", "NOEQUALS"))

	want := map[string][]string{
		"LD_LIBRARY_PATH": {"/at/exec", "/now"},
		"LD_PRELOAD":      {"/same.so"},
		"LD_AUDIT":        {"/a.so=b"},
	}
	if !maps.EqualFunc(values, want, slices.Equal) {
		t.Errorf("values = %v", values)
	}
}

func TestLinuxReadEnvironment_WithoutProcEnviron_UsesTheCurrentEnvironment(t *testing.T) {
	values := linuxReadEnvironment(lookupIn(map[string]string{"LD_PRELOAD": "x.so"}), nil)

	if !slices.Equal(values["LD_PRELOAD"], []string{"x.so"}) || len(values["LD_LIBRARY_PATH"]) != 0 {
		t.Errorf("values = %v", values)
	}
}

func verifyEnvironment(fs *simFS, variable string, values ...string) error {
	return linuxVerifyEnvironment(map[string][]string{variable: values}, func(p string, expected fileType) error {
		_, _, err := fs.resolve(p, expected, true)
		return err
	})
}

func TestLinuxAnUnsetEnvironment_Passes(t *testing.T) {
	err := linuxVerifyEnvironment(map[string][]string{}, func(string, fileType) error {
		t.Fatal("nothing to resolve")
		return nil
	})
	if err != nil {
		t.Error(err)
	}
}

func TestLinuxALibraryPathOfRootControlledDirectories_Passes(t *testing.T) {
	for _, value := range []string{
		"", // ignored by the dynamic linker
		"/usr/lib/x86_64-linux-gnu",
		"/lib/x86_64-linux-gnu:/usr/lib64", // through root-owned links
		"/usr/lib;/usr/lib64",              // ';' separates too
		"/opt/not/installed/yet",           // missing, but only root could create it
	} {
		if err := verifyEnvironment(linuxStandardHost(), "LD_LIBRARY_PATH", value); err != nil {
			t.Errorf("%q: %v", value, err)
		}
	}
}

func TestLinuxALibraryPathWithADirectoryOthersCanWrite_IsRefused(t *testing.T) {
	for _, value := range []string{"/home/dev/lib", "/usr/lib:/home/dev/lib", "/tmp", "/home/dev/lib/not-yet"} {
		requireUntrusted(t, verifyEnvironment(linuxStandardHost(), "LD_LIBRARY_PATH", value), "LD_LIBRARY_PATH", "Remove it")
	}
}

func TestLinuxALibraryPathWithAnEmptyEntry_IsRefusedAsTheWorkingDirectory(t *testing.T) {
	for _, value := range []string{":/usr/lib", "/usr/lib:", "/usr/lib::/usr/lib64"} {
		requireUntrusted(t, verifyEnvironment(linuxStandardHost(), "LD_LIBRARY_PATH", value), "working directory")
	}
}

func TestLinuxALibraryPathThatCantBeCheckedInAdvance_IsRefused(t *testing.T) {
	cases := map[string]string{"lib": "relative", "./lib": "relative", "$ORIGIN/lib": "dynamic string token", "/usr/${LIB}": "dynamic string token"}
	for value, reason := range cases {
		requireUntrusted(t, verifyEnvironment(linuxStandardHost(), "LD_LIBRARY_PATH", value), reason)
	}
}

func TestLinuxEveryValueTheVariableHasHad_IsChecked(t *testing.T) {
	// A clean current value must not hide what the process started with.
	requireUntrusted(t, verifyEnvironment(linuxStandardHost(), "LD_LIBRARY_PATH", "/usr/lib", "/home/dev/lib"))
}

func TestLinuxPreloadingOrAuditingFromRootControlledLocations_Passes(t *testing.T) {
	cases := [][2]string{
		{"LD_PRELOAD", "libjemalloc.so.2"}, // a bare name: found by the checked search
		{"LD_PRELOAD", "/usr/lib/x86_64-linux-gnu/libc.so.6"},
		{"LD_PRELOAD", "libjemalloc.so.2 /lib/x86_64-linux-gnu/libc.so.6"},
		{"LD_PRELOAD", "   "},
		{"LD_AUDIT", "/usr/lib/x86_64-linux-gnu/libc.so.6:libaudit.so"},
	}
	for _, c := range cases {
		if err := verifyEnvironment(linuxStandardHost(), c[0], c[1]); err != nil {
			t.Errorf("%s=%q: %v", c[0], c[1], err)
		}
	}
}

func TestLinuxPreloadingOrAuditingFromAnywhereElse_IsRefused(t *testing.T) {
	cases := [][2]string{
		{"LD_PRELOAD", "/home/dev/lib/libtss2-esys.so.0"},
		{"LD_PRELOAD", "libjemalloc.so.2 /home/dev/lib/libtss2-esys.so.0"},
		{"LD_PRELOAD", "libjemalloc.so.2:/home/dev/lib/libtss2-esys.so.0"},
		{"LD_PRELOAD", "./evil.so"},
		{"LD_PRELOAD", "$LIB/evil.so"},
		{"LD_AUDIT", "/home/dev/lib/libtss2-esys.so.0"},
		{"LD_AUDIT", "lib/evil.so"},
	}
	for _, c := range cases {
		requireUntrusted(t, verifyEnvironment(linuxStandardHost(), c[0], c[1]), c[0])
	}
}

func TestLinuxALocationThatCannotBeExamined_IsRefused(t *testing.T) {
	cause := errors.New("statx('/srv') failed with errno 13")
	err := linuxVerifyEnvironment(map[string][]string{"LD_LIBRARY_PATH": {"/srv/lib"}}, func(string, fileType) error { return cause })

	requireUntrusted(t, err, "errno 13")
	if !errors.Is(err, cause) {
		t.Errorf("error %v does not wrap the cause", err)
	}
}

// --- What was loaded ------------------------------------------------------------------------

func TestLinuxVerifyLoadedImage(t *testing.T) {
	if err := linuxVerifyLoadedImage(linuxLibrary, linuxLibrary); err != nil {
		t.Errorf("the verified path: %v", err)
	}
	requireUntrusted(t, linuxVerifyLoadedImage(linuxLibrary, "/usr/lib64/libhkdfguard.so.1"), "/usr/lib64/libhkdfguard.so.1")
	requireUntrusted(t, linuxVerifyLoadedImage(linuxLibrary, ""), probeExport)
}

// The installed library's closure, as ldd reports it on Ubuntu 24.04.
var linuxNeeded = map[string][]string{
	linuxLibrary:                          {"libtss2-esys.so.0", "libgcc_s.so.1", "libc.so.6"},
	linuxEsys:                             {"libtss2-mu.so.0", "libcrypto.so.3", "libc.so.6"},
	linuxLibDir + "/libtss2-mu.so.0.0.1":  {"libc.so.6"},
	linuxLibDir + "/libcrypto.so.3":       {"libc.so.6"},
	linuxLibDir + "/libgcc_s.so.1":        {"libc.so.6"},
	linuxLibDir + "/libc.so.6":            {"ld-linux-x86-64.so.2"},
	linuxLibDir + "/ld-linux-x86-64.so.2": {},
}

func linuxLoaded() map[string]string {
	return map[string]string{
		"libtss2-esys.so.0":    "/lib/x86_64-linux-gnu/libtss2-esys.so.0",
		"libtss2-mu.so.0":      "/lib/x86_64-linux-gnu/libtss2-mu.so.0",
		"libcrypto.so.3":       "/lib/x86_64-linux-gnu/libcrypto.so.3",
		"libgcc_s.so.1":        "/lib/x86_64-linux-gnu/libgcc_s.so.1",
		"libc.so.6":            "/lib/x86_64-linux-gnu/libc.so.6",
		"ld-linux-x86-64.so.2": "/lib64/ld-linux-x86-64.so.2",
	}
}

func linuxHostWithClosure() *simFS {
	return linuxStandardHost().
		link(linuxLibDir+"/libtss2-mu.so.0", "libtss2-mu.so.0.0.1", linuxRoot).file(linuxLibDir+"/libtss2-mu.so.0.0.1", linuxRoot, 0o644).
		file(linuxLibDir+"/libcrypto.so.3", linuxRoot, 0o644).file(linuxLibDir+"/libgcc_s.so.1", linuxRoot, 0o644).
		link("/usr/lib64/ld-linux-x86-64.so.2", "../lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", linuxRoot).
		file(linuxLibDir+"/ld-linux-x86-64.so.2", linuxRoot, 0o644)
}

func verifyDependencies(fs *simFS, loaded map[string]string, read *[]string) error {
	return linuxVerifyDependencies(linuxLibrary,
		func(file string) ([]string, error) {
			if read != nil {
				*read = append(*read, file)
			}
			return linuxNeeded[file], nil
		},
		func(name string) (string, bool) { path, ok := loaded[name]; return path, ok },
		fs.resolveFile)
}

func TestLinuxATrustedDependencyClosure_Passes_AndEveryFileInItIsReadOnce(t *testing.T) {
	var read []string
	if err := verifyDependencies(linuxHostWithClosure(), linuxLoaded(), &read); err != nil {
		t.Fatal(err)
	}

	slices.Sort(read)
	if want := slices.Sorted(maps.Keys(linuxNeeded)); !slices.Equal(read, want) {
		t.Errorf("read %v, want %v", read, want)
	}
}

func TestLinuxADirectDependencyLoadedFromAUsersDirectory_IsRefused(t *testing.T) {
	loaded := linuxLoaded()
	loaded["libtss2-esys.so.0"] = "/home/dev/lib/libtss2-esys.so.0"

	requireUntrusted(t, verifyDependencies(linuxHostWithClosure(), loaded, nil), "'libtss2-esys.so.0'", linuxLibrary)
}

func TestLinuxATransitiveDependencyLoadedFromAnUntrustedDirectory_IsRefused(t *testing.T) {
	fs := linuxHostWithClosure().file("/tmp/libcrypto.so.3", linuxRoot, 0o644)
	loaded := linuxLoaded()
	loaded["libcrypto.so.3"] = "/tmp/libcrypto.so.3"

	requireUntrusted(t, verifyDependencies(fs, loaded, nil), "'libcrypto.so.3' (needed by '"+linuxEsys+"')")
}

func TestLinuxADependencyNothingAnswersTo_IsRefused(t *testing.T) {
	loaded := linuxLoaded()
	delete(loaded, "libgcc_s.so.1")

	requireUntrusted(t, verifyDependencies(linuxHostWithClosure(), loaded, nil), "libgcc_s.so.1")
}

func TestLinuxADependencyThatCannotBeExamined_IsRefused(t *testing.T) {
	cause := errors.New("statx failed with errno 13")
	err := linuxVerifyDependencies(linuxLibrary,
		func(string) ([]string, error) { return []string{"libc.so.6"}, nil },
		func(string) (string, bool) { return "/lib/x86_64-linux-gnu/libc.so.6", true },
		func(string) (string, error) { return "", cause })

	requireUntrusted(t, err)
	if !errors.Is(err, cause) {
		t.Errorf("error %v does not wrap the cause", err)
	}
}
