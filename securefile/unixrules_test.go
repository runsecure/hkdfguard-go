package securefile

import (
	"errors"
	"fmt"
	"io/fs"
	"testing"
)

// The Linux and macOS key-file location rules, checked against simulated filesystems so they run
// on every platform. read_unix_test.go runs them against the real filesystem.

const (
	uidRoot      = 0
	uidDeployer  = 1001
	uidApp       = 1002
	gidDeployers = 2001
	unixKeyFile  = "/etc/hkdfguard/keys/v1.key"
)

var deployerTrust = NewKeyFileTrust(KeyFileTrustOptions{UnixUserIDs: []uint32{uidDeployer}, UnixGroupIDs: []uint32{gidDeployers}})

// fakeFileSystem is a simulated filesystem: what lstat sees, and what each symbolic link holds.
type fakeFileSystem struct {
	entries map[string]unixFileStatus
	links   map[string]string
}

type owned struct{ owner, group, mode uint32 }

func newFileSystem() *fakeFileSystem {
	return &fakeFileSystem{entries: map[string]unixFileStatus{}, links: map[string]string{}}
}

// standardFileSystem is /etc/hkdfguard/keys, root's all the way up, mode 0755.
func standardFileSystem() *fakeFileSystem {
	return newFileSystem().dir("/").dir("/etc").dir("/etc/hkdfguard").dir("/etc/hkdfguard/keys")
}

func (fs *fakeFileSystem) dir(path string, o ...owned) *fakeFileSystem {
	fs.entries[path] = status(unixDirectory, 0o755, o)
	return fs
}

func (fs *fakeFileSystem) file(path string, o ...owned) *fakeFileSystem {
	fs.entries[path] = status(unixRegularFile, 0o640, o)
	return fs
}

func (fs *fakeFileSystem) link(path, target string, owner uint32) *fakeFileSystem {
	fs.entries[path] = unixFileStatus{ownerID: owner, groupID: owner, mode: 0o777, fileType: unixSymbolicLink}
	fs.links[path] = target
	return fs
}

func (fs *fakeFileSystem) other(path string) *fakeFileSystem {
	fs.entries[path] = unixFileStatus{mode: 0o640, fileType: unixOther}
	return fs
}

func status(fileType unixFileType, mode uint32, o []owned) unixFileStatus {
	s := unixFileStatus{mode: mode, fileType: fileType}
	if len(o) > 0 {
		s.ownerID, s.groupID = o[0].owner, o[0].group
		if o[0].mode != 0 {
			s.mode = o[0].mode
		}
	}
	return s
}

func (fs *fakeFileSystem) getStatus(path string) (unixFileStatus, bool, error) {
	s, ok := fs.entries[path]
	return s, ok, nil
}

func (fs *fakeFileSystem) readLink(path string) (string, bool, error) {
	target, ok := fs.links[path]
	return target, ok, nil
}

func (fs *fakeFileSystem) resolve(path string, trust ...KeyFileTrust) (string, error) {
	t := AdministratorsOnly()
	if len(trust) > 0 {
		t = trust[0]
	}
	return resolveTrusted(path, t, fs.getStatus, fs.readLink)
}

func requireResolved(t *testing.T, fs *fakeFileSystem, path, want string, trust ...KeyFileTrust) {
	t.Helper()
	got, err := fs.resolve(path, trust...)
	if err != nil || got != want {
		t.Fatalf("resolve(%q) = %q, %v; want %q", path, got, err, want)
	}
}

func requireRefused(t *testing.T, fs *fakeFileSystem, path string, target error, contains ...string) {
	t.Helper()
	_, err := fs.resolve(path)
	requireKeyFileError(t, err, target, contains...)
}

func requireRefusedWith(t *testing.T, fs *fakeFileSystem, path string, trust KeyFileTrust, target error, contains ...string) {
	t.Helper()
	_, err := fs.resolve(path, trust)
	requireKeyFileError(t, err, target, contains...)
}

func TestUnixRules_ResolveARootOwnedPath(t *testing.T) {
	requireResolved(t, standardFileSystem().file(unixKeyFile), unixKeyFile, unixKeyFile)
}

func TestUnixRules_NeverRefuseAFileForBeingReadableByOthers(t *testing.T) {
	requireResolved(t, standardFileSystem().file(unixKeyFile, owned{mode: 0o644}), unixKeyFile, unixKeyFile)
}

func TestUnixRules_RefuseAFileOwnedByTheApplication(t *testing.T) {
	requireRefused(t, standardFileSystem().file(unixKeyFile, owned{owner: uidApp, group: uidApp}), unixKeyFile, ErrUntrusted, "uid 1002", "not trusted")
}

func TestUnixRules_RefuseAForeignOwnedFile_WhateverElseIsTrusted(t *testing.T) {
	// Owned by an account the trust doesn't name: only root and the deployer are trusted.
	requireRefusedWith(t, standardFileSystem().file(unixKeyFile, owned{owner: uidApp, group: gidDeployers}), unixKeyFile, deployerTrust,
		fs.ErrPermission, "is owned by uid 1002, not root or a trusted user")
}

func TestUnixRules_ResolveAFileOwnedByATrustedDeployer(t *testing.T) {
	requireResolved(t, standardFileSystem().file(unixKeyFile, owned{owner: uidDeployer, group: uidDeployer}), unixKeyFile, unixKeyFile, deployerTrust)
}

func TestUnixRules_RefuseADirectoryOwnedByAnUntrustedUser(t *testing.T) {
	requireRefused(t, standardFileSystem().dir("/etc/hkdfguard/keys", owned{owner: uidApp, group: uidApp}).file(unixKeyFile), unixKeyFile,
		ErrUntrusted, "'/etc/hkdfguard/keys'")
}

func TestUnixRules_RefuseAnUntrustedRoot_AndOneThatCannotBeExamined(t *testing.T) {
	requireRefused(t, standardFileSystem().dir("/", owned{mode: 0o777}).file(unixKeyFile), unixKeyFile, ErrUntrusted)
	requireRefused(t, newFileSystem(), unixKeyFile, ErrUntrusted)
}

func TestUnixRules_RefuseAWorldWritableDirectory_EvenWithTheStickyBit(t *testing.T) {
	fs := newFileSystem().dir("/").dir("/tmp", owned{mode: 0o1777}).dir("/tmp/keys").file("/tmp/keys/v1.key")
	requireRefused(t, fs, "/tmp/keys/v1.key", ErrUntrusted, "writable by every user")
}

func TestUnixRules_RefuseAWorldWritableFile_WhateverIsTrusted(t *testing.T) {
	requireRefusedWith(t, standardFileSystem().file(unixKeyFile, owned{mode: 0o777}), unixKeyFile, deployerTrust, ErrUntrusted)
}

func TestUnixRules_RefuseGroupWritable_UnlessTheGroupIsTrusted(t *testing.T) {
	fs := standardFileSystem().dir("/etc/hkdfguard/keys", owned{mode: 0o775, group: gidDeployers}).file(unixKeyFile, owned{mode: 0o660, group: gidDeployers})
	requireRefused(t, fs, unixKeyFile, ErrUntrusted, "group 2001")
	requireResolved(t, fs, unixKeyFile, unixKeyFile, deployerTrust)
}

func TestUnixRules_RefuseGroupWritableByAnotherGroup_EvenWithATrustedGroup(t *testing.T) {
	requireRefusedWith(t, standardFileSystem().file(unixKeyFile, owned{mode: 0o660, group: uidApp}), unixKeyFile, deployerTrust, ErrUntrusted)
}

func TestUnixRules_FollowARootOwnedSymbolicLink_AndCheckItsTarget(t *testing.T) {
	// macOS's /etc.
	fs := newFileSystem().dir("/").link("/etc", "private/etc", uidRoot).dir("/private").dir("/private/etc").dir("/private/etc/hkdfguard").
		file("/private/etc/hkdfguard/v1.key")
	requireResolved(t, fs, "/etc/hkdfguard/v1.key", "/private/etc/hkdfguard/v1.key")
}

func TestUnixRules_RestartFromRootForAnAbsoluteSymbolicLink(t *testing.T) {
	fs := standardFileSystem().file(unixKeyFile).dir("/srv").link("/srv/current.key", unixKeyFile, uidRoot)
	requireResolved(t, fs, "/srv/current.key", unixKeyFile)
}

func TestUnixRules_NeverFollowASymbolicLinkOwnedByAnUntrustedUser(t *testing.T) {
	fs := standardFileSystem().file(unixKeyFile).dir("/srv").link("/srv/current.key", unixKeyFile, uidApp)
	requireRefused(t, fs, "/srv/current.key", ErrUntrusted, "symbolic link owned by uid 1002")
}

func TestUnixRules_FollowASymbolicLinkOwnedByATrustedDeployer(t *testing.T) {
	fs := standardFileSystem().file(unixKeyFile).dir("/srv").link("/srv/current.key", unixKeyFile, uidDeployer)
	requireResolved(t, fs, "/srv/current.key", unixKeyFile, deployerTrust)
}

func TestUnixRules_RefuseASymbolicLinkIntoAnUntrustedDirectory(t *testing.T) {
	fs := standardFileSystem().dir("/home").dir("/home/app", owned{owner: uidApp, group: uidApp}).file("/home/app/v1.key", owned{owner: uidApp, group: uidApp}).
		link(unixKeyFile, "/home/app/v1.key", uidRoot)
	requireRefused(t, fs, unixKeyFile, ErrUntrusted)
}

func TestUnixRules_RefuseASymbolicLinkLoop(t *testing.T) {
	fs := newFileSystem().dir("/").link("/a", "/b", uidRoot).link("/b", "/a", uidRoot)
	requireRefused(t, fs, "/a", ErrUntrusted, fmt.Sprintf("more than %d symbolic links", maxSymbolicLinks))
}

func TestUnixRules_RefuseASymbolicLinkThatCannotBeRead(t *testing.T) {
	fs := standardFileSystem().file(unixKeyFile).dir("/srv").link("/srv/current.key", unixKeyFile, uidRoot)
	delete(fs.links, "/srv/current.key")
	requireRefused(t, fs, "/srv/current.key", ErrUntrusted, "could not be read as a symbolic link")
}

func TestUnixRules_ResolveDotAndDotDotAfterLinks_TheWayTheKernelDoes(t *testing.T) {
	fs := standardFileSystem().file(unixKeyFile)
	requireResolved(t, fs, "/etc/./hkdfguard/keys/../keys//v1.key", unixKeyFile)
	requireResolved(t, fs, "/../etc/hkdfguard/keys/v1.key", unixKeyFile)
}

func TestUnixRules_ReportAMissingFile_AndAPathThroughAFile_AsNotFound(t *testing.T) {
	requireRefused(t, standardFileSystem(), unixKeyFile, fs.ErrNotExist, "was not found")
	requireRefused(t, standardFileSystem().file(unixKeyFile), unixKeyFile+"/more", fs.ErrNotExist, "not a directory")
}

func TestUnixRules_RefuseADirectoryOrADevice(t *testing.T) {
	requireRefused(t, standardFileSystem(), "/etc/hkdfguard/keys", ErrUntrusted, "not a regular file")
	requireRefused(t, standardFileSystem().other(unixKeyFile), unixKeyFile, ErrUntrusted, "not a regular file")
}

func TestUnixRules_RefuseARelativePathAsAnArgumentError(t *testing.T) {
	_, err := standardFileSystem().resolve("keys/v1.key")
	requireErrorContaining(t, err, fs.ErrInvalid, "not an absolute path")
}

func TestUnixRules_PassOnAnErrorExaminingAComponent(t *testing.T) {
	files := standardFileSystem().file(unixKeyFile)
	failure := keyFileError(fs.ErrPermission, "/etc/hkdfguard", "EACCES from lstat")
	failing := func(path string) (unixFileStatus, bool, error) {
		if path == "/etc/hkdfguard" {
			return unixFileStatus{}, false, failure
		}
		return files.getStatus(path)
	}
	_, err := resolveTrusted(unixKeyFile, AdministratorsOnly(), failing, files.readLink)
	if !errors.Is(err, failure) {
		t.Fatalf("got %v; want the lstat failure", err)
	}
}

func TestUnixRules_TakeTheLexicalParentOfAPath(t *testing.T) {
	for path, want := range map[string]string{"/etc/hkdfguard": "/etc", "/etc": "/", "/": "/"} {
		if got := parentOf(path); got != want {
			t.Errorf("parentOf(%q) = %q; want %q", path, got, want)
		}
	}
}
