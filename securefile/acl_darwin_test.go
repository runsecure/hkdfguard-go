//go:build darwin

package securefile

import (
	"bytes"
	"fmt"
	"os/exec"
	"os/user"
	"path/filepath"
	"testing"
)

// ReadTrustedKeyFile against real macOS extended ACLs, set with chmod +a on a key file and its
// directory whose modes show no group or other write.

// chmodACL runs chmod with args (+a "entry", -N, ...) on path, and removes every extended ACL
// entry from it when the test ends.
func chmodACL(t *testing.T, path string, args ...string) {
	t.Helper()
	output, err := exec.Command("/bin/chmod", append(args, path)...).CombinedOutput()
	if err != nil {
		t.Fatalf("chmod %v %s: %v: %s", args, path, err, output)
	}
	t.Cleanup(func() { _ = exec.Command("/bin/chmod", "-N", path).Run() })
}

// aclKeyFile writes a key file, mode 0600, in a trusted directory, and checks it reads back.
func aclKeyFile(t *testing.T) (directory, path string, key []byte) {
	t.Helper()
	directory = keyFileDirectory(t)
	path = filepath.Join(directory, "v1.key")
	key = wrapped()
	writeUnixKeyFile(t, path, key, 0o600)
	requireReadsBack(t, path, key)
	return directory, path, key
}

func requireReadsBack(t *testing.T, path string, key []byte) {
	t.Helper()
	if got, err := readUnix(t, path, trustThisUser()); err != nil || !bytes.Equal(got, key) {
		t.Fatalf("%x, %v; want the key", got, err)
	}
}

func TestDarwinKeyFile_RefusesAFileAnExtendedACLLetsEveryoneWrite(t *testing.T) {
	_, path, _ := aclKeyFile(t)
	chmodACL(t, path, "+a", "everyone allow write")

	_, err := readUnix(t, path, trustThisUser())
	requireKeyFileError(t, err, ErrUntrusted, "access ACL", "lets everyone write", path)
}

func TestDarwinKeyFile_RefusesADirectoryAnExtendedACLLetsEveryoneAddFilesTo(t *testing.T) {
	directory, path, _ := aclKeyFile(t)
	chmodACL(t, directory, "+a", "everyone allow add_file")

	_, err := readUnix(t, path, trustThisUser())
	requireKeyFileError(t, err, ErrUntrusted, "access ACL", "lets everyone write", directory)
}

func TestDarwinKeyFile_RefusesAnEntryLettingEveryoneRewriteTheACL(t *testing.T) {
	_, path, _ := aclKeyFile(t)
	chmodACL(t, path, "+a", "everyone allow writesecurity")

	_, err := readUnix(t, path, trustThisUser())
	requireKeyFileError(t, err, ErrUntrusted, "access ACL", "lets everyone write")
}

func TestDarwinKeyFile_IgnoresDenyAndReadOnlyEntries(t *testing.T) {
	directory, path, key := aclKeyFile(t)
	chmodACL(t, directory, "+a", "everyone deny delete,add_file,delete_child")
	chmodACL(t, path, "+a", "everyone allow read,readattr,readextattr,readsecurity,writeattr,writeextattr")

	requireReadsBack(t, path, key)
}

func TestDarwinKeyFile_SkipsAnEntryOnlyPassedOnToNewChildren(t *testing.T) {
	directory, path, key := aclKeyFile(t)
	chmodACL(t, directory, "+a", "everyone allow add_file,write,file_inherit,directory_inherit,only_inherit")

	requireReadsBack(t, path, key)
}

func TestDarwinKeyFile_AcceptsAnEntryLettingATrustedUserWrite(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Skipf("can't name this user: %v", err)
	}
	directory, path, key := aclKeyFile(t)
	chmodACL(t, directory, "+a", fmt.Sprintf("user:%s allow add_file,delete_child", current.Username))
	chmodACL(t, path, "+a", fmt.Sprintf("user:%s allow write,delete,chown", current.Username))

	requireReadsBack(t, path, key)
}

func TestDarwinAccessACLWriters_NoACLIsNoWriters(t *testing.T) {
	_, path, _ := aclKeyFile(t)
	writers, err := accessACLWriters(path)
	if err != nil || len(writers) != 0 {
		t.Fatalf("accessACLWriters = %v, %v; want none", writers, err)
	}
}

// staffGID is macOS's "staff" group, which every Mac has.
const staffGID = 20

func TestDarwinAccessACLWriters_ReportsAGroupThatMayWrite(t *testing.T) {
	_, path, _ := aclKeyFile(t)
	chmodACL(t, path, "+a", "group:staff allow append")
	writers, err := accessACLWriters(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := []aclWriter{{group: true, id: staffGID}}; fmt.Sprint(writers) != fmt.Sprint(want) {
		t.Fatalf("writers = %v, want %v", writers, want)
	}
}

// An everyone entry is refused outright rather than reported as a writer, as an other-writable
// mode is: everyone is every account, whatever the trust names.
func TestDarwinAccessACLWriters_RefusesTheEveryoneGroup(t *testing.T) {
	_, path, _ := aclKeyFile(t)
	chmodACL(t, path, "+a", "everyone allow append")
	writers, err := accessACLWriters(path)
	requireKeyFileError(t, err, ErrUntrusted, "access ACL", "lets everyone write", path)
	if writers != nil {
		t.Fatalf("writers = %v, want none alongside the refusal", writers)
	}
}
