//go:build linux

package securefile

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// accessACL builds a system.posix_acl_access value: owner rw-, owning group rw-, a named user with
// rw-, mask rw-, other r--.
func accessACL(namedUser uint32) []byte {
	value := binary.LittleEndian.AppendUint32(nil, posixACLVersion)
	for _, e := range []struct {
		tag, perm uint16
		id        uint32
	}{{0x01, 6, 0xFFFFFFFF}, {0x02, 6, namedUser}, {0x04, 6, 0xFFFFFFFF}, {0x10, 6, 0xFFFFFFFF}, {0x20, 4, 0xFFFFFFFF}} {
		value = binary.LittleEndian.AppendUint16(value, e.tag)
		value = binary.LittleEndian.AppendUint16(value, e.perm)
		value = binary.LittleEndian.AppendUint32(value, e.id)
	}
	return value
}

func TestUnixKeyFile_RefusesAGroupWritableFileWhoseAccessACLLetsAnUntrustedUserWrite(t *testing.T) {
	key := wrapped()
	path := filepath.Join(keyFileDirectory(t), "v1.key")
	writeUnixKeyFile(t, path, key, 0o660)

	// Trusted as it stands: this user and group.
	if got, err := readUnix(t, path, trustThisUser()); err != nil || !bytes.Equal(got, key) {
		t.Fatalf("%x, %v; want the key", got, err)
	}

	stranger := uint32(os.Geteuid()) + 4242
	if err := unix.Lsetxattr(path, posixACLAccessAttribute, accessACL(stranger), 0); err != nil {
		if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.EPERM) {
			t.Skipf("this filesystem won't take a POSIX ACL here: %v", err)
		}
		t.Fatal(err)
	}

	_, err := readUnix(t, path, trustThisUser())
	requireKeyFileError(t, err, ErrUntrusted, "access ACL")
}
