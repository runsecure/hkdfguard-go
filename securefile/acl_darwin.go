//go:build darwin

package securefile

// accessACLWriters reads no ACL on macOS: its extended ACLs aren't POSIX ACLs, and aren't
// evaluated here; the mode bits decide.
func accessACLWriters(string) ([]aclWriter, error) {
	return nil, nil
}
