package securefile

import "slices"

// KeyFileTrustOptions lists who NewKeyFileTrust trusts besides the operating system's
// administrators. Every list is optional.
type KeyFileTrustOptions struct {
	// WindowsPrincipals are Windows security identifiers (SIDs, such as a deployers group's
	// "S-1-5-21-...-1005") that may also own, and hold write rights on, a key file and the folders
	// above it. They are checked when a key file is read: one that is not a SID, and Everyone,
	// Authenticated Users, Users, Interactive and Anonymous, are refused then (ErrInvalidTrust).
	WindowsPrincipals []string

	// UnixUserIDs are Linux and macOS user ids that may also own a key file, the directories above
	// it, and the symbolic links on its path.
	UnixUserIDs []uint32

	// UnixGroupIDs are Linux and macOS group ids whose members may write a key file or a directory
	// above it: a group-writable file or directory is refused unless its group is listed. Writable
	// by others is refused whatever is listed.
	UnixGroupIDs []uint32
}

// KeyFileTrust is who, besides the operating system's administrators, ReadTrustedKeyFile trusts
// to have written a key file it reads. A key file and every folder above it must be owned by a
// trusted principal, and no one else may write, replace, rename or re-permission any of them:
// whoever can replace a key file - and can also wrap under the KEK, as anyone allowed to encrypt
// with a network KMS key can - chooses the DEK new data is encrypted under.
//
// Always trusted: SYSTEM, Administrators and TrustedInstaller on Windows; root on Linux and macOS.
// The zero value (AdministratorsOnly) trusts no one else, which is the default. Add the account or
// group your deployment writes key files as - never the account the application runs as, unless
// it is a developer machine: an application that can rewrite its own key files can be made to roll
// back to an older one.
//
// A KeyFileTrust is immutable: NewKeyFileTrust copies every list, and the accessors return copies,
// so a list changed afterwards doesn't change what is trusted.
type KeyFileTrust struct {
	windowsPrincipals []string
	unixUserIDs       []uint32
	unixGroupIDs      []uint32
}

// AdministratorsOnly trusts only the operating system's administrators. It is the zero
// KeyFileTrust, and the default.
func AdministratorsOnly() KeyFileTrust { return KeyFileTrust{} }

// NewKeyFileTrust trusts the administrators and everyone options lists, copying each list:
//
//	trust := securefile.NewKeyFileTrust(securefile.KeyFileTrustOptions{
//		WindowsPrincipals: []string{"S-1-5-21-1111111111-2222222222-3333333333-1005"},
//		UnixUserIDs:       []uint32{1001},
//		UnixGroupIDs:      []uint32{2001},
//	})
func NewKeyFileTrust(options KeyFileTrustOptions) KeyFileTrust {
	return KeyFileTrust{
		windowsPrincipals: slices.Clone(options.WindowsPrincipals),
		unixUserIDs:       slices.Clone(options.UnixUserIDs),
		unixGroupIDs:      slices.Clone(options.UnixGroupIDs),
	}
}

// WindowsPrincipals returns a copy of the trusted Windows SIDs, as given.
func (t KeyFileTrust) WindowsPrincipals() []string { return slices.Clone(t.windowsPrincipals) }

// UnixUserIDs returns a copy of the trusted Linux and macOS user ids.
func (t KeyFileTrust) UnixUserIDs() []uint32 { return slices.Clone(t.unixUserIDs) }

// UnixGroupIDs returns a copy of the trusted Linux and macOS group ids.
func (t KeyFileTrust) UnixGroupIDs() []uint32 { return slices.Clone(t.unixGroupIDs) }

// isTrustedUser reports whether uid is root or a trusted user.
func (t KeyFileTrust) isTrustedUser(uid uint32) bool {
	return uid == 0 || slices.Contains(t.unixUserIDs, uid)
}

// isTrustedGroup reports whether gid is a trusted group.
func (t KeyFileTrust) isTrustedGroup(gid uint32) bool {
	return slices.Contains(t.unixGroupIDs, gid)
}
