//go:build windows

package securefile

import (
	"errors"
	"io/fs"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// maxPathChars is the longest path Windows supports, plus its terminator.
const maxPathChars = 32768

// GetFinalPathNameByHandleW flags (fileapi.h), which golang.org/x/sys/windows doesn't define.
const (
	fileNameNormalized = 0x0 // FILE_NAME_NORMALIZED
	volumeNameDOS      = 0x0 // VOLUME_NAME_DOS
)

// openOnPlatform wires the windowsrules.go rules to real files through Win32, then hands consume a
// read function over the open file and the full path to name in its messages; exercised by the
// Windows-only real-file tests. noun is what the messages call the file ("key file").
func openOnPlatform(path string, trust KeyFileTrust, noun string, consume func(read readFunc, name string) error) error {
	trusted, err := trustedPrincipals(trust, canonicalSID, accountName)
	if err != nil {
		return err
	}
	full, err := fullPath(path, noun)
	if err != nil {
		return err
	}
	driveType := uint32(driveNetwork)
	if !strings.HasPrefix(full, `\\`) {
		driveType = getDriveType(filepath.VolumeName(full) + `\`)
	}
	if err := verifyPathForm(full, driveType); err != nil {
		return err
	}

	// Read sharing only: refused if another process has it open for writing, and no one can open
	// it for writing while it's read.
	file, err := openFile(full, noun)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(file)

	final, err := finalPath(file)
	if err != nil {
		return readFailure(full, noun, err)
	}
	if err := verifyFinalPath(full, final); err != nil {
		return err
	}

	// The file through its own handle; the folders by path, which the final-path check ties to the
	// folders it was opened through, and which no untrusted principal can then change.
	security, err := describeSecurity(windows.GetSecurityInfo(file, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION))
	if err != nil {
		return securityFailure(full, full, noun, err)
	}
	if err := verifyTrustedOnly(security, full, full, guardedRights, trusted, accountName); err != nil {
		return err
	}
	for folder := filepath.Dir(full); ; folder = filepath.Dir(folder) {
		descriptor, err := describeSecurity(windows.GetNamedSecurityInfo(folder, windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION))
		if err != nil {
			return securityFailure(full, folder, noun, err)
		}
		if filepath.Dir(folder) == folder {
			if err := verifyTrustedOnly(descriptor, full, folder, guardedRootRights, trusted, accountName); err != nil {
				return err
			}
			break
		}
		if err := verifyNotReparsePoint(fileAttributes(folder), full, folder); err != nil {
			return err
		}
		if err := verifyTrustedOnly(descriptor, full, folder, guardedRights, trusted, accountName); err != nil {
			return err
		}
	}

	return consume(func(buffer []byte) (int, error) {
		var read uint32
		if err := windows.ReadFile(file, buffer, &read, nil); err != nil {
			return 0, readFailure(full, noun, err)
		}
		return int(read), nil
	}, full)
}

// fullPath is what .NET's Path.GetFullPath returns: GetFullPathNameW's absolute, normalized form (a
// relative path resolved against the working directory), with every 8.3 short name that exists on
// disk expanded to its long name. A short name for something that doesn't exist stays short, and
// the final-path check then refuses it.
func fullPath(path, noun string) (string, error) {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", readFailure(path, noun, err)
	}
	buffer := make([]uint16, maxPathChars)
	length, err := windows.GetFullPathName(pointer, uint32(len(buffer)), &buffer[0], nil)
	if err != nil {
		return "", readFailure(path, noun, err)
	}
	if length == 0 || length >= uint32(len(buffer)) {
		return "", readFailure(path, noun, windows.ERROR_FILENAME_EXCED_RANGE)
	}
	full := windows.UTF16ToString(buffer[:length])
	if strings.Contains(full, "~") {
		return expandShortNames(full, longPath), nil
	}
	return full, nil
}

// longPath is GetLongPathNameW - every 8.3 short name expanded - or false when it fails, as it
// does for a path whose last component doesn't exist.
func longPath(path string) (string, bool) {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", false
	}
	buffer := make([]uint16, maxPathChars)
	length, err := windows.GetLongPathName(pointer, &buffer[0], uint32(len(buffer)))
	if err != nil || length == 0 || length >= uint32(len(buffer)) {
		return "", false
	}
	return windows.UTF16ToString(buffer[:length]), true
}

// getDriveType is GetDriveTypeW of a drive root such as "C:\", a DRIVE_* value.
func getDriveType(root string) uint32 {
	pointer, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return driveUnknown
	}
	return windows.GetDriveType(pointer)
}

// fileAttributes is GetFileAttributesW - the item's own attributes, a link not followed - or
// invalidFileAttributes (every bit set, the reparse-point bit included) when it can't be read.
func fileAttributes(path string) uint32 {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return invalidFileAttributes
	}
	attributes, err := windows.GetFileAttributes(pointer)
	if err != nil {
		return invalidFileAttributes
	}
	return attributes
}

// openFile opens the file for reading with read sharing only - refused if another process has
// it open for writing, and no one can open it for writing while it is held.
func openFile(full, noun string) (windows.Handle, error) {
	pointer, err := windows.UTF16PtrFromString(full)
	if err != nil {
		return windows.InvalidHandle, readFailure(full, noun, err)
	}
	handle, err := windows.CreateFile(pointer, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_SEQUENTIAL_SCAN, 0)
	if err == nil {
		return handle, nil
	}
	var errno windows.Errno
	errors.As(err, &errno)
	switch errno {
	case windows.ERROR_FILE_NOT_FOUND, windows.ERROR_PATH_NOT_FOUND, windows.ERROR_INVALID_NAME:
		return windows.InvalidHandle, keyFileError(fs.ErrNotExist, full, "%s '%s' was not found.", capitalized(noun), full)
	case windows.ERROR_ACCESS_DENIED:
		return windows.InvalidHandle, keyFileError(fs.ErrPermission, full, "This account may not read %s '%s' (or it is a folder).", noun, full)
	case windows.ERROR_SHARING_VIOLATION:
		return windows.InvalidHandle, keyFileError(ErrBusy, full, "%s '%s' is open for writing by another process.", capitalized(noun), full)
	default:
		return windows.InvalidHandle, keyFileError(err, full, "Could not open %s '%s' (Windows error %d).", noun, full, uint32(errno))
	}
}

// finalPath is GetFinalPathNameByHandleW (FILE_NAME_NORMALIZED | VOLUME_NAME_DOS) - the path of the
// file the handle actually refers to, after every symbolic link, junction, mount point and
// substituted drive is resolved, in long-name form (\\?\C:\...).
func finalPath(file windows.Handle) (string, error) {
	capacity := uint32(512)
	for {
		buffer := make([]uint16, capacity)
		length, err := windows.GetFinalPathNameByHandle(file, &buffer[0], capacity, fileNameNormalized|volumeNameDOS)
		if err != nil {
			return "", err
		}
		if length < capacity {
			return windows.UTF16ToString(buffer[:length]), nil
		}
		if length > maxPathChars {
			return "", windows.ERROR_FILENAME_EXCED_RANGE
		}
		capacity = length // too small: length is the size needed, terminator included
	}
}

// describeSecurity turns a security descriptor's owner and DACL into the rules' winSecurity. owner
// is "" when there is none; daclAbsent is true for a missing or NULL DACL. An ACE's SID is read
// only for the four types whose layout puts it right after the mask - allowed, denied and their
// callback forms - and is "" for every other type (the object ACEs).
func describeSecurity(descriptor *windows.SECURITY_DESCRIPTOR, err error) (winSecurity, error) {
	if err != nil {
		return winSecurity{}, err
	}
	defer runtime.KeepAlive(descriptor) // the owner, DACL and ACEs point into it

	owner, _, err := descriptor.Owner()
	if err != nil {
		return winSecurity{}, err
	}
	security := winSecurity{owner: sidString(owner)}

	dacl, _, err := descriptor.DACL()
	if errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) || (err == nil && dacl == nil) {
		security.daclAbsent = true
		return security, nil
	}
	if err != nil {
		return winSecurity{}, err
	}

	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return winSecurity{}, err
		}
		if ace == nil {
			return winSecurity{}, windows.ERROR_INVALID_ACL
		}
		entry := winACE{aceType: ace.Header.AceType, flags: ace.Header.AceFlags}
		if ace.Header.AceSize >= 8 { // the mask follows the header in every ACE type
			entry.mask = uint32(ace.Mask)
		}
		switch entry.aceType {
		case aceAllowed, aceDenied, aceAllowedCallback, aceDeniedCallback:
			if ace.Header.AceSize > 8 {
				entry.sid = sidString((*windows.SID)(unsafe.Pointer(&ace.SidStart)))
			}
		}
		security.aces = append(security.aces, entry)
	}
	return security, nil
}

// sidString is a SID's string form, or "" if there is none or it isn't valid.
func sidString(sid *windows.SID) string {
	if sid == nil || !sid.IsValid() {
		return ""
	}
	return sid.String()
}

// canonicalSID is a SID string in its canonical form, as ConvertStringSidToSidW reads it (it also
// accepts the SDDL aliases, such as "BA"), or false if it isn't a SID.
func canonicalSID(text string) (string, bool) {
	sid, err := windows.StringToSid(text)
	if err != nil {
		return "", false
	}
	canonical := sidString(sid)
	return canonical, canonical != ""
}

// accountName is the account a SID string names, as DOMAIN\name (or name alone), or "" if it
// names none here. For messages only; for a domain SID it can contact a domain controller.
func accountName(text string) string {
	sid, err := windows.StringToSid(text)
	if err != nil {
		return ""
	}
	account, domain, _, err := sid.LookupAccount("")
	if err != nil {
		return ""
	}
	if domain != "" {
		return domain + `\` + account
	}
	return account
}

func securityFailure(full, item, noun string, err error) error {
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return keyFileError(fs.ErrPermission, full, "%s '%s': this account may not read the permissions of '%s'.", capitalized(noun), full, item)
	}
	var errno windows.Errno
	errors.As(err, &errno)
	return keyFileError(err, full, "%s '%s': could not read the security descriptor of '%s' (Windows error %d).", capitalized(noun), full, item, uint32(errno))
}

// readFailure reports a Win32 call's own failure as the file's.
func readFailure(path, noun string, err error) error {
	return keyFileError(err, path, "Could not read %s '%s': %v.", noun, path, err)
}
