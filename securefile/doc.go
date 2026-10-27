// Package securefile reads a wrapped-key file only from where no untrusted account could have
// written or replaced it - the native library's hkdfguard_open_file checks, made in Go - for a key
// wrapper with no native library to read through, such as keywrapping/awskms. It is the Go port of
// the .NET HkdfGuard.SecureFile library, and applies the same rules as it and the Node, Python and
// Java ports.
//
// ReadTrustedKeyFile reads; KeyFileTrust says who, besides the operating system's administrators,
// may have written the file. It runs on Windows, Linux and Apple silicon Macs with no native
// HkdfGuard library installed and without cgo: on Linux and macOS the checks are lstat, readlink,
// open with O_NOFOLLOW and fstat (golang.org/x/sys/unix); on Windows they are Win32 calls - owner
// and DACL, reparse points, final path, drive type - made through golang.org/x/sys/windows.
//
// Whoever can replace a key file - and can also wrap under the KEK, as anyone allowed to encrypt
// with a network KMS key can - chooses the DEK new data is encrypted under. So a key file and every
// folder above it must be owned by a trusted principal, and no one else may write, replace, rename
// or re-permission any of them:
//
//   - Windows: the file must be on a local fixed drive, reached through real folders (no symbolic
//     link, junction, mount point or substituted drive; an 8.3 short name that exists is expanded
//     first), and it and every folder above it must be owned by, and modifiable only by, SYSTEM,
//     Administrators, TrustedInstaller or a trusted principal. The drive root is held only to what
//     could rename or delete what is beneath it. The file's owner and DACL are read through the
//     handle it is read from, opened with read sharing only.
//   - Linux and Apple silicon macOS: it and every directory above it must be owned by root or a
//     trusted user and writable by nobody else (by its group only if that group is trusted), and
//     only symbolic links a trusted user owns are followed; the resolved path is then opened with
//     O_NOFOLLOW and must still be a regular file.
//   - Everywhere: the contents must be 1 to hkdfguard.MaxWrappedKeyBytes bytes - never more than one
//     byte past that is read - and must not look like an unwrapped key (exactly 32 bytes, or a
//     32-byte key as hex or base64).
//
// A refusal is a *KeyFileError, matchable with errors.Is against fs.ErrNotExist, fs.ErrPermission
// (a location that isn't trusted matches both ErrUntrusted and fs.ErrPermission),
// hkdfguard.ErrInvalidKeyFile or ErrBusy.
//
// This module does not depend on, or load, the native KMS library or its loader.
package securefile
