// Package nativev1 implements hkdfguard.KeyWrapper over the current OS's native HkdfGuard KMS
// library - the Go port of the .NET HkdfGuard.KeyWrapping.V1 library. The KEK is a TPM2, Secure
// Enclave, or Platform Crypto Provider key held entirely outside this process, identified only by
// a service name; the native library owns the KEK, the wrapped payload's format, and its own key
// derivation.
//
// The native library receives every plaintext DEK on unwrap and chooses every "random" DEK on
// generate-and-wrap, so loading an impostor would hand over every key. It is therefore never found
// by a search: each platform's library is installed separately, to a fixed location, and loaded
// only from there after verification:
//
//	Windows: %ProgramFiles%\HkdfGuard\v1\HkdfGuard.dll
//	macOS:   /Library/Application Support/HkdfGuard/v1/libhkdfguard_v1.dylib, or
//	         ~/.hkdfguard/v1/libhkdfguard_v1.dylib (only when there is no system install)
//	Linux:   /usr/lib/<multiarch>/libhkdfguard.so.1, or /usr/lib64/libhkdfguard.so.1
//
// Verification checks the ownership and permissions of every path component, the platform code
// signature (Authenticode on Windows, Developer ID on macOS) or a pinned SHA-256 (Linux), the
// dynamic linker's environment, and - after loading - which file the dynamic linker actually
// mapped. Any failed check returns an error wrapping ErrUntrusted; there is deliberately no
// fallback and no override.
//
// On macOS and Linux the library is loaded through cgo (dlopen), so those builds need
// CGO_ENABLED=1 and a C toolchain. Windows needs neither.
//
// Key files are read through the native library too: KeyWrapper implements
// hkdfguard.KeyFileReader, so dek.Build reads each key file with hkdfguard_open_file instead of Go
// file I/O. Besides checking the file's size and format, the native library refuses a file another
// account could have written or replaced (a link or reparse point in its path, an 8.3 short name or
// network path on Windows, or a file or folder writable by anyone else) and one holding what looks
// like an unwrapped key. A refusal is a *KeyFileError, matchable with errors.Is against
// fs.ErrNotExist, fs.ErrPermission or hkdfguard.ErrInvalidKeyFile.
//
// Every platform's library returns the same status codes (the native header's HKDFGUARD_ERR_*
// table); a *StatusError or *KeyFileError carries the code and what it means on this platform.
//
// No call here creates a KEK: a service must be provisioned first with
// hkdfguard provision --service-name <name> (the tool is %ProgramFiles%\HkdfGuard\v1\hkdfguard.exe
// on Windows and /usr/bin/hkdfguard on Linux; on macOS it keeps the name hkdfguard-v1-initialize).
package nativev1
