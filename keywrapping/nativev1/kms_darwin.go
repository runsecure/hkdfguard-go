//go:build darwin && cgo

package nativev1

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <unistd.h>
#include <errno.h>

// The effective user's home folder from the account database (getpwuid_r), never from $HOME.
// Copies it into out (cap bytes) and returns 0, or returns -1 if there is no entry, it doesn't
// fit, or the lookup failed.
static int hg_account_home(char* out, size_t cap) {
	struct passwd pwd;
	struct passwd* result = NULL;
	size_t size = 16 * 1024;
	for (;;) {
		char* buf = malloc(size);
		if (buf == NULL)
			return -1;
		int rc = getpwuid_r(geteuid(), &pwd, buf, size, &result);
		if (rc == ERANGE && size < 1024 * 1024) {
			free(buf);
			size *= 2;
			continue;
		}
		int ok = rc == 0 && result != NULL && pwd.pw_dir != NULL && strlen(pwd.pw_dir) < cap;
		if (ok)
			strcpy(out, pwd.pw_dir);
		free(buf);
		return ok ? 0 : -1;
	}
}

// SecStaticCodeCheckValidity against requirement, for every architecture in the file, with strict
// validation. 0 (errSecSuccess) if valid and satisfied, otherwise the failing OSStatus.
static int32_t hg_check_code_signature(const char* path, const char* requirement_text) {
	CFURLRef url = NULL;
	SecStaticCodeRef code = NULL;
	CFStringRef requirement_string = NULL;
	SecRequirementRef requirement = NULL;
	OSStatus status = -1;

	url = CFURLCreateFromFileSystemRepresentation(NULL, (const UInt8*)path, (CFIndex)strlen(path), false);
	if (url == NULL)
		goto done;

	status = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code);
	if (status != errSecSuccess)
		goto done;

	requirement_string = CFStringCreateWithCString(NULL, requirement_text, kCFStringEncodingUTF8);
	if (requirement_string == NULL) {
		status = -1;
		goto done;
	}

	status = SecRequirementCreateWithString(requirement_string, kSecCSDefaultFlags, &requirement);
	if (status != errSecSuccess)
		goto done;

	status = SecStaticCodeCheckValidity(code, kSecCSCheckAllArchitectures | kSecCSStrictValidate, requirement);

done:
	if (requirement != NULL) CFRelease(requirement);
	if (requirement_string != NULL) CFRelease(requirement_string);
	if (code != NULL) CFRelease(code);
	if (url != NULL) CFRelease(url);
	return status;
}
*/
import "C"

import (
	"io"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// loadPlatformLibrary verifies and loads the macOS native KMS library (see macpolicy.go).
func loadPlatformLibrary() (kmsLibrary, error) {
	osVersion, err := unix.Sysctl("kern.osproductversion")
	if err != nil {
		osVersion = ""
	}
	if err := macRequireSupportedPlatform(runtime.GOARCH, osVersion); err != nil {
		return nil, err
	}

	path, isSystem, err := macChoosePath(darwinProbe, darwinAccountHome())
	if err != nil {
		return nil, err
	}

	trustedOwners := []uint32{0}
	if !isSystem {
		trustedOwners = append(trustedOwners, uint32(os.Geteuid()))
	}
	if err := macVerifyLocation(path, darwinStatus, trustedOwners); err != nil {
		return nil, err
	}
	if err := macVerifySignature(path, darwinCheckCodeSignature); err != nil {
		return nil, err
	}
	if err := darwinRequireMinimumVersion(path); err != nil {
		return nil, err
	}
	if err := macRefuseShadowing(os.Getenv, darwinExists); err != nil {
		return nil, err
	}

	// dyld may still map a different file than the path asks for (see macpolicy.go), so the loaded
	// image is checked and, if it isn't the verified file, unloaded. The library's own dependencies
	// are absolute system paths and need no such check.
	handle, err := dlOpen(path)
	if err != nil {
		return nil, untrustedCause(err, "'%s' passed verification but could not be loaded", path)
	}
	if err := macVerifyLoadedImage(path, dlImagePath(dlSym(handle, probeExport))); err != nil {
		dlClose(handle)
		return nil, err
	}

	library, err := bindDL(handle, describeMacStatus)
	if err != nil {
		dlClose(handle)
		return nil, err
	}
	return library, nil
}

// darwinProbe is lstat's errno for a path whose existence is only being probed; 0 if it exists.
func darwinProbe(path string) int {
	var st unix.Stat_t
	return errnoOf(unix.Lstat(path, &st))
}

// darwinStatus is lstat: it describes the path itself, never what a symbolic link points to.
func darwinStatus(path string) (fileStatus, error) {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return fileStatus{}, untrustedCause(err, "lstat('%s') failed", path)
	}
	return statusFromMode(st.Uid, st.Gid, uint32(st.Mode)), nil
}

func darwinExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func darwinCheckCodeSignature(path, requirement string) int32 {
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))
	crequirement := C.CString(requirement)
	defer C.free(unsafe.Pointer(crequirement))

	return int32(C.hg_check_code_signature(cpath, crequirement))
}

// darwinAccountHome is the per-user install's base folder: the effective user's home from the
// account database, or "" if there is none usable.
func darwinAccountHome() string {
	buf := make([]byte, 4096)
	ok := C.hg_account_home((*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf))) == 0
	home := ""
	if ok {
		home = C.GoString((*C.char)(unsafe.Pointer(&buf[0])))
	}
	return macHomeFromAccount(home, ok)
}

// darwinRequireMinimumVersion reads the start of the verified file and refuses a release older
// than macMinimumLibraryVersion.
func darwinRequireMinimumVersion(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return untrustedCause(err, "could not open '%s' to read its version", path)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, macVersionReadLimit))
	if err != nil {
		return untrustedCause(err, "could not read '%s' to find its version", path)
	}
	return macRequireMinimumVersion(path, data)
}
