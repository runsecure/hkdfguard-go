//go:build darwin && cgo

package nativev1

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdlib.h>
#include <string.h>

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

	home, _ := os.UserHomeDir()
	path, isSystem, err := macChoosePath(darwinProbe, home)
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

	library, err := bindDL(handle, "", macStatusDescriptions)
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
