//go:build linux && cgo

package nativev1

/*
#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <stdlib.h>

// The path the dynamic linker recorded for the already-loaded object it would bind soname to, or
// NULL if no such object is loaded. Never loads anything. The returned string belongs to the
// linker's link map; copy it before anything else is unloaded.
static const char* hg_loaded_path(const char* soname, void** handle_out) {
	void* handle = dlopen(soname, RTLD_LAZY | RTLD_NOLOAD);
	*handle_out = handle;
	if (handle == NULL)
		return NULL;

	struct link_map* map = NULL;
	if (dlinfo(handle, RTLD_DI_LINKMAP, &map) != 0 || map == NULL)
		return NULL;
	return map->l_name;
}
*/
import "C"

import (
	"os"
	"runtime"
	"unsafe"
)

// loadPlatformLibrary verifies and loads the Linux native KMS library (see linuxpolicy.go).
func loadPlatformLibrary() (kmsLibrary, error) {
	candidates, err := linuxCandidatePaths(runtime.GOARCH)
	if err != nil {
		return nil, err
	}
	chosen, err := linuxChoosePath(candidates, linuxProbe)
	if err != nil {
		return nil, err
	}

	path, err := linuxTrustedFile(chosen)
	if err != nil {
		return nil, err
	}
	if err := linuxVerifyContent(path, sha256File, linuxKnownReleases); err != nil {
		return nil, err
	}

	initial, err := os.ReadFile("/proc/self/environ")
	if err != nil {
		initial = nil
	}
	environment := linuxReadEnvironment(os.LookupEnv, initial)
	if err := linuxVerifyEnvironment(environment, func(p string, expected fileType) error {
		_, _, err := linuxResolveTrusted(p, expected, linuxStatus, linuxReadLink, true)
		return err
	}); err != nil {
		return nil, err
	}

	handle, err := dlOpen(path)
	if err != nil {
		return nil, untrustedCause(err, "'%s' passed verification but could not be loaded", path)
	}
	library, err := linuxVerifyLoaded(handle, path)
	if err != nil {
		dlClose(handle)
		return nil, err
	}
	return library, nil
}

// linuxVerifyLoaded checks what the dynamic linker actually mapped - the library itself and its
// whole dependency closure - then binds the library's exports.
func linuxVerifyLoaded(handle unsafe.Pointer, path string) (kmsLibrary, error) {
	loaded := dlImagePath(dlSym(handle, probeExport))
	if loaded != "" {
		resolved, err := linuxTrustedFile(loaded)
		if err != nil {
			return nil, err
		}
		loaded = resolved
	}
	if err := linuxVerifyLoadedImage(path, loaded); err != nil {
		return nil, err
	}
	if err := linuxVerifyDependencies(path, elfReadNeededFile, linuxLoadedPath, linuxTrustedFile); err != nil {
		return nil, err
	}
	return bindDL(handle, "hkdfguard_harden_process", linuxStatusDescriptions)
}

// linuxLoadedPath is the path the dynamic linker recorded for the already-loaded object it would
// bind soname to, and false if no such object is loaded. It never loads anything.
func linuxLoadedPath(soname string) (string, bool) {
	csoname := C.CString(soname)
	defer C.free(unsafe.Pointer(csoname))

	var handle unsafe.Pointer
	cpath := C.hg_loaded_path(csoname, &handle)
	var path string
	if cpath != nil {
		path = C.GoString(cpath)
	}
	if handle != nil {
		// RTLD_NOLOAD still took a reference; give it back.
		C.dlclose(handle)
	}
	return path, path != ""
}
