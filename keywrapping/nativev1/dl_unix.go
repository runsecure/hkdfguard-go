//go:build (darwin || linux) && cgo

package nativev1

/*
#cgo linux LDFLAGS: -ldl
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdlib.h>

typedef int32_t (*hg_wrap_fn)(const char*, const uint8_t*, int32_t, uint8_t*, int32_t*);
typedef int32_t (*hg_generate_fn)(const char*, uint8_t*, int32_t*);
typedef int32_t (*hg_harden_fn)(unsigned int);
typedef int32_t (*hg_open_file_fn)(const char*, uint8_t*, int32_t*);

// The native functions are reached through dlsym'd pointers, so cgo needs these trampolines to
// call them. hkdfguard_wrap_dek and hkdfguard_unwrap_dek share one signature.
static int32_t hg_call_wrap(void* fn, const char* service, const uint8_t* in, int32_t in_len, uint8_t* out, int32_t* out_len) {
	return ((hg_wrap_fn)fn)(service, in, in_len, out, out_len);
}

static int32_t hg_call_generate(void* fn, const char* service, uint8_t* out, int32_t* out_len) {
	return ((hg_generate_fn)fn)(service, out, out_len);
}

static int32_t hg_call_harden(void* fn, unsigned int flags) {
	return ((hg_harden_fn)fn)(flags);
}

static int32_t hg_call_open_file(void* fn, const char* path, uint8_t* out, int32_t* out_len) {
	return ((hg_open_file_fn)fn)(path, out, out_len);
}

// The file the dynamic linker mapped the code at addr from, or NULL if it doesn't know the address.
static const char* hg_image_path(void* addr) {
	Dl_info info;
	if (dladdr(addr, &info) == 0)
		return NULL;
	return info.dli_fname;
}
*/
import "C"

import (
	"fmt"
	"runtime"
	"unsafe"
)

// dlLibrary is a dlopen'd native KMS library and its resolved exports.
type dlLibrary struct {
	handle          unsafe.Pointer
	wrap            unsafe.Pointer
	unwrap          unsafe.Pointer
	generateAndWrap unsafe.Pointer
	harden          unsafe.Pointer // hkdfguard_harden_process_with_flags
	openFileFn      unsafe.Pointer // nil when the library predates hkdfguard_open_file
	describe        func(int32) string
}

// dlOpen maps the library at an absolute path, resolving every symbol now.
func dlOpen(path string) (unsafe.Pointer, error) {
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))

	handle := C.dlopen(cpath, C.RTLD_NOW|C.RTLD_LOCAL)
	if handle == nil {
		return nil, fmt.Errorf("dlopen('%s') failed: %s", path, dlError())
	}
	return handle, nil
}

func dlClose(handle unsafe.Pointer) { C.dlclose(handle) }

// dlSym returns the address of an export, or nil if the library has none of that name.
func dlSym(handle unsafe.Pointer, name string) unsafe.Pointer {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	return C.dlsym(handle, cname)
}

func dlError() string {
	if message := C.dlerror(); message != nil {
		return C.GoString(message)
	}
	return "unknown error"
}

// dlImagePath is dladdr: the path of the file the dynamic linker mapped address from, or "" if it
// doesn't know the address. This is what was loaded, as opposed to what was asked for.
func dlImagePath(address unsafe.Pointer) string {
	if address == nil {
		return ""
	}
	if path := C.hg_image_path(address); path != nil {
		return C.GoString(path)
	}
	return ""
}

// bindDL resolves the KMS exports of an opened, verified library. Every platform's library has the
// three DEK calls and hkdfguard_harden_process_with_flags. describe is the platform's status
// descriptions.
//
// hkdfguard_open_file is bound when present. It is not required here, so a release that predates
// it still wraps and unwraps; reading a key file through such a release fails (openFile), rather
// than falling back to a read without the native library's checks.
func bindDL(handle unsafe.Pointer, describe func(int32) string) (*dlLibrary, error) {
	library := &dlLibrary{handle: handle, describe: describe}
	for _, export := range []struct {
		name   string
		target *unsafe.Pointer
	}{
		{"hkdfguard_wrap_dek", &library.wrap},
		{"hkdfguard_unwrap_dek", &library.unwrap},
		{"hkdfguard_generate_and_wrap_dek", &library.generateAndWrap},
		{"hkdfguard_harden_process_with_flags", &library.harden},
	} {
		if *export.target = dlSym(handle, export.name); *export.target == nil {
			return nil, untrusted("The native library has no '%s' export; it is not the HkdfGuard native library.", export.name)
		}
	}
	library.openFileFn = dlSym(handle, "hkdfguard_open_file")
	return library, nil
}

// bytePointer is a C pointer to b's first byte, or nil for an empty slice; the native library
// rejects a nil buffer with its invalid-argument status.
func bytePointer(b []byte) *C.uint8_t {
	if len(b) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(unsafe.SliceData(b)))
}

func (l *dlLibrary) wrapDEK(service string, dek, out []byte) (int32, int32) {
	return l.callWrap(l.wrap, service, dek, out)
}

func (l *dlLibrary) unwrapDEK(service string, wrapped, out []byte) (int32, int32) {
	return l.callWrap(l.unwrap, service, wrapped, out)
}

func (l *dlLibrary) callWrap(fn unsafe.Pointer, service string, in, out []byte) (int32, int32) {
	cservice := C.CString(service)
	defer C.free(unsafe.Pointer(cservice))

	outLen := C.int32_t(len(out))
	status := C.hg_call_wrap(fn, cservice, bytePointer(in), C.int32_t(len(in)), bytePointer(out), &outLen)
	runtime.KeepAlive(in)
	runtime.KeepAlive(out)
	return int32(status), int32(outLen)
}

func (l *dlLibrary) generateAndWrapDEK(service string, out []byte) (int32, int32) {
	cservice := C.CString(service)
	defer C.free(unsafe.Pointer(cservice))

	outLen := C.int32_t(len(out))
	status := C.hg_call_generate(l.generateAndWrap, cservice, bytePointer(out), &outLen)
	runtime.KeepAlive(out)
	return int32(status), int32(outLen)
}

// openFile is hkdfguard_open_file(const char* path, uint8_t* out, int* out_len).
func (l *dlLibrary) openFile(path string, out []byte) (int32, int32, error) {
	if l.openFileFn == nil {
		return 0, 0, unsupported("The installed HkdfGuard native KMS library has no 'hkdfguard_open_file' export, so it can't read key files; install a current release.")
	}
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))

	outLen := C.int32_t(len(out))
	status := C.hg_call_open_file(l.openFileFn, cpath, bytePointer(out), &outLen)
	runtime.KeepAlive(out)
	return int32(status), int32(outLen), nil
}

func (l *dlLibrary) describeStatus(status int32) string { return l.describe(status) }

// hardenProcess is hkdfguard_harden_process_with_flags(unsigned int flags).
func (l *dlLibrary) hardenProcess(flags uint32) int32 {
	return int32(C.hg_call_harden(l.harden, C.uint(flags)))
}
