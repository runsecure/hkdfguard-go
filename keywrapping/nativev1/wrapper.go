package nativev1

import (
	"context"
	"fmt"
	"io/fs"
	"math"
	"strings"

	"github.com/runsecure/hkdfguard-go"
)

// DEKLength is the length, in bytes, of every DEK the native library wraps and unwraps.
const DEKLength = 32

// statusOK is the status every platform's native library returns on success.
const statusOK = 0

// kmsLibrary is one platform's native HkdfGuard KMS library: hkdfguard_wrap_dek,
// hkdfguard_unwrap_dek, hkdfguard_generate_and_wrap_dek and hkdfguard_open_file, identical in shape
// across platforms, as are their status codes (status.go).
type kmsLibrary interface {
	// wrapDEK wraps dek under service's KEK into out. On success written is the payload length;
	// on a buffer-too-small failure, the required capacity.
	wrapDEK(service string, dek, out []byte) (status, written int32)

	// unwrapDEK recovers the DEK from wrapped into out, under the same service it was wrapped for.
	unwrapDEK(service string, wrapped, out []byte) (status, written int32)

	// generateAndWrapDEK generates a fresh DEK and wraps it into out; the plaintext DEK never
	// crosses this boundary.
	generateAndWrapDEK(service string, out []byte) (status, written int32)

	// openFile reads the key file at path into out through hkdfguard_open_file, without unwrapping
	// it. On success read is the number of bytes read. err wraps ErrUnsupportedPlatform when the
	// loaded library has no such call.
	openFile(path string, out []byte) (status, read int32, err error)

	// describeStatus is what a non-zero status means on this platform, or "" if unknown.
	describeStatus(status int32) string

	// hardenProcess is hkdfguard_harden_process_with_flags(flags): process hardening, with flags a
	// bitwise OR of the HKDFGUARD_HARDEN_* flags. Every platform's library has it.
	hardenProcess(flags uint32) int32
}

// KeyWrapper protects (Wrap) a DEK, or reveals (Unwrap) a previously-wrapped one, through the
// current OS's native HkdfGuard KMS library, under the KEK its service name identifies. Since
// Unwrap takes its wrapped payload as an argument, one KeyWrapper handles both directions, and any
// number of different payloads sharing the same service. The native ABI has no concept of AAD.
//
// The native calls are local and synchronous: ctx is checked before each call, but a call that
// has started runs to completion. A KeyWrapper is safe for concurrent use.
type KeyWrapper struct {
	service string
	library kmsLibrary
}

var (
	_ hkdfguard.KeyWrapper    = (*KeyWrapper)(nil)
	_ hkdfguard.KeyFileReader = (*KeyWrapper)(nil)
)

// New returns a KeyWrapper for the KEK identified by serviceName - 1 to 128 ASCII letters, digits
// or '.', not starting with '.' and without ".." (see hkdfguard.ValidateServiceName). The name is
// checked before anything else, so a bad one never reaches native code.
//
// The first New in a process verifies and loads the native library; a failure (an error wrapping
// ErrNotInstalled, ErrUntrusted or ErrUnsupportedPlatform) isn't cached, so a fixed installation
// is picked up by the next call.
func New(serviceName string) (*KeyWrapper, error) {
	if err := hkdfguard.ValidateServiceName(serviceName); err != nil {
		return nil, err
	}

	library, err := hostLibrary()
	if err != nil {
		return nil, err
	}
	return newKeyWrapper(serviceName, library)
}

func newKeyWrapper(serviceName string, library kmsLibrary) (*KeyWrapper, error) {
	if err := hkdfguard.ValidateServiceName(serviceName); err != nil {
		return nil, err
	}
	return &KeyWrapper{service: serviceName, library: library}, nil
}

// ServiceName is the service name identifying this wrapper's KEK.
func (w *KeyWrapper) ServiceName() string { return w.service }

// Wrap wraps plaintext (a DEKLength-byte key) under this service's KEK, writing the payload into
// result and returning its length. hkdfguard.MaxWrappedKeyBytes is always enough room.
func (w *KeyWrapper) Wrap(ctx context.Context, plaintext, result []byte) (int, error) {
	if err := checkCall(ctx, plaintext, result); err != nil {
		return 0, err
	}

	status, written := w.library.wrapDEK(w.service, plaintext, result)
	return w.complete("wrap", status, written, result)
}

// Unwrap reveals the DEK in wrapped, which must have been wrapped under this same service, writing
// it into result and returning its length, which is always DEKLength: a success revealing any
// other count is refused rather than handed on as a short or padded key. On any failure result is
// zeroed, so nothing the native call may have left there survives.
func (w *KeyWrapper) Unwrap(ctx context.Context, wrapped, result []byte) (int, error) {
	if err := checkCall(ctx, wrapped, result); err != nil {
		return 0, err
	}

	status, written := w.library.unwrapDEK(w.service, wrapped, result)
	n, err := w.complete("unwrap", status, written, result)
	if err == nil && n != DEKLength {
		err = fmt.Errorf("nativev1: native KMS unwrap for service '%s' revealed %d bytes; a DEK is always %d", w.service, n, DEKLength)
	}
	if err != nil {
		hkdfguard.Wipe(result)
		return 0, err
	}
	return n, nil
}

// GenerateAndWrap generates a fresh DEK inside the native library and wraps it under this
// service's KEK, writing the payload into result and returning its length. The plaintext DEK never
// reaches this process; Unwrap reveals it.
func (w *KeyWrapper) GenerateAndWrap(ctx context.Context, result []byte) (int, error) {
	if err := checkCall(ctx, nil, result); err != nil {
		return 0, err
	}

	status, written := w.library.generateAndWrapDEK(w.service, result)
	return w.complete("generate-and-wrap", status, written, result)
}

// ReadKeyFile reads a key file through the native library's hkdfguard_open_file rather than Go
// file I/O, returning its bytes still wrapped - ready for Unwrap. Nothing is unwrapped and no KEK
// is touched, so any service's wrapper reads any key file. Besides the size and format checks, the
// native library refuses a file another account could have written or replaced - its path, owner
// and permissions are checked the way only the platform can - and one holding what looks like an
// unwrapped key. dek.Build reads every key file this way (it implements hkdfguard.KeyFileReader).
//
// A refusal is a *KeyFileError naming the path, status and its meaning; it satisfies
// errors.Is(err, fs.ErrNotExist) for a missing file, errors.Is(err, fs.ErrPermission) for one this
// account may not read or whose location isn't trusted, and errors.Is(err,
// hkdfguard.ErrInvalidKeyFile) for one that isn't a wrapped key. An empty path never reaches the
// native library.
func (w *KeyWrapper) ReadKeyFile(ctx context.Context, path string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return openKeyFile(w.library, path)
}

// openKeyFile is hkdfguard_open_file returning the bytes read, or an error. Every platform's
// wrapped DEK fits in hkdfguard.MaxWrappedKeyBytes (Windows 132, Linux 276, macOS 125 bytes), so
// one buffer never needs the size probe.
func openKeyFile(library kmsLibrary, path string) ([]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("nativev1: the key file path is empty: %w", fs.ErrInvalid)
	}
	if strings.IndexByte(path, 0) >= 0 {
		return nil, fmt.Errorf("nativev1: the key file path '%s' contains a NUL byte: %w", path, fs.ErrInvalid)
	}

	buffer := make([]byte, hkdfguard.MaxWrappedKeyBytes)
	status, read, err := library.openFile(path, buffer)
	if err != nil {
		return nil, err
	}
	if status != statusOK {
		return nil, &KeyFileError{Path: path, Status: status, Description: library.describeStatus(status)}
	}
	if read <= 0 || int(read) > len(buffer) {
		return nil, fmt.Errorf("nativev1: native KMS open-file for '%s' reported %d bytes read into a %d-byte buffer", path, read, len(buffer))
	}
	return buffer[:read:read], nil
}

// checkCall refuses a cancelled call, and buffers whose length the native int32 can't carry,
// before any native call is made.
func checkCall(ctx context.Context, input, result []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(input) > math.MaxInt32 || len(result) > math.MaxInt32 {
		return fmt.Errorf("nativev1: buffer longer than %d bytes", math.MaxInt32)
	}
	return nil
}

// complete turns a native status into a byte count or a *StatusError. A success claiming more
// bytes than result holds (or a negative count) is refused rather than trusted.
func (w *KeyWrapper) complete(op string, status, written int32, result []byte) (int, error) {
	if status != statusOK {
		return 0, &StatusError{Op: op, Service: w.service, Status: status, Description: w.library.describeStatus(status)}
	}
	if written < 0 || int(written) > len(result) {
		return 0, fmt.Errorf("nativev1: native KMS %s for service '%s' reported %d bytes written into a %d-byte buffer", op, w.service, written, len(result))
	}
	return int(written), nil
}
