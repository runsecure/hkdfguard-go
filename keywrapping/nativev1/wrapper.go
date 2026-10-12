package nativev1

import (
	"context"
	"fmt"
	"math"

	"github.com/runsecure/hkdfguard-go"
)

// DEKLength is the length, in bytes, of every DEK the native library wraps and unwraps.
const DEKLength = 32

// statusOK is the status every platform's native library returns on success.
const statusOK = 0

// kmsLibrary is one platform's native HkdfGuard KMS library: hkdfguard_wrap_dek,
// hkdfguard_unwrap_dek and hkdfguard_generate_and_wrap_dek, identical in shape across platforms,
// though each library's negative status codes mean different things.
type kmsLibrary interface {
	// wrapDEK wraps dek under service's KEK into out. On success written is the payload length;
	// on a buffer-too-small failure, the required capacity.
	wrapDEK(service string, dek, out []byte) (status, written int32)

	// unwrapDEK recovers the DEK from wrapped into out, under the same service it was wrapped for.
	unwrapDEK(service string, wrapped, out []byte) (status, written int32)

	// generateAndWrapDEK generates a fresh DEK and wraps it into out; the plaintext DEK never
	// crosses this boundary.
	generateAndWrapDEK(service string, out []byte) (status, written int32)

	// describeStatus is what a non-zero status means on this platform, or "" if unknown.
	describeStatus(status int32) string

	// hardenProcess applies process hardening, or returns an error wrapping
	// ErrUnsupportedPlatform when this platform's library has no such call.
	hardenProcess() (int32, error)
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

var _ hkdfguard.KeyWrapper = (*KeyWrapper)(nil)

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
// it into result and returning its length (always DEKLength). On any failure result is zeroed, so
// nothing the native call may have left there survives.
func (w *KeyWrapper) Unwrap(ctx context.Context, wrapped, result []byte) (int, error) {
	if err := checkCall(ctx, wrapped, result); err != nil {
		return 0, err
	}

	status, written := w.library.unwrapDEK(w.service, wrapped, result)
	n, err := w.complete("unwrap", status, written, result)
	if err != nil {
		hkdfguard.Wipe(result)
	}
	return n, err
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

// HardenProcess hardens the whole process through the native KMS library, loading it if it isn't
// already. DEKs pass through this process's memory, so a core dump, or another process of the
// same user attaching a debugger or reading /proc/<pid>/mem, could recover them. On Linux it sets
// the core dump limit to zero (hard limit included) and clears the process's dumpable flag.
//
// It is opt-in because it is process-wide: debuggers and crash dumps stop working for the
// application. Call it once, early, and after any privilege drop - the kernel resets the dumpable
// flag when a process's credentials change. It does not stop root or a process with
// CAP_SYS_PTRACE, and it does not keep memory out of swap; those are host settings (no swap or
// encrypted swap, kernel.yama.ptrace_scope of 2 or 3, and for a systemd service LimitCORE=0 and
// ProtectProc=invisible).
//
// It returns an error wrapping ErrUnsupportedPlatform off Linux, and a *StatusError if the
// hardening failed - treat that as a reason not to start.
func HardenProcess() error {
	library, err := hostLibrary()
	if err != nil {
		return err
	}
	return hardenProcess(library)
}

func hardenProcess(library kmsLibrary) error {
	status, err := library.hardenProcess()
	if err != nil {
		return err
	}
	if status != statusOK {
		return &StatusError{Op: "process hardening", Status: status, Description: library.describeStatus(status)}
	}
	return nil
}
