//go:build windows

package nativev1

import (
	"errors"
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// These harden this very test process, so they only run when asked for:
// HKDFGUARD_TEST_PROCESS_HARDENING=1 with the native library installed. Run each in a test binary
// of its own, since what one does to the process outlives it:
//
//	HKDFGUARD_TEST_PROCESS_HARDENING=1 go test -run 'TestWindowsNative_HardenProcess_ClosesTheProcessToItsOwnAccount$' -v
//	HKDFGUARD_TEST_PROCESS_HARDENING=1 go test -run 'TestWindowsNative_HardenProcess_WithRequireProtectedSignature' -v

var procCreateThread = windows.NewLazySystemDLL("kernel32.dll").NewProc("CreateThread")
var procSleep = windows.NewLazySystemDLL("kernel32.dll").NewProc("Sleep")

func requireProcessHardeningOptIn(t *testing.T) {
	t.Helper()
	if os.Getenv(processHardeningVariable) != "1" {
		t.Skipf("hardens the test process itself; set %s=1 to run it", processHardeningVariable)
	}
	installedWindowsLibraryPath(t)
}

// openOwnProcess is OpenProcess(access, FALSE, this process) and its error; the handle is closed.
func openOwnProcess(access uint32) error {
	handle, err := windows.OpenProcess(access, false, windows.GetCurrentProcessId())
	if err == nil {
		windows.CloseHandle(handle)
	}
	return err
}

// openThreadContext is OpenThread(THREAD_GET_CONTEXT, FALSE, id) and its error; the handle is closed.
func openThreadContext(id uint32) error {
	handle, err := windows.OpenThread(windows.THREAD_GET_CONTEXT, false, id)
	if err == nil {
		windows.CloseHandle(handle)
	}
	return err
}

// withNewThread starts a fresh OS thread - suspended, never Go's - and calls check with its id. It
// is certainly created after whatever ran before, unlike a thread the Go runtime might reuse.
func withNewThread(t *testing.T, check func(id uint32)) {
	t.Helper()
	var id uint32
	// The thread would run Sleep(0); it is created suspended and only resumed to let it exit.
	handle, _, err := procCreateThread.Call(0, 0, procSleep.Addr(), 0, windows.CREATE_SUSPENDED, uintptr(unsafe.Pointer(&id)))
	if handle == 0 {
		t.Fatalf("CreateThread: %v", err)
	}
	defer func() {
		windows.ResumeThread(windows.Handle(handle))
		windows.WaitForSingleObject(windows.Handle(handle), windows.INFINITE)
		windows.CloseHandle(windows.Handle(handle))
	}()
	check(id)
}

// The process's access list then grants its own account only query, synchronize and terminate - so
// even this process, asking without SeDebugPrivilege, can no longer open itself to read its memory,
// though it can still query it.
func TestWindowsNative_HardenProcess_ClosesTheProcessToItsOwnAccount(t *testing.T) {
	requireProcessHardeningOptIn(t)

	if err := HardenProcess(); err != nil {
		t.Fatal(err)
	}

	if err := openOwnProcess(windows.PROCESS_VM_READ); !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Errorf("OpenProcess(PROCESS_VM_READ) = %v, want ERROR_ACCESS_DENIED", err)
	}
	if err := openOwnProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION); err != nil {
		t.Errorf("OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION) = %v, want a handle", err)
	}
	// This goroutine's thread existed when the hardening ran.
	if err := openThreadContext(windows.GetCurrentThreadId()); !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Errorf("OpenThread(THREAD_GET_CONTEXT) on an existing thread = %v, want ERROR_ACCESS_DENIED", err)
	}
	// What the plain call leaves open: a thread started afterwards keeps the default access.
	withNewThread(t, func(id uint32) {
		t.Logf("OpenThread(THREAD_GET_CONTEXT) on a thread started after the plain call: %v (nil: still open to this account)", openThreadContext(id))
	})

	// Idempotent: hardening an already hardened process succeeds.
	if err := HardenProcess(); err != nil {
		t.Errorf("second HardenProcess: %v", err)
	}
}

// The strict form: a console process sharing no named objects - this test binary - can meet
// RequireProtectedSignature, and threads started afterwards are closed too.
func TestWindowsNative_HardenProcess_WithRequireProtectedSignature_ClosesLaterThreadsToo(t *testing.T) {
	requireProcessHardeningOptIn(t)

	if err := HardenProcessWithOptions(RequireProtectedSignature); err != nil {
		t.Fatal(err)
	}

	if err := openOwnProcess(windows.PROCESS_VM_READ); !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Errorf("OpenProcess(PROCESS_VM_READ) = %v, want ERROR_ACCESS_DENIED", err)
	}
	withNewThread(t, func(id uint32) {
		if err := openThreadContext(id); !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			t.Errorf("OpenThread(THREAD_GET_CONTEXT) on a thread started afterwards = %v, want ERROR_ACCESS_DENIED", err)
		}
	})
}
