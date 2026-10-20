package nativev1

import "fmt"

// HardenProcessOptions says how strict HardenProcessWithOptions is: a bitmask, zero or more of the
// options below OR'd together. The zero value is the plain hardening HardenProcess applies.
type HardenProcessOptions uint32

const (
	// RequireProtectedSignature fails the hardening unless no other process of the same user can
	// attach a debugger to, or inject code into, this process - what the native command-line tools
	// themselves require. It is the native HKDFGUARD_HARDEN_REQUIRE_PROTECTED_SIGNATURE flag (0x1,
	// the same bit on every platform).
	//
	// On Windows it also closes everything the process creates afterwards (threads, child
	// processes, named pipes and other named objects) to its own user, so use it in a service that
	// shares no objects with other processes by name. On macOS it fails unless the host executable
	// is signed with the Hardened Runtime and without the get-task-allow or DYLD_* entitlements, so
	// unsigned or ad-hoc signed binaries (go run, go test, a plain go build) can't use it. On Linux
	// it adds nothing: the plain call already guarantees it.
	RequireProtectedSignature HardenProcessOptions = 0x1

	// knownHardenProcessOptions is every option this package defines.
	knownHardenProcessOptions = RequireProtectedSignature
)

// HardenProcess applies the plain process hardening (no options), loading the native KMS library
// if it isn't already. It is HardenProcessWithOptions(0); see there for what it does.
func HardenProcess() error {
	return HardenProcessWithOptions(0)
}

// HardenProcessWithOptions is opt-in hardening of the whole process, through the native KMS
// library's hkdfguard_harden_process_with_flags, loading the library if it isn't already. DEKs pass
// through this process's memory, so a crash dump, or another process of the same user attaching a
// debugger or reading its memory, could recover them. The native library never does this on its
// own: it changes process-wide state the application owns. What it does:
//
//   - Windows: crash reports leave out the heap (WerSetFlags NOHEAP), and the process's and its
//     existing threads' access lists are replaced so that only SYSTEM may read or write its memory,
//     inject threads or duplicate its handles - the account it runs as keeps only query,
//     synchronize and terminate. Threads started later keep the default access unless
//     RequireProtectedSignature is passed; call it early, before starting worker threads.
//   - Linux: the core dump limit is set to zero (hard limit included) and the process's dumpable
//     flag is cleared, which also stops ptrace and /proc/<pid>/mem access by other processes of the
//     same user.
//   - macOS: core dumps are disabled and debugger attachment is denied; the host executable's code
//     signature decides whether code injection is possible, which the library can check but not
//     change. Without RequireProtectedSignature a weak signature is only logged.
//
// It is opt-in because it is process-wide: debuggers, crash dumps and core dumps stop working for
// the application. Call it once, early, and after any privilege drop (on Linux the kernel resets the
// dumpable flag when a process's credentials change). It is a same-user barrier: it does not stop
// administrators, root, SYSTEM, a process with CAP_SYS_PTRACE or SeDebugPrivilege, or the kernel,
// and it does not keep memory out of swap, the page file or hibernation files; those are host
// settings (on Linux: no swap or encrypted swap, kernel.yama.ptrace_scope of 2 or 3, and for a
// systemd service LimitCORE=0 and ProtectProc=invisible).
//
// Go and Windows threads: the Go runtime starts OS threads before main runs, and keeps starting
// more whenever it needs them (a goroutine blocked in a system call or cgo call, more runnable
// goroutines, the garbage collector) - an application cannot call this "before starting threads".
// The plain call closes every thread that exists when it runs; any thread the runtime starts later
// keeps the default access, which lets other processes of the same user suspend it and read or
// change its registers - enough to hijack it. So on Windows, call it as early as possible (the first thing in main), and use
// RequireProtectedSignature in a service, which closes threads started later too.
//
// It returns an error, before any native call, for an option this package doesn't define; a
// *StatusError if the hardening failed, or the process can't meet RequireProtectedSignature -
// treat either as a reason not to start; and the library loader's errors (ErrNotInstalled,
// ErrUntrusted, ErrUnsupportedPlatform) if the native library can't be loaded.
func HardenProcessWithOptions(options HardenProcessOptions) error {
	// Checked before loading the library, so an unknown option never reaches native code (which
	// would refuse it anyway, with HKDFGUARD_ERR_INVALID_ARGUMENT).
	if err := checkHardenProcessOptions(options); err != nil {
		return err
	}
	library, err := hostLibrary()
	if err != nil {
		return err
	}
	return hardenProcess(library, options)
}

func checkHardenProcessOptions(options HardenProcessOptions) error {
	if unknown := options &^ knownHardenProcessOptions; unknown != 0 {
		return fmt.Errorf("nativev1: unknown process hardening option 0x%x", uint32(unknown))
	}
	return nil
}

func hardenProcess(library kmsLibrary, options HardenProcessOptions) error {
	if err := checkHardenProcessOptions(options); err != nil {
		return err
	}
	if status := library.hardenProcess(uint32(options)); status != statusOK {
		return &StatusError{Op: "process hardening", Status: status, Description: library.describeStatus(status)}
	}
	return nil
}
