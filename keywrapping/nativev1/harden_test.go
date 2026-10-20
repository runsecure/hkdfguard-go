package nativev1

import (
	"errors"
	"strings"
	"testing"
)

// processHardeningVariable opts in to the tests that harden this very test process
// (kms_linux_cgo_test.go, harden_windows_test.go).
const processHardeningVariable = "HKDFGUARD_TEST_PROCESS_HARDENING"

func TestHardenProcess_SucceedsWhenTheLibraryReportsOK(t *testing.T) {
	library := &fakeLibrary{harden: func() int32 { return statusOK }}

	if err := hardenProcess(library, 0); err != nil || library.hardenCalls != 1 {
		t.Errorf("hardenProcess = %v after %d calls", err, library.hardenCalls)
	}
}

func TestHardenProcess_ByDefault_PassesNoFlags(t *testing.T) {
	library := &fakeLibrary{}
	swapLoader(t, func() (kmsLibrary, error) { return library, nil })

	if err := HardenProcess(); err != nil {
		t.Fatal(err)
	}

	if library.lastHardenFlags == nil || *library.lastHardenFlags != 0 {
		t.Errorf("flags = %v, want 0", library.lastHardenFlags)
	}
}

func TestHardenProcess_RequireProtectedSignature_PassesTheNativeFlag(t *testing.T) {
	library := &fakeLibrary{}
	swapLoader(t, func() (kmsLibrary, error) { return library, nil })

	if err := HardenProcessWithOptions(RequireProtectedSignature); err != nil {
		t.Fatal(err)
	}

	// HKDFGUARD_HARDEN_REQUIRE_PROTECTED_SIGNATURE is 0x1 in every platform's hkdfguard.h.
	if library.lastHardenFlags == nil || *library.lastHardenFlags != 0x1 || RequireProtectedSignature != 0x1 {
		t.Errorf("flags = %v, want 0x1", library.lastHardenFlags)
	}
}

func TestHardenProcess_RefusesAnUnknownOption_BeforeReachingTheNativeLibrary(t *testing.T) {
	for _, options := range []HardenProcessOptions{0x2, 0x3, 0x80000000, ^HardenProcessOptions(0)} {
		loads := 0
		library := &fakeLibrary{}
		swapLoader(t, func() (kmsLibrary, error) { loads++; return library, nil })

		err := HardenProcessWithOptions(options)

		if err == nil || !strings.Contains(err.Error(), "unknown process hardening option") {
			t.Errorf("0x%x: error = %v", uint32(options), err)
		}
		if loads != 0 || library.hardenCalls != 0 {
			t.Errorf("0x%x: %d loads, %d native calls; want none", uint32(options), loads, library.hardenCalls)
		}
		if err := hardenProcess(library, options); err == nil || library.hardenCalls != 0 {
			t.Errorf("0x%x: hardenProcess = %v after %d native calls", uint32(options), err, library.hardenCalls)
		}
	}
}

func TestHardenProcess_FailureNamesTheStatusAndItsMeaning(t *testing.T) {
	library := &fakeLibrary{
		harden:   func() int32 { return errProcessHardeningFailed },
		describe: func(int32) string { return "could not disable core dumps" },
	}

	err := hardenProcess(library, RequireProtectedSignature)

	want := "Native process hardening failed with status -20 (could not disable core dumps)."
	if err == nil || err.Error() != want {
		t.Errorf("error = %v, want %q", err, want)
	}
	var statusErr *StatusError
	if !errors.As(err, &statusErr) || statusErr.Status != errProcessHardeningFailed || statusErr.Op != "process hardening" || statusErr.Service != "" {
		t.Errorf("error = %#v, want a *StatusError for -20", err)
	}
}

func TestHardenProcess_WithAnUnknownStatus_GivesJustTheStatus(t *testing.T) {
	err := hardenProcess(&fakeLibrary{harden: func() int32 { return -150 }}, 0)

	if err == nil || !strings.HasSuffix(err.Error(), "status -150.") {
		t.Errorf("error = %v", err)
	}
}

func TestHardenProcess_WhenTheLibraryCantBeLoaded_ReturnsTheLoadError(t *testing.T) {
	swapLoader(t, func() (kmsLibrary, error) { return nil, notInstalled("not here") })

	if err := HardenProcess(); !errors.Is(err, ErrNotInstalled) {
		t.Errorf("error = %v, want ErrNotInstalled", err)
	}
}

func TestEachPlatform_DescribesAHardeningFailureInItsOwnTerms(t *testing.T) {
	for platform, hint := range map[string]string{"windows": "access lists", "linux": "ptrace", "darwin": "Hardened Runtime"} {
		if description := platformDescribers[platform](errProcessHardeningFailed); !strings.Contains(description, hint) {
			t.Errorf("%s: -20 = %q, want it to mention %q", platform, description, hint)
		}
	}
}
