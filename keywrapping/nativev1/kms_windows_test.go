//go:build windows

package nativev1

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The Windows loader's checks against this machine's real filesystem, WinVerifyTrust and the
// installed HkdfGuard.dll where there is one. windowspolicy_test.go checks the decisions
// against plain data on every platform.

// winInstalledPath is the one location the library is loaded from.
func winInstalledPath(t *testing.T) string {
	t.Helper()
	programFiles, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, windows.KF_FLAG_DONT_VERIFY)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(programFiles, "HkdfGuard", "v1", winFileName)
}

// installedWindowsLibraryPath skips the test when the library isn't installed.
func installedWindowsLibraryPath(t *testing.T) string {
	t.Helper()
	path := winInstalledPath(t)
	if _, err := os.Stat(path); err != nil {
		t.Skipf("the native KMS library is not installed at %s", path)
	}
	return path
}

// platformTestEnvironment asks the installed library, through its hkdfguard_kek_exists export,
// whether the default test service is provisioned - so "not provisioned yet" (skip) is told apart
// from a real failure (run, and fail).
func platformTestEnvironment() testEnvironment {
	status, exists, err := winKEKExists(defaultTestService)
	switch {
	case err != nil:
		// Installed, but it couldn't be asked: run the tests so that failure is reported.
		return testEnvironment{service: defaultTestService}
	case status == statusOK && exists:
		return testEnvironment{service: defaultTestService}
	case status == statusOK || status == errKEKNotFound:
		return testEnvironment{skipReason: fmt.Sprintf("The test KEK '%s' is not provisioned. Run scripts/provision-windows-test-key.ps1 from an elevated PowerShell, or set %s to a provisioned service.", defaultTestService, testServiceVariable)}
	case status == errKEKAccessDenied:
		return testEnvironment{skipReason: fmt.Sprintf("The test KEK '%s' exists, but this account may not use it. Add it to the HkdfGuardUsers group (then sign out and in), or run the tests elevated.", defaultTestService)}
	default:
		return testEnvironment{service: defaultTestService}
	}
}

// winKEKExists is hkdfguard_kek_exists(const char* service, int32_t* out_exists) on the library
// the verified loader loaded: the library's status, and whether the KEK exists when it is 0.
func winKEKExists(service string) (status int32, exists bool, err error) {
	library, err := hostLibrary()
	if err != nil {
		return 0, false, err
	}
	win, ok := library.(*winLibrary)
	if !ok {
		return 0, false, errors.New("the loaded library is not the Windows binding")
	}
	proc, err := windows.GetProcAddress(win.handle, "hkdfguard_kek_exists")
	if err != nil {
		return 0, false, err
	}
	cservice, err := windows.BytePtrFromString(service)
	if err != nil {
		return 0, false, err
	}

	var outExists int32
	r, _, _ := syscall.SyscallN(proc, uintptr(unsafe.Pointer(cservice)), uintptr(unsafe.Pointer(&outExists)))
	status = int32(r)
	return status, status == statusOK && outExists != 0, nil
}

func writeTempFile(t *testing.T, name string, contents []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, contents, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestWindows_LoadFromAMissingPath_ReportsNotInstalled_NamingTheOnlySupportedPath(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing", winFileName)

	_, err := winLoad(missing, winExpectedPublisher)

	if !errors.Is(err, ErrNotInstalled) || !strings.Contains(err.Error(), missing) {
		t.Errorf("error = %v, want ErrNotInstalled naming %s", err, missing)
	}
}

func TestWindows_APlantedFileInAUserWritableFolder_IsRefused_BeforeAnythingIsLoaded(t *testing.T) {
	// The DLL-planting scenario: a correctly named file in a folder the current user controls.
	planted := writeTempFile(t, winFileName, []byte{'M', 'Z'})

	_, err := winLoad(planted, winExpectedPublisher)

	requireUntrusted(t, err)
}

func TestWindows_AJunction_IsRefused(t *testing.T) {
	// Junctions need no privilege to create, unlike symbolic links.
	target := t.TempDir()
	junction := filepath.Join(os.TempDir(), fmt.Sprintf("hkdfguard-junction-%d", os.Getpid()))
	if output, err := exec.Command("cmd.exe", "/c", "mklink", "/J", junction, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v: %s", err, output)
	}
	t.Cleanup(func() { _ = os.Remove(junction) })

	requireUntrusted(t, winVerifyNotReparsePoint(junction), "symbolic link or junction")
	if err := winVerifyNotReparsePoint(target); err != nil {
		t.Errorf("the real directory: %v", err)
	}
}

func TestWindows_AnUnsignedFile_IsRefused(t *testing.T) {
	path := writeTempFile(t, "unsigned.dll", []byte{'M', 'Z', 0x90, 0x00})

	requireUntrusted(t, winVerifySignature(path, winExpectedPublisher))
}

func TestWindows_AFileThatIsNotAPEImage_FailsClosed(t *testing.T) {
	path := writeTempFile(t, "not-pe.dll", []byte{'M', 'Z', 0x90, 0x00})

	requireUntrusted(t, winVerifyImageKindOf(path))
}

func TestWindows_TheInstalledLibrary_PassesTheLocationSignatureAndImageChecks(t *testing.T) {
	path := installedWindowsLibraryPath(t)

	if err := winVerifyLocation(path); err != nil {
		t.Errorf("location: %v", err)
	}
	if err := winVerifySignature(path, winExpectedPublisher); err != nil {
		t.Errorf("signature: %v", err)
	}
	if err := winVerifyImageKindOf(path); err != nil {
		t.Errorf("image kind: %v", err)
	}
}

func TestWindows_TheInstalledLibrary_ChainsToThePinnedRoot_WithTheProfileEKU(t *testing.T) {
	// The chain WinVerifyTrust validated, not one built separately.
	subject, ekus, root, err := winReadVerifiedSigner(installedWindowsLibraryPath(t))
	if err != nil {
		t.Fatal(err)
	}

	if subject != winExpectedPublisher {
		t.Errorf("subject = %q, want %q", subject, winExpectedPublisher)
	}
	if !strings.EqualFold(root, winExpectedRootSHA256) {
		t.Errorf("root = %s, want %s", root, winExpectedRootSHA256)
	}
	if !slices.Contains(ekus, winCodeSigningEKU) || !slices.Contains(ekus, winExpectedProfileEKU) {
		t.Errorf("EKUs = %v, want code signing and the profile EKU", ekus)
	}
}

func TestWindows_TheInstalledLibrary_SignedByAnotherPublisher_IsRefused(t *testing.T) {
	requireUntrusted(t, winVerifySignature(installedWindowsLibraryPath(t), "CN=Someone Else"), "not the expected HkdfGuard publisher")
}

func TestWindows_ATamperedCopyOfTheInstalledLibrary_IsRefused(t *testing.T) {
	image, err := os.ReadFile(installedWindowsLibraryPath(t))
	if err != nil {
		t.Fatal(err)
	}
	image[len(image)/2] ^= 0xFF // inside the signed image, not the signature itself
	copy := writeTempFile(t, winFileName, image)

	requireUntrusted(t, winVerifySignature(copy, winExpectedPublisher))
}

func TestWindows_TheInstalledProvisioningTool_PassesTheSignerChecks_ButIsRefusedAsNotADLL(t *testing.T) {
	// Installed beside the library and signed under the same profile: only the image check
	// tells them apart.
	tool := filepath.Join(filepath.Dir(installedWindowsLibraryPath(t)), "hkdfguard.exe")
	if _, err := os.Stat(tool); err != nil {
		t.Fatalf("%s is installed with the library: %v", tool, err)
	}

	if err := winVerifySignature(tool, winExpectedPublisher); err != nil {
		t.Errorf("signature: %v", err)
	}
	requireUntrusted(t, winVerifyImageKindOf(tool), "not a DLL")
}

// winModulePath is the file Windows mapped a loaded module from.
func winModulePath(t *testing.T, handle windows.Handle) string {
	t.Helper()
	buffer := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetModuleFileName(handle, &buffer[0], uint32(len(buffer)))
	if err != nil || n == 0 {
		t.Fatalf("GetModuleFileName = %d, %v", n, err)
	}
	return windows.UTF16ToString(buffer[:n])
}

func TestWindows_TheInstalledPath_IsTheFixedProgramFilesLocation(t *testing.T) {
	// Worked out independently of the loader: %ProgramFiles%\HkdfGuard\v1\HkdfGuard.dll.
	programFiles := os.Getenv("ProgramFiles")
	if programFiles == "" {
		t.Fatal("%ProgramFiles% is not set")
	}
	expected := filepath.Join(programFiles, "HkdfGuard", "v1", "HkdfGuard.dll")

	library, err := loadPlatformLibrary()

	if errors.Is(err, ErrNotInstalled) {
		// Nothing there: the refusal names the one location it would have loaded from.
		if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(expected)) {
			t.Errorf("error = %v; want it to name %s", err, expected)
		}
		return
	}
	if err != nil {
		t.Fatalf("the installed native library failed to load: %v", err)
	}
	win, ok := library.(*winLibrary)
	if !ok {
		t.Fatalf("loaded library is a %T", library)
	}
	if loaded := winModulePath(t, win.handle); !strings.EqualFold(loaded, expected) {
		t.Errorf("Windows mapped %s; want %s", loaded, expected)
	}
}

func TestWindows_LoadingTheInstalledLibraryAgain_ReturnsTheSameHandle(t *testing.T) {
	path := installedWindowsLibraryPath(t)

	first, err := winLoad(path, winExpectedPublisher)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = windows.FreeLibrary(first.(*winLibrary).handle) })
	second, err := winLoad(path, winExpectedPublisher)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = windows.FreeLibrary(second.(*winLibrary).handle) })

	firstHandle, secondHandle := first.(*winLibrary).handle, second.(*winLibrary).handle
	if firstHandle == 0 || firstHandle != secondHandle {
		t.Errorf("handles = %#x, %#x; want the same module", firstHandle, secondHandle)
	}
	// And the same module the process-wide binding uses.
	if host, ok := installedLibrary(t).(*winLibrary); !ok || host.handle != firstHandle {
		t.Errorf("the host library is not the module winLoad returned")
	}
}

func TestWindows_KEKExists_AnswersForAnUnprovisionedService(t *testing.T) {
	installedWindowsLibraryPath(t)

	status, exists, err := winKEKExists(unprovisionedServiceName)

	if err != nil || exists {
		t.Errorf("winKEKExists = %d, %v, %v; want no KEK", status, exists, err)
	}
	if status != statusOK && describeWindowsStatus(status) == "" {
		t.Errorf("undescribed status %d", status)
	}
}
