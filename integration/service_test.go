package integration

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/keywrapping/nativev1"
)

// Which native service the end-to-end tests run against - the same rules as the nativev1 module's
// own native tests, through the public API: HKDFGUARD_TEST_SERVICE if set; otherwise
// defaultTestService, which every platform's provisioning script creates, when the platform can confirm it is
// provisioned without prompting (macOS asks the provisioning tool, Windows asks the library);
// otherwise skipped.

const (
	testServiceVariable      = "HKDFGUARD_TEST_SERVICE"
	testOtherServiceVariable = "HKDFGUARD_TEST_SERVICE_OTHER"
	unprovisionedServiceName = "hkdfguard.integrationtest.unprovisioned"

	// Status codes the Windows probe tells "not provisioned" by - shared by every platform's
	// library (see nativev1's status.go).
	statusKEKNotFound     = -17
	statusKEKAccessDenied = -18

	// nativeCallTimeout bounds the first native call under each service: on macOS a freshly built
	// test binary is answered with a keychain dialog (see nativev1's native_test.go).
	nativeCallTimeout = 60 * time.Second

	// defaultTestService is the test KEK every platform's provisioning script creates - the same
	// name in every HkdfGuard port (keywrapping/nativev1/scripts).
	defaultTestService = "com.hkdfguard.integration.test.221"
)

type testEnvironment struct {
	service    string // "" when the tests are skipped
	skipReason string
	failReason string // set when the tests must fail rather than skip
}

var (
	resolveOnce sync.Once
	resolved    testEnvironment

	otherProbeOnce    sync.Once
	otherProbeTimeout string // set when the first call under the other service did not return
)

// testServiceName is the service to run against; it skips (or fails) the test when there is none.
func testServiceName(t *testing.T) string {
	t.Helper()
	resolveOnce.Do(func() { resolved = resolveTestEnvironment() })
	if resolved.failReason != "" {
		t.Fatal(resolved.failReason)
	}
	if resolved.service == "" {
		t.Skip(resolved.skipReason)
	}
	return resolved.service
}

// otherServiceName is the second service for the isolation tests: testOtherServiceVariable, or a
// name that is never provisioned. A named one is a real KEK whose first use from this binary can
// raise a macOS keychain dialog too, so its first native call is made here, once, with the same
// deadline as the test service's; a dialog nobody answers fails the test instead of hanging it.
func otherServiceName(t *testing.T) string {
	t.Helper()
	other := os.Getenv(testOtherServiceVariable)
	if other == "" {
		return unprovisionedServiceName
	}
	otherProbeOnce.Do(func() {
		wrapper, err := nativev1.New(other)
		if err != nil {
			return // reported by the test's own use of the service
		}
		if _, timedOut := probe(wrapper); timedOut {
			otherProbeTimeout = timeoutMessage(other)
		}
	})
	if otherProbeTimeout != "" {
		t.Fatal(otherProbeTimeout)
	}
	return other
}

func resolveTestEnvironment() testEnvironment {
	service := os.Getenv(testServiceVariable)
	explicit := service != ""
	if !explicit {
		service = defaultTestService
	}

	wrapper, err := nativev1.New(service)
	switch {
	case errors.Is(err, nativev1.ErrNotInstalled), errors.Is(err, nativev1.ErrUnsupportedPlatform):
		return testEnvironment{skipReason: fmt.Sprintf("the native library can't be used here: %v", err)}
	case err != nil:
		return testEnvironment{failReason: fmt.Sprintf("the installed native library failed to load: %v", err)}
	}

	if !explicit {
		switch runtime.GOOS {
		case "darwin":
			// Ask the provisioning tool, which never prompts; asking the library would.
			if provisioned, ok := darwinServiceProvisioned(service); ok && !provisioned {
				return testEnvironment{skipReason: fmt.Sprintf("The test KEK '%s' is not provisioned. Run keywrapping/nativev1/scripts/provision-macos-test-key.sh, or set %s to a provisioned service.", service, testServiceVariable)}
			}
		case "linux":
			return testEnvironment{skipReason: fmt.Sprintf("Set %s to a service provisioned with hkdfguard. On a Linux TPM host, sudo keywrapping/nativev1/scripts/provision-linux-test-key.sh provisions %s.", testServiceVariable, service)}
		}
	}

	// The first native call, with a deadline (the macOS keychain dialog); on Windows its status
	// also says whether the default service is provisioned.
	err, timedOut := probe(wrapper)
	if timedOut {
		return testEnvironment{failReason: timeoutMessage(service)}
	}
	var statusErr *nativev1.StatusError
	if !explicit && runtime.GOOS == "windows" && errors.As(err, &statusErr) {
		switch statusErr.Status {
		case statusKEKNotFound:
			return testEnvironment{skipReason: fmt.Sprintf("The test KEK '%s' is not provisioned. Run keywrapping/nativev1/scripts/provision-windows-test-key.ps1 from an elevated PowerShell, or set %s to a provisioned service.", service, testServiceVariable)}
		case statusKEKAccessDenied:
			return testEnvironment{skipReason: fmt.Sprintf("The test KEK '%s' exists, but this account may not use it. Add it to the HkdfGuardUsers group (then sign out and in), or run the tests elevated.", service)}
		}
	}
	return testEnvironment{service: service}
}

// timeoutMessage says why the first native call under service has not returned, and what to do.
func timeoutMessage(service string) string {
	return fmt.Sprintf("the first native call under service '%s' has not returned after %v. On macOS the KEK's keychain item is asking for access in a dialog: click \"Always Allow\" (every freshly built test binary asks once). In a session with no UI the library reports KEK_ACCESS_DENIED (-18) instead", service, nativeCallTimeout)
}

// probe makes one GenerateAndWrap under wrapper's service, reporting its error, or that it did not
// return within nativeCallTimeout.
func probe(wrapper *nativev1.KeyWrapper) (err error, timedOut bool) {
	done := make(chan error, 1)
	go func() {
		_, err := wrapper.GenerateAndWrap(context.Background(), make([]byte, hkdfguard.MaxWrappedKeyBytes))
		done <- err
	}()
	select {
	case err := <-done:
		return err, false
	case <-time.After(nativeCallTimeout):
		return nil, true
	}
}

// darwinServiceProvisioned asks the installed hkdfguard tool - beside the library the
// loader uses: the system install when there is one, else the per-user one - whether service's
// KEK exists. ok is false when the tool couldn't say.
func darwinServiceProvisioned(service string) (provisioned, ok bool) {
	home, _ := os.UserHomeDir()
	var tool string
	for _, directory := range []string{"/Library/Application Support/HkdfGuard/v1", filepath.Join(home, ".hkdfguard", "v1")} {
		if _, err := os.Stat(filepath.Join(directory, "libhkdfguard.dylib")); err == nil {
			tool = filepath.Join(directory, "hkdfguard")
			break
		}
	}
	if tool == "" {
		return false, false
	}
	output, err := exec.Command(tool, "status", "--service-name", service).CombinedOutput()
	if err != nil {
		return false, false
	}
	switch {
	case bytes.Contains(output, []byte("kek: present")):
		return true, true
	case bytes.Contains(output, []byte("kek: absent")):
		return false, true
	}
	return false, false
}
