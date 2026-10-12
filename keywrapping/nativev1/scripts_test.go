package nativev1

import (
	"os"
	"regexp"
	"testing"

	"github.com/runsecure/hkdfguard-go"
)

// The provisioning scripts vet the native tool against the same pins the loader vets the library
// against; this keeps the two from drifting apart.

func TestTheWindowsProvisioningScript_PinsWhatTheLoaderPins(t *testing.T) {
	script, err := os.ReadFile("scripts/provision-windows-test-key.ps1")
	if err != nil {
		t.Fatal(err)
	}

	pins := map[string]string{
		"ExpectedPublisher":  winExpectedPublisher,
		"ExpectedRootSha256": winExpectedRootSHA256,
		"ExpectedProfileEku": winExpectedProfileEKU,
		"CodeSigningEku":     winCodeSigningEKU,
	}
	for variable, want := range pins {
		match := regexp.MustCompile(`(?m)^\$` + variable + ` = '([^']*)'$`).FindSubmatch(script)
		if match == nil {
			t.Errorf("the script no longer assigns $%s", variable)
		} else if string(match[1]) != want {
			t.Errorf("$%s = %q, but the loader pins %q", variable, match[1], want)
		}
	}
}

func TestTheProvisioningScripts_UseTheServicesTheTestsDocument(t *testing.T) {
	linux, err := os.ReadFile("scripts/provision-linux-test-key.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`(?m)^readonly SERVICE="com\.hkdfguard\.native\.linux\.test"$`).Match(linux) {
		t.Error("the Linux script's test service changed")
	}
	if !regexp.MustCompile(`(?m)^readonly OTHER_SERVICE="\$\{SERVICE\}\.other"$`).Match(linux) {
		t.Error("the Linux script's second test service changed")
	}

	for _, name := range []string{"com.hkdfguard.native.linux.test", "com.hkdfguard.native.linux.test.other", "com.hkdfguard.native.windows.test"} {
		if !hkdfguard.IsValidServiceName(name) {
			t.Errorf("%q is not a valid service name", name)
		}
	}
}
