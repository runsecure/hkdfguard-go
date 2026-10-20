package nativev1

import (
	"fmt"
	"os"
	"regexp"
	"strings"
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

func TestTheMacOSProvisioningScript_PinsWhatTheLoaderPins(t *testing.T) {
	script, err := os.ReadFile("scripts/provision-macos-test-key.sh")
	if err != nil {
		t.Fatal(err)
	}

	if match := regexp.MustCompile(`(?m)^readonly TEAM_ID="([^"]*)"$`).FindSubmatch(script); match == nil || string(match[1]) != macTeamID {
		t.Errorf("TEAM_ID = %q, but the loader pins %q", match, macTeamID)
	}
	// The loader's requirement for the library, naming the tool instead.
	want := strings.Replace(macCodeRequirement, `identifier "libhkdfguard"`, `identifier "hkdfguard"`, 1)
	if match := regexp.MustCompile(`(?m)^readonly REQUIREMENT='([^']*)'$`).FindSubmatch(script); match == nil || string(match[1]) != want {
		t.Errorf("REQUIREMENT = %q, but the loader requires %q", match, want)
	}
}

func TestTheProvisioningScripts_UseTheServicesTheTestsDocument(t *testing.T) {
	// Every platform's script provisions the one default test service, the same in every port.
	scripts := map[string]string{
		"scripts/provision-linux-test-key.sh":    `(?m)^readonly SERVICE="%s"$`,
		"scripts/provision-macos-test-key.sh":    `(?m)^readonly SERVICE="%s"$`,
		"scripts/provision-windows-test-key.ps1": `(?m)^    \[string\] \$ServiceName = '%s',?$`,
	}
	for file, pattern := range scripts {
		contents, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if !regexp.MustCompile(fmt.Sprintf(pattern, regexp.QuoteMeta(defaultTestService))).Match(contents) {
			t.Errorf("%s does not provision %q, the default test service the tests look for", file, defaultTestService)
		}
	}

	linux, _ := os.ReadFile("scripts/provision-linux-test-key.sh")
	// One test service only: the isolation tests use a never-provisioned name unless
	// HKDFGUARD_TEST_SERVICE_OTHER names a second real KEK.
	if regexp.MustCompile(`(?m)^readonly OTHER_SERVICE=`).Match(linux) {
		t.Error("the Linux script provisions a second test service again")
	}

	for _, name := range []string{defaultTestService, unprovisionedServiceName} {
		if !hkdfguard.IsValidServiceName(name) {
			t.Errorf("%q is not a valid service name", name)
		}
	}
}
