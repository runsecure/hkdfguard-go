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
	want := strings.Replace(macCodeRequirement, `identifier "libhkdfguard_v1"`, `identifier "hkdfguard-v1-initialize"`, 1)
	if match := regexp.MustCompile(`(?m)^readonly REQUIREMENT='([^']*)'$`).FindSubmatch(script); match == nil || string(match[1]) != want {
		t.Errorf("REQUIREMENT = %q, but the loader requires %q", match, want)
	}
}

func TestTheProvisioningScripts_UseTheServicesTheTestsDocument(t *testing.T) {
	scripts := map[string]struct{ file, pattern string }{
		"linux":   {"scripts/provision-linux-test-key.sh", `(?m)^readonly SERVICE="%s"$`},
		"darwin":  {"scripts/provision-macos-test-key.sh", `(?m)^readonly SERVICE="%s"$`},
		"windows": {"scripts/provision-windows-test-key.ps1", `(?m)^    \[string\] \$ServiceName = '%s'$`},
	}
	for goos, script := range scripts {
		contents, err := os.ReadFile(script.file)
		if err != nil {
			t.Fatal(err)
		}
		service := defaultTestServices[goos]
		if !regexp.MustCompile(fmt.Sprintf(script.pattern, regexp.QuoteMeta(service))).Match(contents) {
			t.Errorf("%s does not provision %q, the %s default the tests look for", script.file, service, goos)
		}
	}

	linux, _ := os.ReadFile("scripts/provision-linux-test-key.sh")
	if !regexp.MustCompile(`(?m)^readonly OTHER_SERVICE="\$\{SERVICE\}\.other"$`).Match(linux) {
		t.Error("the Linux script's second test service changed")
	}

	for _, name := range []string{defaultTestServices["linux"], defaultTestServices["linux"] + ".other", defaultTestServices["darwin"], defaultTestServices["windows"], unprovisionedServiceName} {
		if !hkdfguard.IsValidServiceName(name) {
			t.Errorf("%q is not a valid service name", name)
		}
	}
}
