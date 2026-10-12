package nativev1

// The services the native integration tests run against, and how they are chosen - shared by
// every platform's test files and checked against the provisioning scripts in scripts_test.go.

const (
	// testServiceVariable names a service already provisioned on this machine; its KEK is used,
	// never created or deleted. It always wins over the platform default, and is never skipped:
	// setting it means the native tests must run.
	testServiceVariable = "HKDFGUARD_TEST_SERVICE"

	// testOtherServiceVariable is an optional second provisioned service, for the cross-service
	// isolation tests. Unset, those tests unwrap under unprovisionedServiceName instead, which
	// must also fail.
	testOtherServiceVariable = "HKDFGUARD_TEST_SERVICE_OTHER"

	// unprovisionedServiceName is a valid service name that is never provisioned.
	unprovisionedServiceName = "hkdfguard.integrationtest.unprovisioned"
)

// defaultTestServices are the test KEKs each platform's provisioning script creates, used when
// testServiceVariable is unset and the platform can tell, without prompting, that the KEK exists.
var defaultTestServices = map[string]string{
	"windows": "com.hkdfguard.native.windows.test", // scripts/provision-windows-test-key.ps1
	"darwin":  "com.hkdfguard.native.macos.test",   // scripts/provision-macos-test-key.sh
	"linux":   "com.hkdfguard.native.linux.test",   // scripts/provision-linux-test-key.sh
}
