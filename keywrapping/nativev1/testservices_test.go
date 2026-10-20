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

// defaultTestService is the test KEK every platform's provisioning script creates - the same name
// in every HkdfGuard port - used when testServiceVariable is unset and the platform can tell,
// without prompting, that the KEK exists. scripts/provision-windows-test-key.ps1,
// provision-macos-test-key.sh and provision-linux-test-key.sh each provision it.
const defaultTestService = "com.hkdfguard.integration.test.221"
