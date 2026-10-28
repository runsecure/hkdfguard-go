// Package integration holds the end-to-end tests that cross module boundaries: the paths a
// deployment and a running application actually take, from a pipeline encrypting configuration
// through the native KEK to the application reading it back - the Go port of the .NET
// NativeEndToEndTests.
//
// It is a module of its own so the published modules never depend on each other: it requires all
// of them (the root module, cryptoprovider/aesgcm256, keywrapping/nativev1, keywrapping/awskms,
// keywrapping/azurekeyvault, keywrapping/googlekms and securefile) through replace directives, is
// never tagged or published, and contains only tests.
// Run them from this directory:
//
//	CGO_ENABLED=1 go test ./...   (cgo on macOS and Linux; Windows needs neither)
//
// Like keywrapping/nativev1's own native tests, the native ones run against a provisioned test
// service (see HKDFGUARD_TEST_SERVICE and the provisioning scripts under
// keywrapping/nativev1/scripts) and are reported as skipped where there is none. The AWS KMS, Azure
// Key Vault and Google Cloud KMS ones (awskms_e2e_test.go, azurekeyvault_e2e_test.go,
// googlekms_e2e_test.go) use in-process stand-ins for the three services and run everywhere.
package integration
