// Package integration holds the end-to-end tests that cross module boundaries: the paths a
// deployment and a running application actually take, from a pipeline encrypting configuration
// through the native KEK to the application reading it back - the Go port of the .NET
// NativeEndToEndTests.
//
// It is a module of its own so the published modules never depend on each other: it requires all
// three (the root module, cryptoprovider/aesgcm256 and keywrapping/nativev1) through replace
// directives, is never tagged or published, and contains only tests. Run them from this directory:
//
//	CGO_ENABLED=1 go test ./...   (cgo on macOS and Linux; Windows needs neither)
//
// Like keywrapping/nativev1's own native tests, they run against a provisioned test service (see
// HKDFGUARD_TEST_SERVICE and the provisioning scripts under keywrapping/nativev1/scripts) and are
// reported as skipped where there is none.
package integration
