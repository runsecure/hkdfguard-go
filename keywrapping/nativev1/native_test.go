//go:build (darwin && cgo) || (linux && cgo) || windows

package nativev1

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"testing"

	"github.com/runsecure/hkdfguard-go"
)

// Real wrapping and unwrapping against this platform's installed native KMS library. No native
// library creates a KEK during wrap/unwrap, so the round trips run against an operator-provisioned
// service:
//
//	hkdfguard-v1-initialize provision --service-name hkdfguard.integrationtest   (elevated on Windows)
//	HKDFGUARD_TEST_SERVICE=hkdfguard.integrationtest go test ./...
//
// scripts/provision-linux-test-key.sh (sudo) and scripts/provision-windows-test-key.ps1 (elevated)
// do the provisioning for a test host, after checking the installed tool, and print the command.
//
// Without the library installed every test here is skipped; without HKDFGUARD_TEST_SERVICE the
// round trips are. A library that is installed but fails verification fails the run.

const (
	testServiceVariable      = "HKDFGUARD_TEST_SERVICE"
	testOtherServiceVariable = "HKDFGUARD_TEST_SERVICE_OTHER"
	unprovisionedServiceName = "hkdfguard.integrationtest.unprovisioned"
)

// installedLibrary loads the real library, skipping the test if it isn't installed.
func installedLibrary(t *testing.T) kmsLibrary {
	t.Helper()
	library, err := hostLibrary()
	if errors.Is(err, ErrNotInstalled) {
		t.Skipf("the native library is not installed: %v", err)
	}
	if err != nil {
		t.Fatalf("the installed native library failed to load: %v", err)
	}
	return library
}

// provisionedWrapper returns a KeyWrapper for HKDFGUARD_TEST_SERVICE, skipping the test without it.
func provisionedWrapper(t *testing.T) *KeyWrapper {
	t.Helper()
	installedLibrary(t)
	service := os.Getenv(testServiceVariable)
	if service == "" {
		t.Skipf("set %s to a provisioned service to run round trips against the native library", testServiceVariable)
	}
	w, err := New(service)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func TestTheInstalledLibrary_LoadsOnce_AndAnswersCalls(t *testing.T) {
	first := installedLibrary(t)
	second, err := hostLibrary()
	if err != nil || second != first {
		t.Fatalf("second load = %v, %v; want the same binding", second, err)
	}

	// No KEK is provisioned for this name, so the library answers with an error status - which
	// proves it loaded and ran.
	status, _ := first.wrapDEK(unprovisionedServiceName, make([]byte, DEKLength), make([]byte, hkdfguard.MaxWrappedKeyBytes))
	if status >= 0 {
		t.Errorf("wrap under an unprovisioned service returned status %d", status)
	}
}

func TestNative_WrapAndUnwrap_RoundTripsA32ByteDEK(t *testing.T) {
	w := provisionedWrapper(t)
	ctx := context.Background()

	dek := make([]byte, DEKLength)
	_, _ = rand.Read(dek)
	wrapped := make([]byte, hkdfguard.MaxWrappedKeyBytes)
	n, err := w.Wrap(ctx, dek, wrapped)
	if err != nil || n == 0 || bytes.Equal(wrapped[:n], dek) {
		t.Fatalf("Wrap = %d, %v", n, err)
	}

	unwrapped := make([]byte, DEKLength)
	m, err := w.Unwrap(ctx, wrapped[:n], unwrapped)
	if err != nil || m != DEKLength || !bytes.Equal(unwrapped, dek) {
		t.Errorf("Unwrap = %d, %v; DEK recovered: %v", m, err, bytes.Equal(unwrapped, dek))
	}
}

func TestNative_GenerateAndWrap_ProducesAStableNonZeroDEK(t *testing.T) {
	w := provisionedWrapper(t)
	ctx := context.Background()

	wrapped := make([]byte, hkdfguard.MaxWrappedKeyBytes)
	n, err := w.GenerateAndWrap(ctx, wrapped)
	if err != nil || n == 0 {
		t.Fatalf("GenerateAndWrap = %d, %v", n, err)
	}

	first, second := make([]byte, DEKLength), make([]byte, DEKLength)
	if _, err := w.Unwrap(ctx, wrapped[:n], first); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Unwrap(ctx, wrapped[:n], second); err != nil {
		t.Fatal(err)
	}
	if hkdfguard.IsZero(first) || !bytes.Equal(first, second) {
		t.Error("the generated DEK is zero, or differs between unwraps")
	}
}

func TestNative_APayloadFromAnotherService_RevealsNothing(t *testing.T) {
	// A second provisioned service exercises the "wrong KEK" path; without one, an unprovisioned
	// name exercises "no KEK". Either way the unwrap must fail and reveal nothing.
	a := provisionedWrapper(t)
	other := os.Getenv(testOtherServiceVariable)
	if other == "" {
		other = unprovisionedServiceName
	}
	b, err := New(other)
	if err != nil {
		t.Fatal(err)
	}

	dek := make([]byte, DEKLength)
	_, _ = rand.Read(dek)
	wrapped := make([]byte, hkdfguard.MaxWrappedKeyBytes)
	n, err := a.Wrap(context.Background(), dek, wrapped)
	if err != nil {
		t.Fatal(err)
	}

	destination := make([]byte, DEKLength)
	var statusErr *StatusError
	if _, err := b.Unwrap(context.Background(), wrapped[:n], destination); !errors.As(err, &statusErr) {
		t.Errorf("Unwrap under another service: error = %v, want a *StatusError", err)
	}
	if !hkdfguard.IsZero(destination) {
		t.Error("the failed unwrap left bytes in the destination")
	}
}

func TestNative_TooSmallBuffersAndCorruptPayloads_Fail(t *testing.T) {
	w := provisionedWrapper(t)
	ctx := context.Background()

	if _, err := w.Wrap(ctx, make([]byte, DEKLength), make([]byte, 8)); err == nil {
		t.Error("Wrap into 8 bytes succeeded")
	}
	if _, err := w.GenerateAndWrap(ctx, make([]byte, 8)); err == nil {
		t.Error("GenerateAndWrap into 8 bytes succeeded")
	}

	wrapped := make([]byte, hkdfguard.MaxWrappedKeyBytes)
	n, err := w.GenerateAndWrap(ctx, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Unwrap(ctx, wrapped[:n], make([]byte, 8)); err == nil {
		t.Error("Unwrap into 8 bytes succeeded")
	}

	wrapped[n/2] ^= 0xFF
	destination := make([]byte, DEKLength)
	if _, err := w.Unwrap(ctx, wrapped[:n], destination); err == nil || !hkdfguard.IsZero(destination) {
		t.Errorf("Unwrap of a corrupted payload: error = %v, destination zeroed = %v", err, hkdfguard.IsZero(destination))
	}
}
