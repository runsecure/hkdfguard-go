// Package kmstest holds what the tests of the cloud key wrappers - keywrapping/awskms,
// keywrapping/azurekeyvault and keywrapping/googlekms - check alike: reading key files through the
// wrapper, refusing an ended context, and reading the integration tests' settings file.
//
// Test support only: it is internal to this repository, and nothing outside a _test.go file imports
// it.
package kmstest

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/runsecure/hkdfguard-go"
)

// KeyWrapper is what these checks need of a wrapper: hkdfguard.KeyWrapper's calls, and ReadKeyFile.
type KeyWrapper interface {
	Wrap(ctx context.Context, plaintext, result []byte) (int, error)
	Unwrap(ctx context.Context, wrapped, result []byte) (int, error)
	GenerateAndWrap(ctx context.Context, result []byte) (int, error)
	ReadKeyFile(ctx context.Context, path string) ([]byte, error)
}

// KeyFilesRead reports whether securefile reads key files on this platform.
func KeyFilesRead() bool {
	return runtime.GOOS == "windows" || runtime.GOOS == "linux" || (runtime.GOOS == "darwin" && runtime.GOARCH == "arm64")
}

// RandomKeyFile writes a key file of random bytes - one that looks wrapped - named v1.key in
// directory, and returns its path.
func RandomKeyFile(t testing.TB, directory string) string {
	t.Helper()
	contents := make([]byte, 184)
	_, _ = rand.Read(contents)
	path := filepath.Join(directory, "v1.key")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// UserWritableKeyFile is a key file in a folder the user running the tests could replace: under the
// user's temp folder (Windows) or the shared /tmp (Linux and macOS) - neither somewhere only
// administrators can write.
func UserWritableKeyFile(t testing.TB) string {
	t.Helper()
	root := "/tmp"
	if runtime.GOOS == "windows" {
		root = os.TempDir()
	}
	directory, err := os.MkdirTemp(root, "hkdfguard-keys-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	return RandomKeyFile(t, directory)
}

// RequireNotTrusted checks err is a key file refused as not trusted: an E (a
// *securefile.KeyFileError) matching untrusted (securefile.ErrUntrusted) and fs.ErrPermission.
func RequireNotTrusted[E error](t testing.TB, err, untrusted error) {
	t.Helper()
	var keyFileErr E
	if !errors.As(err, &keyFileErr) || !errors.Is(err, untrusted) || !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("got %v; want a key file refused as not trusted", err)
	}
}

// ReadAndReveal writes a wrapped DEK generated through wrapper to path, reads it back through
// wrapper, and checks it reveals.
func ReadAndReveal(t testing.TB, wrapper KeyWrapper, path string) {
	t.Helper()
	ctx := t.Context()
	wrapped := make([]byte, 512)
	n, err := wrapper.GenerateAndWrap(ctx, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, wrapped[:n], 0o600); err != nil {
		t.Fatal(err)
	}
	read, err := wrapper.ReadKeyFile(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if string(read) != string(wrapped[:n]) {
		t.Fatal("the key file read back differs from what was written")
	}
	if m, err := wrapper.Unwrap(ctx, read, make([]byte, 32)); err != nil || m != 32 {
		t.Fatalf("%d, %v; want the DEK revealed", m, err)
	}
}

// RequireEndedContextRefused checks every call wrapper makes fails with context.Canceled once its
// context has ended, and Unwrap zeroes its result; wrapped is a wrapped DEK of a size the wrapper
// would otherwise unwrap. Whether the service was called is the caller's to check.
func RequireEndedContextRefused(t testing.TB, wrapper KeyWrapper, wrapped []byte) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	result := bytes.Repeat([]byte{0xaa}, hkdfguard.MaxWrappedKeyBytes)
	plaintext := make([]byte, 32)
	_, _ = rand.Read(plaintext)

	if _, err := wrapper.Wrap(ctx, plaintext, result); !errors.Is(err, context.Canceled) {
		t.Errorf("wrap: %v", err)
	}
	if _, err := wrapper.GenerateAndWrap(ctx, result); !errors.Is(err, context.Canceled) {
		t.Errorf("generate-and-wrap: %v", err)
	}
	if _, err := wrapper.ReadKeyFile(ctx, "v1.key"); !errors.Is(err, context.Canceled) {
		t.Errorf("read key file: %v", err)
	}
	if _, err := wrapper.Unwrap(ctx, wrapped, result); !errors.Is(err, context.Canceled) {
		t.Errorf("unwrap: %v", err)
	}
	if !hkdfguard.IsZero(result) {
		t.Error("unwrap did not zero the result")
	}
}

// Settings is the settings file name at the repository root - two directories above the package
// under test, where go test runs - as NAME=value lines, '#' and '!' starting a comment; empty if
// there is none. A local file, ignored by git, naming keys only: no credential ever goes in it.
func Settings(t testing.TB, name string) map[string]string {
	t.Helper()
	values := map[string]string{}
	file, err := os.Open(filepath.Join("..", "..", name))
	if errors.Is(err, os.ErrNotExist) {
		return values
	}
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		name, value, found := strings.Cut(line, "=")
		if line != "" && !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "!") && found && strings.TrimSpace(name) != "" {
			values[strings.TrimSpace(name)] = strings.TrimSpace(value)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return values
}
