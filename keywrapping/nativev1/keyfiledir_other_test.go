//go:build !windows && !linux

package nativev1

import "testing"

// keyFileDirectory is a fresh temporary directory for files the tests hand to the native library.
// On macOS t.TempDir() is already private to this user (under /var/folders); Linux and Windows
// have their own (keyfiledir_linux_test.go, keyfile_windows_test.go).
func keyFileDirectory(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}
