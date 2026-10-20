//go:build !windows && !linux

package integration

import "testing"

// keyFileDirectory is a fresh temporary folder for key files. On macOS t.TempDir() is already
// private to this user (under /var/folders); Linux and Windows have their own
// (keyfile_linux_test.go, keyfile_windows_test.go).
func keyFileDirectory(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}
