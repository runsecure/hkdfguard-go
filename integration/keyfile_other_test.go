//go:build !windows

package integration

import "testing"

// keyFileDirectory is a fresh temporary folder for key files.
func keyFileDirectory(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}
