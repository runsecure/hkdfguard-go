//go:build !windows && !linux && !darwin

package securefile

// readOnPlatform is never reached here: platformSupport refuses this platform first.
func readOnPlatform(string, KeyFileTrust) ([]byte, error) {
	return nil, unsupported("Key files are read on Windows, Linux and macOS only.")
}
