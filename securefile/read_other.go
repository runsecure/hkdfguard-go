//go:build !windows && !linux && !darwin

package securefile

// openOnPlatform is never reached here: platformSupport refuses this platform first.
func openOnPlatform(string, KeyFileTrust, string, func(readFunc, string) error) error {
	return unsupported("Trusted files are read on Windows, Linux and macOS only.")
}
