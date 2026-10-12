//go:build !windows && !((darwin || linux) && cgo)

package nativev1

import "runtime"

// loadPlatformLibrary: there is no native library for this platform, or - on macOS and Linux - it
// can only be loaded through cgo, which this build was compiled without.
func loadPlatformLibrary() (kmsLibrary, error) {
	if runtime.GOOS == "darwin" || runtime.GOOS == "linux" {
		return nil, unsupported("The HkdfGuard native KMS library is loaded through cgo on %s, and this program was built with CGO_ENABLED=0. Rebuild it with CGO_ENABLED=1 and a C toolchain.", runtime.GOOS)
	}
	return nil, unsupported("nativev1 has no native KMS library for %s/%s.", runtime.GOOS, runtime.GOARCH)
}
