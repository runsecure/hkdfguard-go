//go:build !windows && !(darwin && cgo)

package certificate

import (
	"fmt"
	"runtime"
)

// readStore has no store to read: Windows reads its certificate stores, macOS - built with cgo -
// its keychains, and nothing else has one the Validator lets a source name.
func readStore(StoreLocation, StoreName) ([]storeCertificate, error) {
	if runtime.GOOS == "darwin" {
		return nil, fmt.Errorf("%w: reading the macOS keychain needs cgo (build with CGO_ENABLED=1)", ErrUnsupported)
	}
	return nil, fmt.Errorf("%w: there is no certificate store to read on %s", ErrUnsupported, describePlatform(runtime.GOOS))
}
