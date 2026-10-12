package nativev1

import "sync"

var (
	hostMu      sync.Mutex
	hostLoaded  kmsLibrary
	loadLibrary = loadPlatformLibrary // each platform's loader; swapped only by tests
)

// hostLibrary verifies and loads the current OS's native KMS library exactly once per process,
// returning the same binding on every later call. A failure isn't cached, so a fixed installation
// is picked up by the next call.
func hostLibrary() (kmsLibrary, error) {
	hostMu.Lock()
	defer hostMu.Unlock()

	if hostLoaded != nil {
		return hostLoaded, nil
	}

	library, err := loadLibrary()
	if err != nil {
		return nil, classify(err)
	}
	hostLoaded = library
	return hostLoaded, nil
}
