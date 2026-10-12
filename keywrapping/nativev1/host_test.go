package nativev1

import (
	"errors"
	"testing"
)

// swapLoader replaces the platform loader for one test, starting from nothing loaded.
func swapLoader(t *testing.T, load func() (kmsLibrary, error)) {
	t.Helper()
	hostMu.Lock()
	previousLoaded, previousLoad := hostLoaded, loadLibrary
	hostLoaded, loadLibrary = nil, load
	hostMu.Unlock()

	t.Cleanup(func() {
		hostMu.Lock()
		hostLoaded, loadLibrary = previousLoaded, previousLoad
		hostMu.Unlock()
	})
}

func TestHostLibrary_LoadsOnce_AndReturnsTheSameBindingEveryTime(t *testing.T) {
	loads := 0
	library := &fakeLibrary{}
	swapLoader(t, func() (kmsLibrary, error) { loads++; return library, nil })

	first, err1 := hostLibrary()
	second, err2 := hostLibrary()

	if err1 != nil || err2 != nil || first != library || second != library || loads != 1 {
		t.Errorf("got %v/%v, %v/%v after %d loads", first, err1, second, err2, loads)
	}
}

func TestHostLibrary_DoesNotCacheAFailure(t *testing.T) {
	attempts := 0
	library := &fakeLibrary{}
	swapLoader(t, func() (kmsLibrary, error) {
		attempts++
		if attempts == 1 {
			return nil, notInstalled("not yet")
		}
		return library, nil
	})

	if _, err := hostLibrary(); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("first attempt error = %v, want ErrNotInstalled", err)
	}
	if got, err := hostLibrary(); err != nil || got != library {
		t.Errorf("second attempt = %v, %v; want the library", got, err)
	}
}

func TestHostLibrary_ClassifiesAnUnexpectedFailureAsUntrusted(t *testing.T) {
	cause := errors.New("statx('/usr') failed with errno 13")
	swapLoader(t, func() (kmsLibrary, error) { return nil, cause })

	_, err := hostLibrary()

	if !errors.Is(err, ErrUntrusted) || !errors.Is(err, cause) {
		t.Errorf("error = %v, want ErrUntrusted wrapping the cause", err)
	}
}

func TestNew_UsesTheHostLibrary(t *testing.T) {
	library := &fakeLibrary{}
	swapLoader(t, func() (kmsLibrary, error) { return library, nil })

	w, err := New("test.service")

	if err != nil || w.library != library || w.ServiceName() != "test.service" {
		t.Errorf("New = %+v, %v", w, err)
	}
}

func TestNew_ReportsALoadFailure(t *testing.T) {
	swapLoader(t, func() (kmsLibrary, error) { return nil, untrusted("bad signature") })

	if _, err := New("test.service"); !errors.Is(err, ErrUntrusted) {
		t.Errorf("error = %v, want ErrUntrusted", err)
	}
}
