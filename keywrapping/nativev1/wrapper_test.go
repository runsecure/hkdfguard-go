package nativev1

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/runsecure/hkdfguard-go"
)

// fakeLibrary is a kmsLibrary that records its calls and answers as configured.
type fakeLibrary struct {
	wrapStatus, unwrapStatus, generateStatus int32
	writtenOverride                          *int32

	wrapPayload, unwrapPayload, generatePayload []byte
	unwrapLeavesBytes                           bool // on failure, scribble into out first

	lastService                 string
	lastWrapInput, lastUnwrapIn []byte
	wrapCalls, unwrapCalls      int
	generateCalls, hardenCalls  int

	describe func(int32) string
	harden   func() int32 // nil: hardening succeeds

	lastHardenFlags *uint32 // the flags of the last hardenProcess call

	openFileStatus  int32
	openFilePayload []byte
	openFileRead    *int32 // overrides the count read on success
	openFileErr     error  // the library has no open-file call
	openFilePaths   []string
	openFileCaps    []int
}

func (f *fakeLibrary) emit(status int32, payload, out []byte) (int32, int32) {
	if status != statusOK {
		return status, 0
	}
	n := int32(copy(out, payload))
	if f.writtenOverride != nil {
		n = *f.writtenOverride
	}
	return statusOK, n
}

func (f *fakeLibrary) wrapDEK(service string, dek, out []byte) (int32, int32) {
	f.wrapCalls++
	f.lastService, f.lastWrapInput = service, bytes.Clone(dek)
	payload := f.wrapPayload
	if payload == nil {
		payload = dek
	}
	return f.emit(f.wrapStatus, payload, out)
}

func (f *fakeLibrary) unwrapDEK(service string, wrapped, out []byte) (int32, int32) {
	f.unwrapCalls++
	f.lastService, f.lastUnwrapIn = service, bytes.Clone(wrapped)
	if f.unwrapStatus != statusOK && f.unwrapLeavesBytes {
		for i := range out {
			out[i] = 0xFF
		}
	}
	payload := f.unwrapPayload
	if payload == nil {
		payload = wrapped
	}
	return f.emit(f.unwrapStatus, payload, out)
}

func (f *fakeLibrary) generateAndWrapDEK(service string, out []byte) (int32, int32) {
	f.generateCalls++
	f.lastService = service
	payload := f.generatePayload
	if payload == nil {
		payload = make([]byte, 64)
	}
	return f.emit(f.generateStatus, payload, out)
}

func (f *fakeLibrary) describeStatus(status int32) string {
	if f.describe == nil {
		return ""
	}
	return f.describe(status)
}

func (f *fakeLibrary) openFile(path string, out []byte) (int32, int32, error) {
	f.openFilePaths = append(f.openFilePaths, path)
	f.openFileCaps = append(f.openFileCaps, len(out))
	if f.openFileErr != nil {
		return 0, 0, f.openFileErr
	}
	if f.openFileStatus != statusOK {
		return f.openFileStatus, 0, nil
	}
	n := int32(copy(out, f.openFilePayload))
	if f.openFileRead != nil {
		n = *f.openFileRead
	}
	return statusOK, n, nil
}

func (f *fakeLibrary) hardenProcess(flags uint32) int32 {
	f.hardenCalls++
	f.lastHardenFlags = &flags
	if f.harden == nil {
		return statusOK
	}
	return f.harden()
}

func mustWrapper(t *testing.T, service string, library kmsLibrary) *KeyWrapper {
	t.Helper()
	w, err := newKeyWrapper(service, library)
	if err != nil {
		t.Fatalf("newKeyWrapper(%q): %v", service, err)
	}
	return w
}

func TestKeyWrapper_SatisfiesTheKeyWrapperInterface(t *testing.T) {
	var _ hkdfguard.KeyWrapper = mustWrapper(t, "test.service", &fakeLibrary{})
}

func TestWrap_DelegatesToTheLibrary(t *testing.T) {
	library := &fakeLibrary{wrapPayload: []byte{10, 20, 30, 40}}
	w := mustWrapper(t, "service.a", library)
	plaintext := []byte{1, 2, 3, 4, 5}
	result := make([]byte, 16)

	n, err := w.Wrap(context.Background(), plaintext, result)

	if err != nil || n != 4 {
		t.Fatalf("Wrap = %d, %v; want 4, nil", n, err)
	}
	if library.wrapCalls != 1 || library.lastService != "service.a" || !bytes.Equal(library.lastWrapInput, plaintext) {
		t.Errorf("library saw %d calls, service %q, input %v", library.wrapCalls, library.lastService, library.lastWrapInput)
	}
	if !bytes.Equal(result[:4], []byte{10, 20, 30, 40}) {
		t.Errorf("result = %v", result[:4])
	}
}

func TestUnwrap_DelegatesToTheLibrary(t *testing.T) {
	dek := bytes.Repeat([]byte{0xD1}, DEKLength)
	library := &fakeLibrary{unwrapPayload: dek}
	w := mustWrapper(t, "service.a", library)
	wrapped := []byte{10, 20, 30, 40}
	result := make([]byte, DEKLength+8)

	n, err := w.Unwrap(context.Background(), wrapped, result)

	if err != nil || n != DEKLength {
		t.Fatalf("Unwrap = %d, %v; want %d, nil", n, err, DEKLength)
	}
	if library.unwrapCalls != 1 || library.lastService != "service.a" || !bytes.Equal(library.lastUnwrapIn, wrapped) {
		t.Errorf("library saw %d calls, service %q, input %v", library.unwrapCalls, library.lastService, library.lastUnwrapIn)
	}
	if !bytes.Equal(result[:DEKLength], dek) || !hkdfguard.IsZero(result[DEKLength:]) {
		t.Errorf("result = %v", result)
	}
}

func TestUnwrap_RevealingAnythingButADEKLengthKey_IsRefusedAndZeroed(t *testing.T) {
	for _, length := range []int{1, DEKLength - 1, DEKLength + 1} {
		library := &fakeLibrary{unwrapPayload: bytes.Repeat([]byte{0xD1}, length)}
		w := mustWrapper(t, "service.a", library)
		result := bytes.Repeat([]byte{0xAB}, DEKLength+8)

		n, err := w.Unwrap(context.Background(), []byte{10, 20, 30}, result)

		if err == nil || n != 0 {
			t.Errorf("%d bytes revealed: Unwrap = %d, %v; want 0 and an error", length, n, err)
		}
		if !hkdfguard.IsZero(result) {
			t.Errorf("%d bytes revealed: result = %v, want zeroed", length, result)
		}
	}
}

func TestGenerateAndWrap_DelegatesToTheLibrary(t *testing.T) {
	library := &fakeLibrary{generatePayload: []byte{11, 22, 33, 44, 55}}
	w := mustWrapper(t, "service.e", library)
	result := make([]byte, 16)

	n, err := w.GenerateAndWrap(context.Background(), result)

	if err != nil || n != 5 {
		t.Fatalf("GenerateAndWrap = %d, %v; want 5, nil", n, err)
	}
	if library.generateCalls != 1 || library.lastService != "service.e" {
		t.Errorf("library saw %d calls, service %q", library.generateCalls, library.lastService)
	}
	if !bytes.Equal(result[:5], []byte{11, 22, 33, 44, 55}) {
		t.Errorf("result = %v", result[:5])
	}
}

func TestFailures_ReportTheOperationServiceAndStatus(t *testing.T) {
	cases := []struct {
		op   string
		call func(*KeyWrapper) error
		set  func(*fakeLibrary, int32)
	}{
		{"wrap", func(w *KeyWrapper) error {
			_, err := w.Wrap(context.Background(), []byte{1, 2, 3}, make([]byte, 8))
			return err
		},
			func(f *fakeLibrary, s int32) { f.wrapStatus = s }},
		{"unwrap", func(w *KeyWrapper) error {
			_, err := w.Unwrap(context.Background(), []byte{10, 20, 30}, make([]byte, 8))
			return err
		},
			func(f *fakeLibrary, s int32) { f.unwrapStatus = s }},
		{"generate-and-wrap", func(w *KeyWrapper) error {
			_, err := w.GenerateAndWrap(context.Background(), make([]byte, 16))
			return err
		},
			func(f *fakeLibrary, s int32) { f.generateStatus = s }},
	}
	for _, c := range cases {
		for _, status := range []int32{-1, -2, -7} {
			library := &fakeLibrary{}
			c.set(library, status)
			w := mustWrapper(t, "service.d", library)

			err := c.call(w)

			var statusErr *StatusError
			if !errors.As(err, &statusErr) || statusErr.Status != status || statusErr.Op != c.op {
				t.Fatalf("%s/%d: error = %v", c.op, status, err)
			}
			want := "Native KMS " + c.op + " failed for service 'service.d' with status " + strconv.Itoa(int(status)) + "."
			if err.Error() != want {
				t.Errorf("%s/%d: message = %q, want %q", c.op, status, err.Error(), want)
			}
		}
	}
}

func TestAFailureTheLibraryCanDescribe_NamesWhatTheStatusMeans(t *testing.T) {
	library := &fakeLibrary{
		unwrapStatus: errKEKAccessDenied,
		describe: func(s int32) string {
			if s == errKEKAccessDenied {
				return "this account is not authorized to use the KEK"
			}
			return ""
		},
	}
	w := mustWrapper(t, "service.d", library)

	_, err := w.Unwrap(context.Background(), []byte{1}, make([]byte, 32))

	want := "Native KMS unwrap failed for service 'service.d' with status -18 (this account is not authorized to use the KEK)."
	if err == nil || err.Error() != want {
		t.Errorf("error = %v, want %q", err, want)
	}
}

func TestUnwrap_WhenTheLibraryFails_ZeroesTheResult(t *testing.T) {
	library := &fakeLibrary{unwrapStatus: -6, unwrapLeavesBytes: true}
	w := mustWrapper(t, "service.d", library)
	result := bytes.Repeat([]byte{0xAB}, 8)

	if _, err := w.Unwrap(context.Background(), []byte{10, 20, 30}, result); err == nil {
		t.Fatal("Unwrap succeeded")
	}
	if !hkdfguard.IsZero(result) {
		t.Errorf("result = %v, want zeroed", result)
	}
}

func TestASuccessClaimingMoreBytesThanTheBufferHolds_IsRefused(t *testing.T) {
	for _, written := range []int32{-1, 17} {
		written := written
		library := &fakeLibrary{writtenOverride: &written}
		w := mustWrapper(t, "service.a", library)
		result := bytes.Repeat([]byte{0xAB}, 16)

		if n, err := w.Wrap(context.Background(), make([]byte, 32), result); err == nil {
			t.Errorf("written %d: Wrap = %d, nil; want an error", written, n)
		}
		if _, err := w.Unwrap(context.Background(), make([]byte, 32), result); err == nil || !hkdfguard.IsZero(result) {
			t.Errorf("written %d: Unwrap error = %v, result zeroed = %v", written, err, hkdfguard.IsZero(result))
		}
	}
}

func TestACancelledContext_NeverReachesTheLibrary(t *testing.T) {
	library := &fakeLibrary{}
	w := mustWrapper(t, "service.g", library)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := w.Wrap(ctx, make([]byte, 32), make([]byte, 64)); !errors.Is(err, context.Canceled) {
		t.Errorf("Wrap error = %v", err)
	}
	if _, err := w.Unwrap(ctx, make([]byte, 64), make([]byte, 32)); !errors.Is(err, context.Canceled) {
		t.Errorf("Unwrap error = %v", err)
	}
	if _, err := w.GenerateAndWrap(ctx, make([]byte, 64)); !errors.Is(err, context.Canceled) {
		t.Errorf("GenerateAndWrap error = %v", err)
	}
	if calls := library.wrapCalls + library.unwrapCalls + library.generateCalls; calls != 0 {
		t.Errorf("library called %d times", calls)
	}
}

func TestAnInvalidServiceName_IsRejectedBeforeAnyNativeCall(t *testing.T) {
	for _, name := range []string{"", ".service", "my..service", "my-service", strings.Repeat("a", 129)} {
		library := &fakeLibrary{}
		if _, err := newKeyWrapper(name, library); !errors.Is(err, hkdfguard.ErrInvalidServiceName) {
			t.Errorf("%q: error = %v, want ErrInvalidServiceName", name, err)
		}
		if _, err := New(name); !errors.Is(err, hkdfguard.ErrInvalidServiceName) {
			t.Errorf("New(%q): error = %v, want ErrInvalidServiceName", name, err)
		}
		if calls := library.wrapCalls + library.unwrapCalls + library.generateCalls; calls != 0 {
			t.Errorf("%q: library called %d times", name, calls)
		}
	}
}
