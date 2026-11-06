package securefile

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"math"
	"testing"
)

// The bounded read ReadTrustedFile and ParseTrustedFile make, over in-memory contents; the
// platform tests read real files.

const trustedFileLimit = 64

func readBoundedBytes(r *reader, maxBytes int) ([]byte, error) {
	var result []byte
	err := readBounded(r.read, "secret.enc", maxBytes, func(contents []byte) error {
		result = bytes.Clone(contents)
		return nil
	})
	return result, err
}

func TestReadBounded_ReturnsTheContentsExactly(t *testing.T) {
	contents := random(40)
	got, err := readBoundedBytes(&reader{contents: contents}, trustedFileLimit)
	if err != nil || !bytes.Equal(got, contents) {
		t.Fatalf("got %x, %v; want the contents", got, err)
	}
}

func TestReadBounded_AcceptsExactlyTheLimit(t *testing.T) {
	contents := random(trustedFileLimit)
	got, err := readBoundedBytes(&reader{contents: contents}, trustedFileLimit)
	if err != nil || !bytes.Equal(got, contents) {
		t.Fatalf("got %x, %v; want the contents", got, err)
	}
}

func TestReadBounded_AnEmptyFile_IsHandedOverEmpty(t *testing.T) {
	called := false
	err := readBounded((&reader{}).read, "secret.enc", trustedFileLimit, func(contents []byte) error {
		called = true
		if len(contents) != 0 {
			t.Errorf("got %d bytes; want none", len(contents))
		}
		return nil
	})
	if err != nil || !called {
		t.Fatalf("called %v, %v; want the empty contents handed over", called, err)
	}
}

func TestReadBounded_OverTheLimit_IsRefused_ReadingOnlyOneBytePast(t *testing.T) {
	r := &reader{contents: make([]byte, trustedFileLimit*4)}
	called := false
	err := readBounded(r.read, "secret.enc", trustedFileLimit, func([]byte) error { called = true; return nil })

	requireKeyFileError(t, err, ErrTooLarge, "'secret.enc' is larger than 64 bytes")
	if called {
		t.Error("the contents were handed over")
	}
	if r.offset != trustedFileLimit+1 {
		t.Errorf("read %d bytes; want %d", r.offset, trustedFileLimit+1)
	}
}

func TestReadBounded_AppliesNoKeyFileRules(t *testing.T) {
	// ReadTrustedKeyFile refuses exactly 32 bytes as a probable plaintext key; a trusted file leaves
	// the contents to its caller.
	contents := random(PlaintextKeyLength)
	got, err := readBoundedBytes(&reader{contents: contents}, trustedFileLimit)
	if err != nil || !bytes.Equal(got, contents) {
		t.Fatalf("got %x, %v; want the contents", got, err)
	}
}

func TestReadBounded_ZeroesTheBuffer_OnceUsed(t *testing.T) {
	var seen []byte
	err := readBounded((&reader{contents: random(40)}).read, "secret.enc", trustedFileLimit, func(contents []byte) error {
		seen = contents // kept only to check it was zeroed
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(seen, make([]byte, len(seen))) {
		t.Errorf("the buffer handed over holds %x after use; want it zeroed", seen)
	}
}

func TestReadBounded_AnErrorFromUseOrRead_IsReturnedAsItIs(t *testing.T) {
	refused := errors.New("refused")
	if err := readBounded((&reader{contents: random(3)}).read, "secret.enc", trustedFileLimit, func([]byte) error { return refused }); err != refused {
		t.Errorf("use: got %v; want its own error", err)
	}
	failing := func([]byte) (int, error) { return 0, refused }
	if err := readBounded(failing, "secret.enc", trustedFileLimit, func([]byte) error { return nil }); err != refused {
		t.Errorf("read: got %v; want its own error", err)
	}
}

func TestReadTrustedFile_InvalidArguments_AreRefusedBeforeAnythingIsOpened(t *testing.T) {
	trust := AdministratorsOnly()
	for _, c := range []struct {
		path     string
		maxBytes int
	}{{"", trustedFileLimit}, {"secret\x00.enc", trustedFileLimit}, {"secret.enc", 0}, {"secret.enc", -1}, {"secret.enc", math.MaxInt}} {
		if _, err := ReadTrustedFile(t.Context(), c.path, trust, c.maxBytes); !errors.Is(err, fs.ErrInvalid) {
			t.Errorf("%q, %d: %v; want fs.ErrInvalid", c.path, c.maxBytes, err)
		}
	}
	if _, err := ParseTrustedFile[int](t.Context(), "secret.enc", trust, trustedFileLimit, nil); !errors.Is(err, fs.ErrInvalid) {
		t.Errorf("a nil parse: %v; want fs.ErrInvalid", err)
	}
	if _, err := ParseTrustedFile(t.Context(), "secret.enc", trust, -1, func(c []byte) (int, error) { return len(c), nil }); !errors.Is(err, fs.ErrInvalid) {
		t.Errorf("a negative limit: %v; want fs.ErrInvalid", err)
	}
}

func TestReadTrustedFile_IsCancelledByItsContext_BeforeAnythingIsExamined(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := ReadTrustedFile(ctx, "secret.enc", AdministratorsOnly(), trustedFileLimit); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v; want context.Canceled", err)
	}
}

func TestCapitalized_UpperCasesTheFirstLetterOnly(t *testing.T) {
	for in, want := range map[string]string{"key file": "Key file", "file": "File", "": "", "File": "File"} {
		if got := capitalized(in); got != want {
			t.Errorf("capitalized(%q) = %q; want %q", in, got, want)
		}
	}
}
