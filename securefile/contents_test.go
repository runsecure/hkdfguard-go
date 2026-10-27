package securefile

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"strings"
	"testing"

	"github.com/runsecure/hkdfguard-go"
)

// reader is a read function over contents, as the platform reads hand readContents, recording how
// far it read.
type reader struct {
	contents []byte
	offset   int
}

func (r *reader) read(view []byte) (int, error) {
	count := copy(view, r.contents[r.offset:])
	r.offset += count
	return count, nil
}

func readBytes(contents []byte) ([]byte, error) {
	return readContents((&reader{contents: contents}).read, "v1.key")
}

func TestReadContents_ReturnsAWrappedKeyExactly_InASliceTheCallerOwns(t *testing.T) {
	key := wrapped()
	result, err := readBytes(key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result, key) {
		t.Fatalf("got %x; want %x", result, key)
	}
	if cap(result) != len(result) {
		t.Errorf("the result has capacity %d past its %d bytes", cap(result), len(result))
	}
}

func TestReadContents_AcceptsExactlyTheLimit(t *testing.T) {
	key := random(hkdfguard.MaxWrappedKeyBytes)
	result, err := readBytes(key)
	if err != nil || !bytes.Equal(result, key) {
		t.Fatalf("got %x, %v; want the key", result, err)
	}
}

func TestReadContents_RefusesAnEmptyFile(t *testing.T) {
	_, err := readBytes(nil)
	requireKeyFileError(t, err, hkdfguard.ErrInvalidKeyFile, "empty")
}

func TestReadContents_RefusesAFileOverTheLimit_ReadingOnlyOneBytePastIt(t *testing.T) {
	source := &reader{contents: bytes.Repeat([]byte{1}, hkdfguard.MaxWrappedKeyBytes*4)}
	_, err := readContents(source.read, "v1.key")
	requireKeyFileError(t, err, hkdfguard.ErrInvalidKeyFile, "larger than 512 bytes")
	if source.offset != hkdfguard.MaxWrappedKeyBytes+1 {
		t.Errorf("read %d bytes; want %d", source.offset, hkdfguard.MaxWrappedKeyBytes+1)
	}
}

func TestReadContents_RefusesAPlaintextKeyAsExposed(t *testing.T) {
	_, err := readBytes(random(32))
	requireKeyFileError(t, err, hkdfguard.ErrInvalidKeyFile, "exposed")
}

func TestReadContents_ReadsUntilTheEnd_HoweverTheReadsAreSplit(t *testing.T) {
	key := wrapped()
	chunks := [][]byte{key[:1], key[1:100], key[100:]}
	read := func(view []byte) (int, error) {
		if len(chunks) == 0 {
			return 0, io.EOF
		}
		n := copy(view, chunks[0])
		chunks = chunks[1:]
		return n, nil
	}
	result, err := readContents(read, "v1.key")
	if err != nil || !bytes.Equal(result, key) {
		t.Fatalf("got %x, %v; want the key", result, err)
	}
}

func TestReadContents_CountsBytesReadWithEOF(t *testing.T) {
	key := wrapped()
	result, err := readContents(func(view []byte) (int, error) { return copy(view, key), io.EOF }, "v1.key")
	if err != nil || !bytes.Equal(result, key) {
		t.Fatalf("got %x, %v; want the key", result, err)
	}
}

func TestReadContents_ZeroesItsBuffer_WhetherItReturnsOrRefuses(t *testing.T) {
	for _, length := range []int{32, 184} {
		var whole []byte
		read := func(view []byte) (int, error) {
			if whole != nil {
				return 0, nil
			}
			whole = view[:cap(view)]
			for i := range length {
				view[i] = 0xab
			}
			return length, nil
		}
		_, err := readContents(read, "v1.key")
		if length == 32 && err == nil {
			t.Fatal("a 32-byte key was accepted")
		}
		if len(whole) != hkdfguard.MaxWrappedKeyBytes+1 {
			t.Fatalf("the buffer is %d bytes; want %d", len(whole), hkdfguard.MaxWrappedKeyBytes+1)
		}
		if !hkdfguard.IsZero(whole) {
			t.Errorf("buffer not zeroed after a %d-byte read", length)
		}
	}
}

func TestReadContents_PassesOnAnErrorReading(t *testing.T) {
	failure := errors.New("disk on fire")
	_, err := readContents(func([]byte) (int, error) { return 0, failure }, "v1.key")
	if !errors.Is(err, failure) {
		t.Fatalf("got %v; want %v", err, failure)
	}
}

// A fixed key, so the standard and URL-safe encodings always differ: FB EF BE encodes as "++++",
// FF FF FF as "////". A random key would sometimes encode with neither, merging two rows.
func fixedKey() []byte {
	pattern := []byte{0xfb, 0xef, 0xbe, 0xff, 0xff, 0xff}
	key := make([]byte, 32)
	for i := range key {
		key[i] = pattern[i%len(pattern)]
	}
	return key
}

func TestLooksLikePlaintextKey_DetectsAKeyWrittenAsText(t *testing.T) {
	key := fixedKey()
	hexKey := strings.ToUpper(hex.EncodeToString(key))
	standard := base64.StdEncoding.EncodeToString(key)
	urlSafe := base64.RawURLEncoding.EncodeToString(key)
	for _, text := range []string{
		hexKey, strings.ToLower(hexKey) + "\n", standard, strings.TrimRight(standard, "="), urlSafe + "=", urlSafe + "\r\n",
		"  \t" + standard + " \n", "\v" + hexKey + "\f",
	} {
		if !looksLikePlaintextKey([]byte(text)) {
			t.Errorf("%q not detected", text)
		}
	}
}

func TestLooksLikePlaintextKey_DetectsARawKey(t *testing.T) {
	if !looksLikePlaintextKey(random(32)) || !looksLikePlaintextKey(make([]byte, 32)) {
		t.Error("a raw 32-byte key not detected")
	}
}

func TestLooksLikePlaintextKey_DoesNotDetectOtherText(t *testing.T) {
	for _, text := range []string{
		strings.Repeat("a", 63),        // one hex digit short
		strings.Repeat("a", 62) + "zz", // not hex
		strings.Repeat("A", 42),        // too short for base64
		strings.Repeat("A", 45),        // too long for base64
		strings.Repeat("A", 41) + "+-", // mixes the two alphabets
		strings.Repeat("A", 42) + "!",  // not base64
		strings.Repeat("A", 43) + "==", // 45 characters
		strings.Repeat("A", 42) + "==", // 44, but padded for 31 bytes
	} {
		if looksLikePlaintextKey([]byte(text)) {
			t.Errorf("%q detected", text)
		}
	}
}

func TestLooksLikePlaintextKey_DoesNotDetectAWrappedKey(t *testing.T) {
	if looksLikePlaintextKey(wrapped()) || looksLikePlaintextKey(random(plaintextTextScanLimit+1)) {
		t.Error("a wrapped key detected as plaintext")
	}
}

func TestReadTrustedKeyFile_RefusesAMissingOrUnusablePath_BeforeAnythingIsExamined(t *testing.T) {
	for _, path := range []string{"", "v1\x00.key"} {
		_, err := ReadTrustedKeyFile(t.Context(), path, AdministratorsOnly())
		if !errors.Is(err, fs.ErrInvalid) {
			t.Errorf("%q: %v; want fs.ErrInvalid", path, err)
		}
	}
}

func TestReadTrustedKeyFile_IsCancelledByItsContext_BeforeAnythingIsExamined(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := ReadTrustedKeyFile(ctx, "", AdministratorsOnly()); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v; want context.Canceled", err)
	}
}

func TestPlatformSupport_RefusesEverythingButWindowsLinuxAndAppleSilicon(t *testing.T) {
	for _, platform := range [][2]string{{"windows", "amd64"}, {"windows", "arm64"}, {"linux", "amd64"}, {"linux", "arm64"}, {"darwin", "arm64"}} {
		if err := platformSupport(platform[0], platform[1]); err != nil {
			t.Errorf("%s/%s: %v", platform[0], platform[1], err)
		}
	}
	requireErrorContaining(t, platformSupport("freebsd", "amd64"), ErrUnsupportedPlatform, "Windows, Linux and macOS only")
	requireErrorContaining(t, platformSupport("darwin", "amd64"), ErrUnsupportedPlatform, "Apple silicon Macs only; this process is amd64")
}

func TestKeyFileTrust_CopiesItsLists(t *testing.T) {
	sids := []string{"S-1-5-21-1-2-3-1005"}
	users := []uint32{1001}
	groups := []uint32{2001}
	trust := NewKeyFileTrust(KeyFileTrustOptions{WindowsPrincipals: sids, UnixUserIDs: users, UnixGroupIDs: groups})
	sids[0], users[0], groups[0] = "S-1-1-0", 0, 0

	if got := trust.WindowsPrincipals(); len(got) != 1 || got[0] != "S-1-5-21-1-2-3-1005" {
		t.Errorf("WindowsPrincipals = %v", got)
	}
	if got := trust.UnixUserIDs(); len(got) != 1 || got[0] != 1001 {
		t.Errorf("UnixUserIDs = %v", got)
	}
	if got := trust.UnixGroupIDs(); len(got) != 1 || got[0] != 2001 {
		t.Errorf("UnixGroupIDs = %v", got)
	}

	// What the accessors return is a copy too.
	trust.UnixUserIDs()[0] = 0
	trust.WindowsPrincipals()[0] = "S-1-1-0"
	if trust.UnixUserIDs()[0] != 1001 || trust.WindowsPrincipals()[0] != "S-1-5-21-1-2-3-1005" {
		t.Error("changing an accessor's result changed the trust")
	}
	if !NewKeyFileTrust(KeyFileTrustOptions{UnixUserIDs: []uint32{4294967295}}).isTrustedUser(4294967295) {
		t.Error("the largest uid is not trusted")
	}
}

func TestKeyFileTrust_TrustsNoOneElseByDefault(t *testing.T) {
	for _, trust := range []KeyFileTrust{AdministratorsOnly(), {}, NewKeyFileTrust(KeyFileTrustOptions{})} {
		if len(trust.WindowsPrincipals())+len(trust.UnixUserIDs())+len(trust.UnixGroupIDs()) != 0 {
			t.Errorf("%+v trusts someone", trust)
		}
		if !trust.isTrustedUser(0) || trust.isTrustedUser(1000) || trust.isTrustedGroup(0) {
			t.Errorf("%+v: root must be trusted, and no one else", trust)
		}
	}
}

func TestKeyFileError_UnwrapsAnUntrustedLocationToPermissionToo(t *testing.T) {
	err := error(untrustedUnix("/etc/v1.key", "because"))
	if !errors.Is(err, ErrUntrusted) || !errors.Is(err, fs.ErrPermission) || errors.Is(err, fs.ErrNotExist) {
		t.Errorf("%v: want ErrUntrusted and fs.ErrPermission only", err)
	}
	notFound := error(keyFileError(fs.ErrNotExist, "v1.key", "missing"))
	if !errors.Is(notFound, fs.ErrNotExist) || errors.Is(notFound, ErrUntrusted) || errors.Is(notFound, fs.ErrPermission) {
		t.Errorf("%v: want fs.ErrNotExist only", notFound)
	}
	if (&KeyFileError{}).Unwrap() != nil {
		t.Error("a KeyFileError with no Err unwraps to something")
	}
}
