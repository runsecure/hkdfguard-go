package azurekeyvault

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
)

const (
	testWrapVersion = "0123456789abcdef0123456789abcdef"
	testSignVersion = "fedcba9876543210fedcba9876543210"
)

// errFormat is what the envelope tests' fail returns.
var errFormat = errors.New("format")

func testFail(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errFormat, fmt.Sprintf(format, args...))
}

func requireFormatError(t *testing.T, err error, text string) {
	t.Helper()
	if !errors.Is(err, errFormat) || !strings.Contains(err.Error(), text) {
		t.Errorf("got %v; want a format error containing %q", err, text)
	}
}

func mustBuild(t *testing.T, version string, ciphertext []byte) []byte {
	t.Helper()
	unsigned, err := buildUnsigned(version, ciphertext, testFail)
	if err != nil {
		t.Fatal(err)
	}
	return unsigned
}

func buildEnvelope(t *testing.T, ciphertextLength int) []byte {
	t.Helper()
	unsigned := mustBuild(t, testWrapVersion, random(ciphertextLength))
	result := make([]byte, len(unsigned)+80)
	if _, err := write(unsigned, testSignVersion, random(64), result, testFail); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestEnvelope_RoundTripsEveryPartThroughWriteAndParse(t *testing.T) {
	ciphertext, signature := random(256), random(64)
	unsigned := mustBuild(t, strings.ToUpper(testWrapVersion), ciphertext)
	result := make([]byte, 512)

	n, err := write(unsigned, testSignVersion, signature, result, testFail)
	if err != nil || n != 256+overhead {
		t.Fatalf("%d, %v", n, err)
	}
	p, err := parse(result[:n], testFail)
	if err != nil {
		t.Fatal(err)
	}
	if p.wrappingKeyVersion != testWrapVersion || !bytes.Equal(p.wrappedDEK, ciphertext) || p.signingKeyVersion != testSignVersion ||
		!bytes.Equal(p.signature, signature) || p.unsignedLength != headerLength+256 {
		t.Errorf("parts %+v", p)
	}
}

func TestEnvelope_IsTheOtherPortsLayout_ByteForByte(t *testing.T) {
	// The format every port writes and reads; a key file made by any of them must be read by the
	// others. The same bytes as the Java, Python and Node tests'.
	unsigned := mustBuild(t, testWrapVersion, []byte{0xc1, 0xc2, 0xc3})
	result := make([]byte, len(unsigned)+80)
	if _, err := write(unsigned, testSignVersion, bytes.Repeat([]byte{0x5a}, 64), result, testFail); err != nil {
		t.Fatal(err)
	}
	want := "48474b56" + "01" + testWrapVersion + "0003" + "c1c2c3" + testSignVersion + strings.Repeat("5a", 64)
	if got := hex.EncodeToString(result); got != want {
		t.Errorf("envelope\n%s; want\n%s", got, want)
	}
	context, _ := encodeContext("myapp")
	want = hex.EncodeToString([]byte("HkdfGuard-AzureKeyVault-wrap-v1\x00")) + "0005" + hex.EncodeToString([]byte("myapp")) + hex.EncodeToString(unsigned)
	if got := hex.EncodeToString(signedData(unsigned, context)); got != want {
		t.Errorf("signed data\n%s; want\n%s", got, want)
	}
}

func TestEnvelope_RefusesToParseWhatIsNotOne(t *testing.T) {
	for _, data := range [][]byte{make([]byte, overhead), random(300), {}, []byte("HGKV")} {
		_, err := parse(data, testFail)
		requireFormatError(t, err, "not a wrapped DEK written by AzureKeyVaultKeyWrapper")
	}
}

func TestEnvelope_RefusesAnotherFormatVersion(t *testing.T) {
	data := buildEnvelope(t, 256)
	data[4] = 2
	_, err := parse(data, testFail)
	requireFormatError(t, err, "format version 2")
}

func TestEnvelope_RefusesALengthThatDisagreesWithTheHeader(t *testing.T) {
	data := buildEnvelope(t, 256)
	for _, changed := range [][]byte{data[:len(data)-1], append(bytes.Clone(data), 0)} {
		_, err := parse(changed, testFail)
		requireFormatError(t, err, "but its header describes")
	}
}

func TestEnvelope_ReadsTheCiphertextLengthAsUnsigned(t *testing.T) {
	p, err := parse(buildEnvelope(t, 0x8001), testFail)
	if err != nil || len(p.wrappedDEK) != 0x8001 {
		t.Fatalf("%v, %d", err, len(p.wrappedDEK))
	}
}

func TestEnvelope_RefusesAnEmptyCiphertext(t *testing.T) {
	data := buildEnvelope(t, 256)
	data[21], data[22] = 0, 0
	_, err := parse(data[:overhead+1], testFail)
	requireFormatError(t, err, "")
}

func TestEnvelope_ParsesIntoCopies(t *testing.T) {
	data := buildEnvelope(t, 256)
	p, err := parse(data, testFail)
	if err != nil {
		t.Fatal(err)
	}
	dek, signature := bytes.Clone(p.wrappedDEK), bytes.Clone(p.signature)
	clear(data)
	if !bytes.Equal(p.wrappedDEK, dek) || !bytes.Equal(p.signature, signature) {
		t.Error("a part changed with the envelope")
	}
}

func TestEnvelope_RefusesToBuildACiphertextItCantEncode(t *testing.T) {
	for _, length := range []int{0, 0x10000} {
		_, err := buildUnsigned(testWrapVersion, make([]byte, length), testFail)
		requireFormatError(t, err, fmt.Sprintf("a %d-byte wrapped key", length))
	}
}

func TestEnvelope_RefusesAVersionThatIsntKeyVaults_LeavingResultAsItWas(t *testing.T) {
	for _, version := range []string{"", testWrapVersion[:31], testWrapVersion + "0", strings.Repeat("g", 32), strings.Repeat("０", 32),
		" " + testWrapVersion[1:], testWrapVersion[:30] + "\n"} {
		_, err := buildUnsigned(version, random(256), testFail)
		requireFormatError(t, err, "not 32 hex digits")

		result := filled(512)
		_, err = write(mustBuild(t, testWrapVersion, random(256)), version, random(64), result, testFail)
		requireFormatError(t, err, "not 32 hex digits")
		if !bytes.Equal(result, filled(512)) {
			t.Errorf("%q: result was changed", version)
		}
	}
}

func TestEnvelope_RefusesASignatureThatIsntES256s(t *testing.T) {
	unsigned := mustBuild(t, testWrapVersion, random(256))
	for _, length := range []int{0, 63, 65, 96} {
		_, err := write(unsigned, testSignVersion, make([]byte, length), make([]byte, 512), testFail)
		requireFormatError(t, err, fmt.Sprintf("a %d-byte signature", length))
	}
}

func TestEnvelope_RefusesAResultTooSmall_LeavingItAsItWas(t *testing.T) {
	result := filled(358)
	_, err := write(mustBuild(t, testWrapVersion, random(256)), testSignVersion, random(64), result, testFail)
	if !errors.Is(err, ErrInvalidArgument) || !strings.Contains(err.Error(), "is 359 bytes; result holds 358") {
		t.Errorf("got %v", err)
	}
	if !bytes.Equal(result, filled(358)) {
		t.Error("result was changed")
	}
}

func TestEnvelope_SignsOverTheDomainTheContextAndTheEnvelope(t *testing.T) {
	unsigned := mustBuild(t, testWrapVersion, random(256))
	signed := signedData(unsigned, []byte("app"))
	if bytes.Equal(signed, signedData(unsigned, []byte("apq"))) || bytes.Equal(signed, signedData(unsigned, nil)) {
		t.Error("the context is not signed")
	}
	changed := bytes.Clone(unsigned)
	changed[len(changed)-1] ^= 1
	if bytes.Equal(signed, signedData(changed, []byte("app"))) {
		t.Error("the envelope is not signed")
	}
	// The context is length-prefixed, so it can't run into the envelope.
	tail := unsigned[4:]
	if bytes.Equal(signedData(append(bytes.Clone(magic), tail...), []byte("ab")), signedData(append([]byte("b"+string(magic)), tail...), []byte("a"))) {
		t.Error("the context is not length-prefixed")
	}
}

func TestEnvelope_EncodesTheContextAsUTF8(t *testing.T) {
	for _, context := range []string{"", "café \U0001f511", strings.Repeat("x", 65535)} {
		if encoded, err := encodeContext(context); err != nil || string(encoded) != context {
			t.Errorf("%.20q: %v", context, err)
		}
	}
}

func TestEnvelope_RefusesAContextTooLongToLengthPrefix_OrNotUTF8(t *testing.T) {
	for context, text := range map[string]string{
		strings.Repeat("x", 65536): "65536 bytes in UTF-8; at most 65535",
		strings.Repeat("é", 32768): "at most 65535",
		"\xed\xb0\x80app":          "isn't valid UTF-8", // a lone surrogate, as WTF-8
		"app\xff":                  "isn't valid UTF-8",
	} {
		if _, err := encodeContext(context); !errors.Is(err, ErrInvalidArgument) || !strings.Contains(err.Error(), text) {
			t.Errorf("%.20q: %v; want %q", context, err, text)
		}
	}
}

// --- Key identifiers -----------------------------------------------------------------------------

func mustParseKeyID(t *testing.T, id string) keyID {
	t.Helper()
	key, err := parseKeyID(id)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestKeyID_IsParsedAndNormalized(t *testing.T) {
	for id, want := range map[string]keyID{
		"https://MyVault.Vault.Azure.NET/keys/My-Key":                           {"https://myvault.vault.azure.net", "My-Key", ""},
		"HTTPS://myvault.vault.azure.net:08443/keys/k/" + testWrapVersion + "/": {"https://myvault.vault.azure.net:8443", "k", testWrapVersion},
		"https://myvault.managedhsm.azure.net/keys/k/":                          {"https://myvault.managedhsm.azure.net", "k", ""},
	} {
		if got := mustParseKeyID(t, id); got != want {
			t.Errorf("%q: %+v; want %+v", id, got, want)
		}
	}
	if got := mustParseKeyID(t, "https://myvault.managedhsm.azure.net/keys/k/").String(); got != "https://myvault.managedhsm.azure.net/keys/k" {
		t.Errorf("String() = %q", got)
	}
}

func TestKeyID_NamesTheSameKeyWhateverTheVersionAndTheNamesCase_ButNotInAnotherVault(t *testing.T) {
	key := mustParseKeyID(t, "https://myvault.vault.azure.net/keys/my-key")
	if !key.sameKey(mustParseKeyID(t, "https://MYVAULT.vault.azure.net/keys/MY-KEY/"+testWrapVersion)) {
		t.Error("not the same key in another version and case")
	}
	for _, other := range []string{"https://myvault.vault.azure.net:443/keys/my-key", "https://other.vault.azure.net/keys/my-key",
		"https://myvault.vault.azure.net/keys/my-key2"} {
		if key.sameKey(mustParseKeyID(t, other)) {
			t.Errorf("%q is the same key", other)
		}
	}
}

func TestKeyID_WithVersionNamesAVersionOfTheSameKey(t *testing.T) {
	key := mustParseKeyID(t, "https://myvault.vault.azure.net/keys/my-key")
	if got := key.withVersion(testWrapVersion).String(); got != "https://myvault.vault.azure.net/keys/my-key/"+testWrapVersion {
		t.Errorf("withVersion = %q", got)
	}
	if key.version != "" {
		t.Error("the key was changed")
	}
}

func TestKeyID_RefusesWhatIsntAKeyIdentifier(t *testing.T) {
	for _, id := range []string{
		"", "https://myvault.vault.azure.net/keys/" + strings.Repeat("k", 128),
		"https://myvault.vault.azure.net/keys/k/v-1", "https://myvault.vault.azure.net//keys/k", "https:///keys/k", "https://myvault.vault.azure.net/keys/k%2D1",
		"https://-myvault.vault.azure.net/keys/k", "http://myvault.vault.azure.net/keys/k", "https://myvault.vault.azure.net/secrets/k",
		"https://myvault.vault.azure.net/Keys/k", `https://myvault.vault.azure.net\keys\k`, "https://myvault.vault.azure.net/keys/./k",
		"https://myvault.vault.azure.net/keys/x/../k", "https://user@myvault.vault.azure.net/keys/k", "https://myvault.vault.azure.net:99999/keys/k",
		"https://myvault.vault.azure.net/keys/k?api-version=7.4", "https://myvault.vault.azure.net/keys/k#v", " https://myvault.vault.azure.net/keys/k",
		"https://myvault.vault.azure.net/keys/k\n", "https://[::1]/keys/k", "https://myvault.vault.azure.net/keys/k/v/w",
		"https://myvault.vault.azure.net/keys/k\x00",
	} {
		if _, err := parseKeyID(id); !errors.Is(err, ErrInvalidArgument) || !strings.Contains(err.Error(), "isn't a Key Vault key identifier") {
			t.Errorf("%q: %v", id, err)
		}
	}
}
