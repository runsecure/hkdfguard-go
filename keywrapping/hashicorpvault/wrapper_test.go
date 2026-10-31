package hashicorpvault

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/internal/kmstest"
)

// contextBase64 is testContext as the wrapper sends it: base64 of its UTF-8.
const contextBase64 = "aGtkZmd1YXJkLnRlc3Q="

// --- Construction --------------------------------------------------------------------------------

func TestNew_RefusesMissingOrInvalidArguments(t *testing.T) {
	client := newFakeTransit(t).newClient(t)
	for name, call := range map[string]func() (*KeyWrapper, error){
		"no client":           func() (*KeyWrapper, error) { return New(nil, testKeyName, Options{}) },
		"a context not UTF-8": func() (*KeyWrapper, error) { return New(client, testKeyName, Options{Context: "\xff"}) },
		"a context too long": func() (*KeyWrapper, error) {
			return New(client, testKeyName, Options{Context: strings.Repeat("c", MaxContextLength+1)})
		},
	} {
		if wrapper, err := call(); !errors.Is(err, ErrInvalidArgument) || wrapper != nil {
			t.Errorf("%s: %v, %v; want ErrInvalidArgument", name, wrapper, err)
		}
	}
}

func TestNew_RefusesAKeyNameThatIsntOne(t *testing.T) {
	client := newFakeTransit(t).newClient(t)
	for _, name := range []string{"", ".", "..", "team/kek", "my kek", "kek?x=1", "kék", "kek\x00", strings.Repeat("k", MaxKeyNameLength+1)} {
		if _, err := New(client, name, Options{}); !errors.Is(err, ErrInvalidArgument) || !strings.Contains(err.Error(), "isn't one") {
			t.Errorf("%q: %v", name, err)
		}
	}
	if _, err := New(client, strings.Repeat("k", MaxKeyNameLength), Options{}); err != nil {
		t.Errorf("the longest key name: %v", err)
	}
}

func TestNew_RefusesAMountPathThatIsntOne_AndDefaultsToTransit(t *testing.T) {
	client := newFakeTransit(t).newClient(t)
	for _, mount := range []string{".", "transit/../sys", "/transit", "transit/", "transit//a", "team a", "transit?x"} {
		if _, err := New(client, testKeyName, Options{MountPath: mount}); !errors.Is(err, ErrInvalidArgument) || !strings.Contains(err.Error(), "isn't a Vault path") {
			t.Errorf("%q: %v", mount, err)
		}
	}
	if wrapper := newWrapper(t, client); wrapper.encryptPath != "/v1/transit/encrypt/"+testKeyName {
		t.Errorf("encrypt path %q", wrapper.encryptPath)
	}
}

func TestNew_RefusesAnAddressThatWouldExposeTheTokenOrDEKs(t *testing.T) {
	for _, address := range []string{
		"http://vault.example.com:8200",
		"http://10.0.0.5:8200",
		"https://user:pass@vault.example.com:8200",
		"https://vault.example.com:8200/?x=1",
		"https://vault.example.com:8200/#f",
		"ftp://vault.example.com",
	} {
		_, err := New(newClientAt(t, address, nil), testKeyName, Options{})
		if !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("%s: %v; want ErrInvalidArgument", address, err)
		} else if strings.Contains(err.Error(), "pass") {
			t.Errorf("%s: the error shows the password: %v", address, err)
		}
	}
}

func TestNew_AllowsHTTPSAnywhere_AndHTTPOnLoopbackOrAUnixSocket(t *testing.T) {
	for _, address := range []string{
		"https://vault.example.com:8200",
		"https://vault.example.com/vault",
		"http://127.0.0.1:8200",
		"http://127.1.2.3:8200",
		"http://localhost:8200",
		"http://LOCALHOST:8200",
		"http://[::1]:8200",
		"unix:///var/run/vault-agent.sock",
	} {
		if _, err := New(newClientAt(t, address, nil), testKeyName, Options{}); err != nil {
			t.Errorf("%s: %v", address, err)
		}
	}
}

func TestNew_RefusesAClientWhoseHTTPClientFollowsRedirects_UnlessAllowed(t *testing.T) {
	address := newFakeTransit(t).server.URL
	for name, checkRedirect := range map[string]func(*http.Request, []*http.Request) error{
		"net/http's default (none)":  nil,
		"one that lets them through": func(*http.Request, []*http.Request) error { return nil },
	} {
		client := newClientAt(t, address, func(c *api.Config) { c.HttpClient.CheckRedirect = checkRedirect })
		if _, err := New(client, testKeyName, Options{}); !errors.Is(err, ErrInvalidArgument) || !strings.Contains(err.Error(), "follows redirects") {
			t.Errorf("%s: %v; want ErrInvalidArgument", name, err)
		}
		if _, err := New(client, testKeyName, Options{AllowRedirects: true}); err != nil {
			t.Errorf("%s, allowed: %v", name, err)
		}
	}
	stops := newClientAt(t, address, func(c *api.Config) {
		c.HttpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("no redirects") }
	})
	if _, err := New(stops, testKeyName, Options{}); err != nil {
		t.Errorf("a CheckRedirect that refuses them: %v", err)
	}
}

func TestNew_IsAKeyWrapper_KeepingTheNameAsGiven_AndMakesNoCall(t *testing.T) {
	fake := newFakeTransit(t)
	wrapper := newWrapper(t, fake.newClient(t))
	var _ hkdfguard.KeyWrapper = wrapper
	if wrapper.KeyName() != testKeyName {
		t.Errorf("KeyName() = %q", wrapper.KeyName())
	}
	if len(fake.recorded()) != 0 {
		t.Error("a call was made")
	}
}

// --- Wrap and unwrap -----------------------------------------------------------------------------

func TestKeyWrapper_RoundTripsADEK(t *testing.T) {
	wrapper := newWrapper(t, newFakeTransit(t).newClient(t), withContext())
	dek := random(32)
	wrapped := wrapWith(t, wrapper, dek)
	if !bytes.HasPrefix(wrapped, []byte("vault:v1:")) {
		t.Errorf("wrapped %q; want Vault's ciphertext", wrapped)
	}
	revealed := make([]byte, 32)
	if n, err := wrapper.Unwrap(t.Context(), wrapped, revealed); err != nil || n != 32 || !bytes.Equal(revealed, dek) {
		t.Fatalf("%d, %v; want the DEK", n, err)
	}
}

func TestKeyWrapper_RoundTripsADEKOverHTTPS(t *testing.T) {
	fake := newFakeTransit(t)
	server := httptest.NewTLSServer(fake)
	t.Cleanup(server.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	client := newClientAt(t, server.URL, func(c *api.Config) {
		if err := c.ConfigureTLS(&api.TLSConfig{CACertBytes: ca}); err != nil {
			t.Fatal(err)
		}
	})
	wrapper := newWrapper(t, client, withContext())
	dek := random(32)
	revealed := make([]byte, 32)
	if n, err := wrapper.Unwrap(t.Context(), wrapWith(t, wrapper, dek), revealed); err != nil || n != 32 || !bytes.Equal(revealed, dek) {
		t.Fatalf("%d, %v; want the DEK", n, err)
	}
}

func TestKeyWrapper_RoundTripsADEKOverAUnixSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("api.NewClient can't parse a Windows path in a unix:// address; Linux and macOS cover this.")
	}
	fake := newFakeTransit(t)
	socket := filepath.Join(t.TempDir(), "vault.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Skipf("Unix sockets aren't available here: %v", err)
	}
	server := &http.Server{Handler: fake, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })

	wrapper := newWrapper(t, newClientAt(t, "unix://"+socket, nil), withContext())
	dek := random(32)
	revealed := make([]byte, 32)
	if n, err := wrapper.Unwrap(t.Context(), wrapWith(t, wrapper, dek), revealed); err != nil || n != 32 || !bytes.Equal(revealed, dek) {
		t.Fatalf("%d, %v; want the DEK", n, err)
	}
}

func TestWrap_EncryptsUnderTheKeyWithTheContext_SendingExactlyTheDotNetBody(t *testing.T) {
	fake := newFakeTransit(t)
	wrapper := newWrapper(t, fake.newClient(t), withContext())
	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i)
	}
	wrapWith(t, wrapper, dek)

	request := fake.recorded()[0]
	// What the .NET wrapper sends for this DEK and context, byte for byte.
	want := `{"plaintext":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=","associated_data":"` + contextBase64 + `"}`
	if request.Operation != "encrypt" || request.Key != testKeyName || string(request.Body) != want {
		t.Errorf("%s %s %s; want encrypt of the DEK with the context", request.Operation, request.Key, request.Body)
	}
	if request.Token != testToken || request.Namespace != "" || request.ContentType != "application/json" || request.VaultRequest != "true" {
		t.Errorf("headers: token %q, namespace %q, content type %q, X-Vault-Request %q", request.Token, request.Namespace, request.ContentType, request.VaultRequest)
	}
	if unexpected := fake.unexpectedRequests(); len(unexpected) != 0 {
		t.Errorf("unexpected requests %v", unexpected)
	}
}

func TestUnwrap_DecryptsUnderTheKeyWithTheContext_SendingExactlyTheDotNetBody(t *testing.T) {
	fake := newFakeTransit(t)
	wrapper := newWrapper(t, fake.newClient(t), withContext())
	wrapped := wrapWith(t, wrapper, random(32))
	if _, err := wrapper.Unwrap(t.Context(), wrapped, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	request := fake.recorded()[1]
	if want := `{"ciphertext":"` + string(wrapped) + `","associated_data":"` + contextBase64 + `"}`; request.Operation != "decrypt" ||
		request.Key != testKeyName || string(request.Body) != want {
		t.Errorf("%s %s %s; want decrypt of %s", request.Operation, request.Key, request.Body, want)
	}
}

func TestWrap_ZeroesTheRequestBodyItSentOnceTheCallReturns_AndLeavesTheCallersPlaintextAlone(t *testing.T) {
	fake := newFakeTransit(t)
	var mu sync.Mutex
	var sent [][]byte
	// The client hands every request to its callbacks before sending it: the body is the
	// wrapper's own buffer, sent as it is.
	client := fake.newClient(t).WithRequestCallbacks(func(r *api.Request) {
		mu.Lock()
		defer mu.Unlock()
		sent = append(sent, r.BodyBytes)
	})
	dek := random(32)
	original := bytes.Clone(dek)
	wrapper := newWrapper(t, client, withContext())
	wrapWith(t, wrapper, dek)
	generate(t, wrapper) // with a context: generated here, then encrypted

	if !bytes.Equal(dek, original) {
		t.Error("the caller's plaintext was modified")
	}
	requests := fake.recorded()
	if len(sent) != 2 || len(requests) != 2 {
		t.Fatalf("%d bodies sent, %d received; want 2", len(sent), len(requests))
	}
	if requests[0].field("plaintext") != base64.StdEncoding.EncodeToString(dek) {
		t.Error("Vault wasn't sent the DEK")
	}
	if decoded, _ := base64.StdEncoding.DecodeString(requests[1].field("plaintext")); len(decoded) != GeneratedKeyLength {
		t.Errorf("a generated DEK of %d bytes was sent; want %d", len(decoded), GeneratedKeyLength)
	}
	for i, body := range sent {
		if len(body) == 0 || !hkdfguard.IsZero(body) {
			t.Errorf("request %d: the body sent was not zeroed", i)
		}
	}
}

func TestWrap_ZeroesTheRequestBody_WhenTheCallFails(t *testing.T) {
	fake := newFakeTransit(t)
	fake.answerAlways(http.StatusForbidden, `{"errors":["permission denied"]}`)
	var sent []byte
	client := fake.newClient(t).WithRequestCallbacks(func(r *api.Request) { sent = r.BodyBytes })
	if _, err := newWrapper(t, client).Wrap(t.Context(), random(32), make([]byte, 512)); err == nil {
		t.Fatal("the wrap succeeded")
	}
	if len(sent) == 0 || !hkdfguard.IsZero(sent) {
		t.Error("the body sent was not zeroed")
	}
}

func TestGenerateAndWrap_WithNoContext_HasVaultGenerateAWrappedAES256KeyOnly(t *testing.T) {
	fake := newFakeTransit(t)
	wrapper := newWrapper(t, fake.newClient(t))
	wrapped := generate(t, wrapper)
	revealed := make([]byte, 32)
	n, err := wrapper.Unwrap(t.Context(), wrapped, revealed)
	if err != nil || n != GeneratedKeyLength || hkdfguard.IsZero(revealed) {
		t.Fatalf("%d, %v; want 32 non-zero bytes", n, err)
	}
	requests := fake.recorded()
	if requests[0].Operation != "datakey" || requests[0].Key != testKeyName || string(requests[0].Body) != `{"bits":256}` {
		t.Errorf("%s %s %s; want datakey/wrapped of 256 bits", requests[0].Operation, requests[0].Key, requests[0].Body)
	}
	if string(requests[1].Body) != `{"ciphertext":"`+string(wrapped)+`"}` {
		t.Errorf("decrypt body %s; want the ciphertext alone", requests[1].Body)
	}
	if bytes.Equal(generate(t, wrapper), wrapped) {
		t.Error("each generated DEK should be fresh")
	}
}

func TestKeyWrapper_WithAnEmptyContext_SendsNone_AndGeneratesInVault(t *testing.T) {
	fake := newFakeTransit(t)
	wrapper := newWrapper(t, fake.newClient(t), Options{Context: ""})
	wrapped := wrapWith(t, wrapper, random(32))
	if _, err := wrapper.Unwrap(t.Context(), wrapped, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	generate(t, wrapper)
	requests := fake.recorded()
	for _, request := range requests {
		if strings.Contains(string(request.Body), "associated_data") {
			t.Errorf("%s sent associated_data: %s", request.Operation, request.Body)
		}
	}
	if requests[2].Operation != "datakey" {
		t.Errorf("generated with %s; want datakey", requests[2].Operation)
	}
}

func TestGenerateAndWrap_WithAContext_GeneratesHere_AndEncryptsWithIt(t *testing.T) {
	// datakey/wrapped ignores associated_data, so it can't bind a context.
	fake := newFakeTransit(t)
	wrapper := newWrapper(t, fake.newClient(t), withContext())
	revealed := make([]byte, 32)
	if _, err := wrapper.Unwrap(t.Context(), generate(t, wrapper), revealed); err != nil {
		t.Fatal(err)
	}
	request := fake.recorded()[0]
	sent, _ := base64.StdEncoding.DecodeString(request.field("plaintext"))
	if request.Operation != "encrypt" || request.field("associated_data") != contextBase64 || !bytes.Equal(sent, revealed) || hkdfguard.IsZero(revealed) {
		t.Errorf("%s %s; want the generated DEK encrypted with the context", request.Operation, request.Body)
	}
}

func TestKeyWrapper_EncodesTheContextAsUTF8(t *testing.T) {
	fake := newFakeTransit(t)
	context := "café € \U0001F511"
	wrapWith(t, newWrapper(t, fake.newClient(t), Options{Context: context}), random(32))
	if got := fake.recorded()[0].field("associated_data"); got != base64.StdEncoding.EncodeToString([]byte("caf\xc3\xa9 \xe2\x82\xac \xf0\x9f\x94\x91")) {
		t.Errorf("associated_data %q", got)
	}
}

func TestNew_AcceptsTheLongestContext(t *testing.T) {
	wrapper := newWrapper(t, newFakeTransit(t).newClient(t), Options{Context: strings.Repeat("c", MaxContextLength)})
	dek := random(32)
	revealed := make([]byte, 32)
	if n, err := wrapper.Unwrap(t.Context(), wrapWith(t, wrapper, dek), revealed); err != nil || n != 32 || !bytes.Equal(revealed, dek) {
		t.Fatalf("%d, %v; want the DEK", n, err)
	}
}

func TestUnwrap_KeepsUnwrappingKeyFilesMadeBeforeTheKeyRotated_UntilTheirVersionIsTooOld(t *testing.T) {
	fake := newFakeTransit(t)
	wrapper := newWrapper(t, fake.newClient(t), withContext())
	dek := random(32)
	before := wrapWith(t, wrapper, dek)
	fake.rotate(testKeyName)
	after := wrapWith(t, wrapper, random(32))
	if !bytes.HasPrefix(before, []byte("vault:v1:")) || !bytes.HasPrefix(after, []byte("vault:v2:")) {
		t.Errorf("made as %.9s and %.9s; want v1 then v2", before, after)
	}
	revealed := make([]byte, 32)
	if n, err := wrapper.Unwrap(t.Context(), before, revealed); err != nil || n != 32 || !bytes.Equal(revealed, dek) {
		t.Fatalf("%d, %v; want the DEK", n, err)
	}

	fake.setMinDecryptionVersion(testKeyName, 2)
	result := filled(32)
	_, err := wrapper.Unwrap(t.Context(), before, result)
	requireVaultError(t, err, "Vault transit unwrap failed for key '"+testKeyName+
		"': Vault answered 400 Bad Request: ciphertext or signature version is disallowed by policy (too old)")
	if !hkdfguard.IsZero(result) {
		t.Error("the result was not zeroed")
	}
	if _, err := wrapper.Unwrap(t.Context(), after, make([]byte, 32)); err != nil {
		t.Errorf("the current version: %v", err)
	}
}

func TestWrap_OfTheLargestPlaintext_FitsTheKeyFileLimit(t *testing.T) {
	wrapper := newWrapper(t, newFakeTransit(t).newClient(t), withContext())
	dek := random(MaxPlaintextLength)
	revealed := make([]byte, len(dek))
	if n, err := wrapper.Unwrap(t.Context(), wrapWith(t, wrapper, dek), revealed); err != nil || n != len(dek) || !bytes.Equal(revealed, dek) {
		t.Fatalf("%d, %v; want the DEK", n, err)
	}
}

func TestWrap_WritesIntoTheStartOfALargerResult(t *testing.T) {
	wrapper := newWrapper(t, newFakeTransit(t).newClient(t))
	result := filled(hkdfguard.MaxWrappedKeyBytes)
	n, err := wrapper.Wrap(t.Context(), random(32), result)
	if err != nil || n == 0 || !bytes.Equal(result[n:], filled(len(result)-n)) {
		t.Fatalf("%d, %v", n, err)
	}
}

func TestUnwrap_WritesIntoTheStartOfALargerResult(t *testing.T) {
	wrapper := newWrapper(t, newFakeTransit(t).newClient(t))
	dek := random(32)
	result := filled(64)
	n, err := wrapper.Unwrap(t.Context(), wrapWith(t, wrapper, dek), result)
	if err != nil || n != 32 || !bytes.Equal(result[:32], dek) || !bytes.Equal(result[32:], filled(32)) {
		t.Fatalf("%d, %v, % x", n, err, result)
	}
}

func TestKeyWrapper_UsesTheMountThePathPrefixAndTheClientsNamespace(t *testing.T) {
	fake := newFakeTransit(t)
	fake.mountPath, fake.pathPrefix = "transit/team-a", "/vault"
	client := fake.newClient(t)
	client.SetNamespace("team-a/prod")
	wrapper := newWrapper(t, client, Options{MountPath: "transit/team-a"})
	if _, err := wrapper.Unwrap(t.Context(), generate(t, wrapper), make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	for _, request := range fake.recorded() {
		if request.Namespace != "team-a/prod" {
			t.Errorf("%s in namespace %q", request.Operation, request.Namespace)
		}
	}
	if unexpected := fake.unexpectedRequests(); len(unexpected) != 0 {
		t.Errorf("unexpected requests %v", unexpected)
	}
}

func TestKeyWrapper_FollowsATokenTheApplicationReplaces(t *testing.T) {
	fake := newFakeTransit(t)
	client := fake.newClient(t)
	wrapper := newWrapper(t, client)
	client.SetToken("hvs.expired")
	if _, err := wrapper.GenerateAndWrap(t.Context(), make([]byte, 512)); err == nil {
		t.Fatal("a request with the old token succeeded")
	}
	client.SetToken(testToken) // as a LifetimeWatcher or the application's own login would
	generate(t, wrapper)
}

// --- Refusals ------------------------------------------------------------------------------------

func TestUnwrap_RefusesADEKWrappedUnderAnotherKey_NamingVaultsAnswer_AndZeroesTheResult(t *testing.T) {
	fake := newFakeTransit(t)
	fake.addKey("other-kek")
	client := fake.newClient(t)
	wrapped := wrapWith(t, newWrapperOver(t, client, "other-kek", withContext()), random(32))
	result := filled(32)
	_, err := newWrapper(t, client, withContext()).Unwrap(t.Context(), wrapped, result)
	vaultErr := requireVaultError(t, err, "Vault transit unwrap failed for key '"+testKeyName+"': Vault answered 400 Bad Request: cipher: message authentication failed")
	var refusal *api.ResponseError
	if vaultErr.Op != "unwrap" || vaultErr.KeyName != testKeyName || !errors.As(err, &refusal) || refusal.StatusCode != http.StatusBadRequest {
		t.Errorf("Op %q, KeyName %q, cause %v; want Vault's 400", vaultErr.Op, vaultErr.KeyName, vaultErr.Err)
	}
	if !hkdfguard.IsZero(result) {
		t.Error("the result was not zeroed")
	}
	if requests := fake.recorded(); len(requests) != 2 || requests[1].Key != testKeyName {
		t.Error("decrypt wasn't pinned to the wrapper's key")
	}
}

func TestUnwrap_RefusesADEKWrappedUnderAnotherContext_OrNone(t *testing.T) {
	client := newFakeTransit(t).newClient(t)
	for _, contexts := range [][2]string{{testContext, testContext + ".other"}, {testContext, ""}, {"", testContext}} {
		wrapped := wrapWith(t, newWrapper(t, client, Options{Context: contexts[0]}), random(32))
		_, err := newWrapper(t, client, Options{Context: contexts[1]}).Unwrap(t.Context(), wrapped, make([]byte, 32))
		requireVaultError(t, err, "...400 Bad Request: cipher: message authentication failed")
	}
}

func TestUnwrap_RefusesATamperedDEK(t *testing.T) {
	wrapper := newWrapper(t, newFakeTransit(t).newClient(t), withContext())
	wrapped := wrapWith(t, wrapper, random(32))
	// Another base64 character, so it still reaches Vault and fails there.
	tampered := bytes.Clone(wrapped)
	if tampered[12] == 'A' {
		tampered[12] = 'B'
	} else {
		tampered[12] = 'A'
	}
	result := filled(32)
	_, err := wrapper.Unwrap(t.Context(), tampered, result)
	requireVaultError(t, err, "...400 Bad Request: cipher: message authentication failed")
	if !hkdfguard.IsZero(result) {
		t.Error("the result was not zeroed")
	}
}

func TestUnwrap_RefusesWhatIsntAVaultCiphertext_WithoutCallingVault_ZeroingTheResult(t *testing.T) {
	fake := newFakeTransit(t)
	wrapper := newWrapper(t, fake.newClient(t))
	for wrapped, message := range map[string]string{
		"": "A wrapped DEK is 1-512 bytes; got 0.",
		"vault:v1:" + strings.Repeat("A", hkdfguard.MaxWrappedKeyBytes): "A wrapped DEK is 1-512 bytes; got 521.",
		"vault:v1:":               "...isn't one.",
		"vault:v:AAAA":            "...isn't one.",
		"vault:x1:AAAA":           "...isn't one.",
		"vault:v12345678901:AAAA": "...isn't one.",
		`vault:v1:AA"},"x":"AA`:   "...isn't one.",
		"vault:v1:AA AA":          "...isn't one.",
		"VAULT:v1:AAAA":           "...isn't one.",
		"\x01\x02\x03":            "...isn't one.",
	} {
		result := filled(32)
		_, err := wrapper.Unwrap(t.Context(), []byte(wrapped), result)
		if vaultErr := requireVaultError(t, err, message); vaultErr.Op != "unwrap" || vaultErr.Err != nil {
			t.Errorf("%q: Op %q, Err %v", wrapped, vaultErr.Op, vaultErr.Err)
		}
		if !hkdfguard.IsZero(result) {
			t.Errorf("%q: the result was not zeroed", wrapped)
		}
	}
	if len(fake.recorded()) != 0 {
		t.Error("Vault was called")
	}
}

func TestIsVaultCiphertext_AcceptsOnlyVaultsFormat(t *testing.T) {
	for value, want := range map[string]bool{
		"vault:v1:AAAA":               true,
		"vault:v1234567890:AB+/=":     true,
		"vault:v1:":                   false,
		"vault:v:AAAA":                false,
		"vault:v1AAAA":                false,
		"vault:v12345678901:AAAA":     false,
		"vault:v1:AA-A":               false,
		"vault:v1:AA\nA":              false,
		"vault:":                      false,
		"":                            false,
		"vault:v1":                    false,
		"xvault:v1:AAAA":              false,
		"vault:v１:AAAA":               false,
		"vault:v1:AAAA\x00":           false,
		"vault:v0000000001:AAAAAAAAA": true,
	} {
		if got := isVaultCiphertext([]byte(value)); got != want {
			t.Errorf("isVaultCiphertext(%q) = %v; want %v", value, got, want)
		}
	}
}

func TestUnwrap_RefusesAResultTooSmallForTheRevealedKey_ZeroingIt(t *testing.T) {
	wrapper := newWrapper(t, newFakeTransit(t).newClient(t))
	result := filled(31)
	_, err := wrapper.Unwrap(t.Context(), wrapWith(t, wrapper, random(32)), result)
	if !errors.Is(err, ErrInvalidArgument) || !strings.Contains(err.Error(), "The revealed key is 32 bytes; result holds 31.") {
		t.Fatalf("got %v; want ErrInvalidArgument", err)
	}
	if !hkdfguard.IsZero(result) {
		t.Error("the result was not zeroed")
	}
}

func TestWrap_RefusesAPlaintextOutOfBounds_WithoutCallingVault(t *testing.T) {
	fake := newFakeTransit(t)
	wrapper := newWrapper(t, fake.newClient(t))
	for _, plaintext := range [][]byte{nil, {}, random(MaxPlaintextLength + 1)} {
		_, err := wrapper.Wrap(t.Context(), plaintext, make([]byte, 512))
		if !errors.Is(err, ErrInvalidArgument) || !strings.Contains(err.Error(), "Vault transit wraps 1-256 bytes") {
			t.Errorf("%d bytes: %v", len(plaintext), err)
		}
	}
	if len(fake.recorded()) != 0 {
		t.Error("Vault was called")
	}
}

func TestKeyWrapper_RefusesAResultTooSmallForTheWrappedDEK_LeavingItAsItWas(t *testing.T) {
	fake := newFakeTransit(t)
	fake.answerAlways(http.StatusOK, envelope(map[string]any{"ciphertext": "vault:v1:" + strings.Repeat("A", 52)}, nil))
	for name, wrapper := range map[string]*KeyWrapper{
		"no context": newWrapper(t, fake.newClient(t)), "a context": newWrapper(t, fake.newClient(t), withContext()),
	} {
		for op, call := range map[string]func([]byte) (int, error){
			"wrap":              func(result []byte) (int, error) { return wrapper.Wrap(t.Context(), random(32), result) },
			"generate-and-wrap": func(result []byte) (int, error) { return wrapper.GenerateAndWrap(t.Context(), result) },
		} {
			result := filled(60)
			if _, err := call(result); !errors.Is(err, ErrInvalidArgument) || !strings.Contains(err.Error(), "The wrapped DEK is 61 bytes; result holds 60.") {
				t.Errorf("%s, %s: %v", name, op, err)
			}
			if !bytes.Equal(result, filled(60)) {
				t.Errorf("%s, %s: the result was changed", name, op)
			}
		}
	}
}

func TestWrap_RefusesAnAnswerThatIsntACiphertext(t *testing.T) {
	ignored := []string{"Endpoint ignored these unrecognized parameters: [associated_data]"}
	for because, body := range map[string]string{
		"not JSON":                "<html>proxy</html>",
		"not an object":           "[]",
		"truncated":               `{"data":{"ciphertext":"vault:v1:AAAA"}`,
		"no data":                 envelope(nil, nil),
		"data not an object":      `{"data":"x"}`,
		"no ciphertext":           envelope(map[string]any{"key_version": 1}, nil),
		"ciphertext not a string": envelope(map[string]any{"ciphertext": 7}, nil),
		"ciphertext empty":        envelope(map[string]any{"ciphertext": ""}, nil),
		"ciphertext twice":        `{"data":{"ciphertext":"vault:v1:AAAA","ciphertext":"vault:v1:BBBB"}}`,
		"ciphertext in two datas": `{"data":{"ciphertext":"vault:v1:AAAA"},"data":{"ciphertext":"vault:v1:BBBB"}}`,
		"not a ciphertext":        envelope(map[string]any{"ciphertext": "AAAA"}, nil),
		"over the key file limit": envelope(map[string]any{"ciphertext": "vault:v1:" + strings.Repeat("A", hkdfguard.MaxWrappedKeyBytes)}, nil),
		"a parameter ignored":     envelope(map[string]any{"ciphertext": "vault:v1:AAAA"}, ignored),
	} {
		fake := newFakeTransit(t)
		fake.answerAlways(http.StatusOK, body)
		result := filled(2 * hkdfguard.MaxWrappedKeyBytes)
		_, err := newWrapper(t, fake.newClient(t), withContext()).Wrap(t.Context(), random(32), result)
		var vaultErr *Error
		if !errors.As(err, &vaultErr) || vaultErr.Op != "wrap" {
			t.Errorf("%s: %v; want an *Error", because, err)
		}
		if len(fake.recorded()) != 1 {
			t.Errorf("%s: %d requests; want 1", because, len(fake.recorded()))
		}
		if !bytes.Equal(result, filled(len(result))) {
			t.Errorf("%s: the result was changed", because)
		}
	}
}

func TestWrap_NamesWhatWasWrongWithAnAnswer(t *testing.T) {
	fake := newFakeTransit(t)
	wrapper := newWrapper(t, fake.newClient(t), withContext())
	prefix := "Vault transit wrap for key '" + testKeyName + "' "
	for body, message := range map[string]string{
		"[]": prefix + "returned a response that isn't Vault's.",
		envelope(map[string]any{"key_version": 1}, nil):     prefix + "returned no ciphertext.",
		envelope(map[string]any{"ciphertext": "AAAA"}, nil): prefix + "returned something that isn't a ciphertext.",
		envelope(map[string]any{"ciphertext": "vault:v1:" + strings.Repeat("A", hkdfguard.MaxWrappedKeyBytes)}, nil): prefix +
			"returned 521 bytes; a wrapped DEK is at most 512.",
	} {
		fake.answerAlways(http.StatusOK, body)
		_, err := wrapper.Wrap(t.Context(), random(32), make([]byte, 1024))
		requireVaultError(t, err, message)
	}
}

func TestWrap_UnescapesAnEscapedAnswer(t *testing.T) {
	// vault:v1:AB+/ with '+' as a \u escape and '/' as \/, as a proxy re-encoding the answer might
	// write it.
	fake := newFakeTransit(t)
	fake.answerAlways(http.StatusOK, `{"data":{"ciphertext":"vault:v1:AB+\/"}}`)
	if wrapped := wrapWith(t, newWrapper(t, fake.newClient(t)), random(32)); string(wrapped) != "vault:v1:AB+/" {
		t.Errorf("wrapped %q", wrapped)
	}
}

func TestWrap_AcceptsAnAnswerWithOtherWarnings(t *testing.T) {
	fake := newFakeTransit(t)
	fake.answerAlways(http.StatusOK, `{"data":{"ciphertext":"vault:v1:AAAA"},"warnings":[7,{"unrecognized parameters":1},"some other warning",null]}`)
	if wrapped := wrapWith(t, newWrapper(t, fake.newClient(t)), random(32)); string(wrapped) != "vault:v1:AAAA" {
		t.Errorf("wrapped %q", wrapped)
	}
}

func TestKeyWrapper_RefusesAVaultThatIgnoresTheContext_RatherThanWrappingUnbound(t *testing.T) {
	fake := newFakeTransit(t)
	fake.ignoresAssociatedData = true
	wrapper := newWrapper(t, fake.newClient(t), withContext())
	_, err := wrapper.GenerateAndWrap(t.Context(), make([]byte, 512))
	requireVaultError(t, err, "Vault transit wrap for key '"+testKeyName+
		"' ignored a parameter it was sent, so its answer can't be used: a context needs a Vault that supports associated_data.")

	// An escaped or differently cased warning says the same.
	fake.answerAlways(http.StatusOK, `{"data":{"plaintext":"AAAA"},"warnings":["Endpoint ignored these UNRECOGNIZED parameters: [associated_data]"]}`)
	result := filled(32)
	_, err = wrapper.Unwrap(t.Context(), []byte("vault:v1:AAAA"), result)
	requireVaultError(t, err, "...ignored a parameter it was sent...")
	if !hkdfguard.IsZero(result) {
		t.Error("the result was not zeroed")
	}
}

func TestUnwrap_RefusesAnAnswerThatIsntAPlaintext_ZeroingTheResult(t *testing.T) {
	fake := newFakeTransit(t)
	wrapper := newWrapper(t, fake.newClient(t))
	notBase64 := "Vault transit unwrap for key '" + testKeyName + "' returned a plaintext that isn't base64."
	for body, message := range map[string]string{
		`{"data":{"plaintext":"not base64!"}}`: notBase64,
		`{"data":{"plaintext":"AAA"}}`:         notBase64,
		`{"data":{"plaintext":"AA\nAA=="}}`:    notBase64,
		`{"data":{"plaintext":""}}`:            "Vault transit unwrap for key '" + testKeyName + "' returned no plaintext.",
		`{"data":{}}`:                          "Vault transit unwrap for key '" + testKeyName + "' returned no plaintext.",
		`{"data":{"plaintext":7}}`:             "Vault transit unwrap for key '" + testKeyName + "' returned a response that isn't Vault's.",
	} {
		fake.answerAlways(http.StatusOK, body)
		result := filled(32)
		_, err := wrapper.Unwrap(t.Context(), []byte("vault:v1:AAAA"), result)
		requireVaultError(t, err, message)
		if !hkdfguard.IsZero(result) {
			t.Errorf("%s: the result was not zeroed", body)
		}
	}
}

func TestKeyWrapper_RefusesAnAnswerOverTheResponseLimit_AndReadsOneOfExactlyIt(t *testing.T) {
	fake := newFakeTransit(t)
	wrapper := newWrapper(t, fake.newClient(t))
	fake.answerAlways(http.StatusOK, envelope(map[string]any{"ciphertext": "vault:v1:AAAA", "padding": strings.Repeat("x", maxResponseLength)}, nil))
	_, err := wrapper.Wrap(t.Context(), random(32), make([]byte, 512))
	requireVaultError(t, err, "Vault's answer for key '"+testKeyName+"' is over 16384 bytes; a transit answer is far smaller.")

	body := envelope(map[string]any{"ciphertext": "vault:v1:AAAA", "padding": ""}, nil)
	body = strings.Replace(body, `"padding":""`, `"padding":"`+strings.Repeat("x", maxResponseLength-len(body))+`"`, 1)
	if len(body) != maxResponseLength {
		t.Fatalf("the answer is %d bytes", len(body))
	}
	fake.answerAlways(http.StatusOK, body)
	if wrapped := wrapWith(t, wrapper, random(32)); string(wrapped) != "vault:v1:AAAA" {
		t.Errorf("wrapped %q", wrapped)
	}
}

// --- Redirects and the address -------------------------------------------------------------------

// elsewhere is a server a redirect could point at, which records whether anything reached it.
func elsewhere(t *testing.T) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var reached []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		reached = append(reached, r.Header.Get("X-Vault-Token"))
		mu.Unlock()
		respond(w, http.StatusOK, nil, envelope(map[string]any{"ciphertext": "vault:v1:AAAA"}, nil))
	}))
	t.Cleanup(server.Close)
	return server, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), reached...)
	}
}

func TestKeyWrapper_FollowsNoRedirect_WhetherOrNotTheClientWould(t *testing.T) {
	target, reached := elsewhere(t)
	for _, code := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		for name, disable := range map[string]bool{"the client's default": false, "DisableRedirects": true} {
			fake := newFakeTransit(t)
			fake.setAnswer(func(request transitRequest, _ int) (int, http.Header, string, bool) {
				return code, http.Header{"Location": {target.URL + "/v1/transit/encrypt/" + testKeyName}}, "", true
			})
			client := newClientAt(t, fake.server.URL, func(c *api.Config) { c.DisableRedirects = disable })
			_, err := newWrapper(t, client).Wrap(t.Context(), random(32), make([]byte, 512))
			requireVaultError(t, err, "Vault transit wrap failed for key '"+testKeyName+"': Vault answered "+status(code)+
				", a redirect to "+target.URL+"/v1/transit/encrypt/"+testKeyName+", which isn't followed: it would carry the Vault token there...")
			if len(fake.recorded()) != 1 {
				t.Errorf("%d, %s: %d requests; want 1", code, name, len(fake.recorded()))
			}
		}
	}
	if got := reached(); len(got) != 0 {
		t.Errorf("the redirect target was reached, with tokens %q", got)
	}
}

func TestKeyWrapper_WithAllowRedirects_FollowsTheClientsRedirect_ResendingTheBody(t *testing.T) {
	fake := newFakeTransit(t)
	fake.setAnswer(func(request transitRequest, count int) (int, http.Header, string, bool) {
		if count == 1 {
			return http.StatusTemporaryRedirect, http.Header{"Location": {fake.server.URL + "/v1/transit/encrypt/" + testKeyName}}, "", true
		}
		return 0, nil, "", false
	})
	wrapper := newWrapper(t, fake.newClient(t), Options{AllowRedirects: true})
	dek := random(32)
	wrapped := wrapWith(t, wrapper, dek)
	fake.setAnswer(nil)
	revealed := make([]byte, 32)
	if n, err := wrapper.Unwrap(t.Context(), wrapped, revealed); err != nil || n != 32 || !bytes.Equal(revealed, dek) {
		t.Fatalf("%d, %v; want the DEK", n, err)
	}
	requests := fake.recorded()
	if len(requests) != 3 || !bytes.Equal(requests[0].Body, requests[1].Body) {
		t.Errorf("%d requests; want the encrypt body sent again to the redirect's target", len(requests))
	}
}

func TestKeyWrapper_ChecksTheAddressAgainOnEveryCall(t *testing.T) {
	fake := newFakeTransit(t)
	client := fake.newClient(t)
	wrapper := newWrapper(t, client)
	if err := client.SetAddress("http://vault.example.com:8200"); err != nil {
		t.Fatal(err)
	}
	result := filled(32)
	if _, err := wrapper.Unwrap(t.Context(), []byte("vault:v1:AAAA"), result); !errors.Is(err, ErrInvalidArgument) || !strings.Contains(err.Error(), "must be https") {
		t.Errorf("got %v; want ErrInvalidArgument", err)
	}
	if _, err := wrapper.GenerateAndWrap(t.Context(), make([]byte, 512)); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("got %v; want ErrInvalidArgument", err)
	}
	if !hkdfguard.IsZero(result) {
		t.Error("the result was not zeroed")
	}
}

func TestKeyWrapper_RefusesAClientSetToOutputACurlCommandOrPolicyInsteadOfSending(t *testing.T) {
	fake := newFakeTransit(t)
	for name, set := range map[string]func(*api.Client){
		"curl":   func(c *api.Client) { c.SetOutputCurlString(true) },
		"policy": func(c *api.Client) { c.SetOutputPolicy(true) },
	} {
		client := fake.newClient(t)
		wrapper := newWrapper(t, client)
		set(client)
		if _, err := wrapper.Wrap(t.Context(), random(32), make([]byte, 512)); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("%s: %v; want ErrInvalidArgument", name, err)
		}
	}
	if len(fake.recorded()) != 0 {
		t.Error("Vault was called")
	}
}

// --- Failures ------------------------------------------------------------------------------------

func TestFailures_AVaultRefusalNamesTheStatusAndVaultsErrors_WithTheClientsErrorAsTheCause_AndIsntRetried(t *testing.T) {
	fake := newFakeTransit(t)
	client := fake.newClient(t)
	client.SetToken("hvs.revoked")
	_, err := newWrapper(t, client).Wrap(t.Context(), random(32), make([]byte, 512))
	vaultErr := requireVaultError(t, err, "Vault transit wrap failed for key '"+testKeyName+"': Vault answered 403 Forbidden: 1 error occurred:\n\t* permission denied\n\n")
	var refusal *api.ResponseError
	if vaultErr.Op != "wrap" || !errors.As(err, &refusal) || refusal.StatusCode != http.StatusForbidden {
		t.Errorf("Op %q, cause %v; want Vault's 403", vaultErr.Op, vaultErr.Err)
	}
	if len(fake.recorded()) != 1 {
		t.Errorf("%d requests; want 1", len(fake.recorded()))
	}
}

func TestFailures_SeveralErrorsAreJoined(t *testing.T) {
	fake := newFakeTransit(t)
	fake.answerAlways(http.StatusBadRequest, `{"errors":["first","second"]}`)
	_, err := newWrapper(t, fake.newClient(t)).GenerateAndWrap(t.Context(), make([]byte, 512))
	requireVaultError(t, err, "Vault transit generate-and-wrap failed for key '"+testKeyName+"': Vault answered 400 Bad Request: first; second")
}

func TestFailures_ARefusalThatIsntVaultsJSON_IsReportedByItsStatus(t *testing.T) {
	fake := newFakeTransit(t)
	wrapper := newWrapper(t, fake.newClient(t))
	for _, body := range []string{"<html>bad gateway</html>", `{"errors":"x"}`, "[]", "{}", ""} {
		fake.answerAlways(http.StatusNotFound, body)
		_, err := wrapper.GenerateAndWrap(t.Context(), make([]byte, 512))
		requireVaultError(t, err, "Vault transit generate-and-wrap failed for key '"+testKeyName+"': Vault answered 404 Not Found")
	}
}

func TestFailures_ATransientFailureIsRetriedByTheClient(t *testing.T) {
	for _, status := range []int{http.StatusServiceUnavailable, http.StatusInternalServerError, http.StatusTooManyRequests} {
		fake := newFakeTransit(t)
		fake.setAnswer(func(_ transitRequest, count int) (int, http.Header, string, bool) {
			return status, nil, `{"errors":["Vault is sealed"]}`, count <= 2
		})
		wrapper := newWrapper(t, fake.newClient(t), withContext())
		dek := random(32)
		wrapped := wrapWith(t, wrapper, dek)
		requests := fake.recorded()
		if len(requests) != 3 || !bytes.Equal(requests[0].Body, requests[2].Body) {
			t.Errorf("%d: %d requests; want the same body sent 3 times", status, len(requests))
		}
		revealed := make([]byte, 32)
		if _, err := wrapper.Unwrap(t.Context(), wrapped, revealed); err != nil || !bytes.Equal(revealed, dek) {
			t.Errorf("%d: %v; want the DEK", status, err)
		}
	}
}

func TestFailures_ATransientFailureThatOutlastsTheRetries_NamesTheLastAnswer(t *testing.T) {
	fake := newFakeTransit(t)
	fake.answerAlways(http.StatusServiceUnavailable, `{"errors":["Vault is sealed"]}`)
	_, err := newWrapper(t, fake.newClient(t)).GenerateAndWrap(t.Context(), make([]byte, 512))
	requireVaultError(t, err, "Vault transit generate-and-wrap failed for key '"+testKeyName+"': Vault answered 503 Service Unavailable: Vault is sealed")
	if len(fake.recorded()) != 3 {
		t.Errorf("%d requests; want the client's 2 retries", len(fake.recorded()))
	}
}

func TestFailures_NotImplementedIsntRetried(t *testing.T) {
	fake := newFakeTransit(t)
	fake.answerAlways(http.StatusNotImplemented, `{"errors":[]}`)
	_, err := newWrapper(t, fake.newClient(t)).GenerateAndWrap(t.Context(), make([]byte, 512))
	requireVaultError(t, err, "...Vault answered 501 Not Implemented")
	if len(fake.recorded()) != 1 {
		t.Errorf("%d requests; want 1", len(fake.recorded()))
	}
}

func TestFailures_ALostConnectionIsRetriedByTheClient(t *testing.T) {
	fake := newFakeTransit(t)
	var once sync.Once
	fake.setOnRequest(func(*http.Request) {
		once.Do(func() { panic(http.ErrAbortHandler) }) // the connection is dropped without an answer
	})
	generate(t, newWrapper(t, fake.newClient(t)))
	if len(fake.recorded()) != 2 {
		t.Errorf("%d requests; want 2", len(fake.recorded()))
	}
}

func TestFailures_AnUnreachableVaultIsAnErrorWithTheClientsMessage(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	address := server.URL
	server.Close()
	client := newClientAt(t, address, func(c *api.Config) { c.MaxRetries = 0 })
	result := filled(32)
	_, err := newWrapper(t, client).Unwrap(t.Context(), []byte("vault:v1:AAAA"), result)
	vaultErr := requireVaultError(t, err, "Vault transit unwrap failed for key '"+testKeyName+"': ...")
	if vaultErr.Err == nil || !strings.Contains(err.Error(), vaultErr.Err.Error()) {
		t.Errorf("got %v; want the client's error as the cause, and its message", err)
	}
	if !hkdfguard.IsZero(result) {
		t.Error("the result was not zeroed")
	}
}

func TestFailures_TheClientsTimeoutIsAnError_SayingSo(t *testing.T) {
	fake := newFakeTransit(t)
	fake.setOnRequest(func(r *http.Request) { <-r.Context().Done() })
	client := fake.newClient(t)
	client.SetClientTimeout(50 * time.Millisecond)
	_, err := newWrapper(t, client).GenerateAndWrap(t.Context(), make([]byte, 512))
	requireVaultError(t, err, "Vault transit generate-and-wrap failed for key '"+testKeyName+"': no answer within the client's timeout (50ms)")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("got %v; want the client's deadline as the cause", err)
	}
}

func TestFailures_AnEndedContextMakesNoCall(t *testing.T) {
	fake := newFakeTransit(t)
	for _, options := range []Options{{}, withContext()} {
		kmstest.RequireEndedContextRefused(t, newWrapper(t, fake.newClient(t), options), []byte("vault:v1:AAAA"))
	}
	if len(fake.recorded()) != 0 {
		t.Error("Vault was called")
	}
}

func TestFailures_ACancellationOrTimeoutInFlightMatchesTheContextsError_AndUnwrapZeroesTheResult(t *testing.T) {
	fake := newFakeTransit(t)
	fake.setOnRequest(func(r *http.Request) { <-r.Context().Done() })
	wrapper := newWrapper(t, fake.newClient(t))

	ctx, cancel := context.WithCancel(t.Context())
	time.AfterFunc(50*time.Millisecond, cancel)
	result := filled(32)
	_, err := wrapper.Unwrap(ctx, []byte("vault:v1:AAAA"), result)
	if !errors.Is(err, context.Canceled) || errors.Is(err, ErrVault) {
		t.Errorf("unwrap: %v (%T); want the cancellation", err, err)
	}
	if !hkdfguard.IsZero(result) {
		t.Error("the result was not zeroed")
	}

	ctx, cancel = context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	_, err = wrapper.GenerateAndWrap(ctx, make([]byte, 512))
	if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrVault) {
		t.Errorf("generate-and-wrap: %v (%T); want the timeout", err, err)
	}
	if len(fake.recorded()) != 2 {
		t.Errorf("%d requests; want 2, neither retried", len(fake.recorded()))
	}
}

func TestKeyWrapper_IsSafeForConcurrentUse(t *testing.T) {
	wrapper := newWrapper(t, newFakeTransit(t).newClient(t), withContext())
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for range 16 {
		wg.Go(func() {
			dek := random(32)
			wrapped := make([]byte, hkdfguard.MaxWrappedKeyBytes)
			n, err := wrapper.Wrap(context.Background(), dek, wrapped)
			if err == nil {
				revealed := make([]byte, 32)
				if _, err = wrapper.Unwrap(context.Background(), wrapped[:n], revealed); err == nil && !bytes.Equal(revealed, dek) {
					err = errors.New("another DEK was revealed")
				}
			}
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
}
