package integration

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"

	"github.com/runsecure/hkdfguard-go/dek"
	"github.com/runsecure/hkdfguard-go/keywrapping/azurekeyvault"
	"github.com/runsecure/hkdfguard-go/securefile"
)

// The Azure Key Vault key wrapper with the rest of HkdfGuard: a release pipeline wrapping and
// signing its key through Key Vault into a key file, and an application building a ring from it -
// and generating a runtime key - through the same wrapper. Key Vault is an in-process stand-in
// behind the Azure SDK's own client, holding a real RSA key and EC P-256 key, so these run
// everywhere; the real-Key Vault round trips are keywrapping/azurekeyvault's integration tests.

const (
	azureVault       = "https://hkdfguard-e2e.vault.azure.net"
	azureWrapKeyID   = azureVault + "/keys/wrap"
	azureSignKeyID   = azureVault + "/keys/sign"
	azureContext     = "hkdfguard.integrationtest"
	azureLocalToken  = "local-token"
	azureLocalTenant = "00000000-0000-0000-0000-000000000000"
)

var (
	azureRSAOnce sync.Once
	azureRSAKey  *rsa.PrivateKey
)

// localKeyVault stands in for a Key Vault holding one version of an RSA key ("wrap") and an EC
// P-256 key ("sign"), answering the four operations the wrapper calls - and the authentication
// challenge before them - as the Azure SDK's transport.
type localKeyVault struct {
	rsaKey      *rsa.PrivateKey
	ecKey       *ecdsa.PrivateKey
	wrapVersion string
	signVersion string
	mu          sync.Mutex
	calls       map[string]int
}

func newLocalKeyVault(t *testing.T) *localKeyVault {
	t.Helper()
	azureRSAOnce.Do(func() {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		azureRSAKey = key
	})
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	version := func() string {
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		return hex.EncodeToString(b)
	}
	return &localKeyVault{rsaKey: azureRSAKey, ecKey: ecKey, wrapVersion: version(), signVersion: version(), calls: map[string]int{}}
}

func (v *localKeyVault) Do(request *http.Request) (*http.Response, error) {
	if request.Header.Get("Authorization") != "Bearer "+azureLocalToken {
		return v.respond(request, http.StatusUnauthorized, map[string]any{}, "WWW-Authenticate",
			`Bearer authorization="https://login.microsoftonline.com/`+azureLocalTenant+`", resource="https://vault.azure.net"`), nil
	}
	// /keys/{name}/{version}/{op}, or /keys/{name}/{op} for the current version.
	segments := strings.Split(strings.TrimPrefix(request.URL.Path, "/keys/"), "/")
	name, version, op := segments[0], "", segments[len(segments)-1]
	if len(segments) == 3 {
		version = segments[1]
	}
	var body struct{ Alg, Value, Digest string }
	if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
		return nil, err
	}
	v.mu.Lock()
	v.calls[op]++
	v.mu.Unlock()
	value, _ := base64.RawURLEncoding.DecodeString(body.Value)

	current := map[string]string{"wrap": v.wrapVersion, "sign": v.signVersion}[name]
	if current == "" || (version != "" && version != current) {
		return v.respond(request, http.StatusNotFound, map[string]any{"error": map[string]any{"code": "KeyNotFound"}}), nil
	}
	kid := azureVault + "/keys/" + name + "/" + current
	var result []byte
	var err error
	switch name + "/" + op {
	case "wrap/wrapkey":
		result, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, &v.rsaKey.PublicKey, value, nil)
	case "wrap/unwrapkey":
		result, err = rsa.DecryptOAEP(sha256.New(), nil, v.rsaKey, value, nil)
	case "sign/sign":
		var r, s *big.Int
		if r, s, err = ecdsa.Sign(rand.Reader, v.ecKey, value); err == nil {
			result = append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
		}
	case "sign/verify":
		digest, _ := base64.RawURLEncoding.DecodeString(body.Digest)
		valid := len(value) == 64 && ecdsa.Verify(&v.ecKey.PublicKey, digest, new(big.Int).SetBytes(value[:32]), new(big.Int).SetBytes(value[32:]))
		return v.respond(request, http.StatusOK, map[string]any{"value": valid}), nil
	default:
		return v.respond(request, http.StatusBadRequest, map[string]any{"error": map[string]any{"code": "BadParameter"}}), nil
	}
	if err != nil {
		return v.respond(request, http.StatusBadRequest, map[string]any{"error": map[string]any{"code": "BadParameter", "message": err.Error()}}), nil
	}
	return v.respond(request, http.StatusOK, map[string]any{"kid": kid, "value": base64.RawURLEncoding.EncodeToString(result)}), nil
}

func (v *localKeyVault) respond(request *http.Request, status int, body any, headers ...string) *http.Response {
	encoded, _ := json.Marshal(body)
	header := http.Header{"Content-Type": {"application/json"}}
	for i := 0; i+1 < len(headers); i += 2 {
		header.Set(headers[i], headers[i+1])
	}
	return &http.Response{StatusCode: status, Status: http.StatusText(status), Header: header, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Body: io.NopCloser(bytes.NewReader(encoded)), ContentLength: int64(len(encoded)), Request: request}
}

func (v *localKeyVault) count(op string) int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.calls[op]
}

type localCredential struct{}

func (localCredential) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: azureLocalToken, ExpiresOn: time.Now().Add(time.Hour)}, nil
}

func azureWrapper(t *testing.T, vault *localKeyVault, context string, trust securefile.KeyFileTrust) *azurekeyvault.KeyWrapper {
	t.Helper()
	wrapper, err := azurekeyvault.New(azureWrapKeyID, azureSignKeyID, localCredential{}, azurekeyvault.Options{
		Context:       context,
		KeyFileTrust:  trust,
		ClientOptions: &azkeys.ClientOptions{ClientOptions: azcore.ClientOptions{Transport: vault, Retry: policy.RetryOptions{MaxRetries: -1}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return wrapper
}

func TestAzureKeyVault_LetsACryptoProviderGenerateAndRevealItsDEKThroughKeyVault(t *testing.T) {
	vault := newLocalKeyVault(t)
	ring, err := buildKMSRing(t, dek.Config{KeyWrapper: azureWrapper(t, vault, azureContext, securefile.AdministratorsOnly()), EphemeralKeys: []int{100}})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	protector, err := ring.CreateProtector("customer-notes")
	if err != nil {
		t.Fatal(err)
	}
	formatted := protect(t, protector, "hello, key vault")
	if !strings.HasPrefix(formatted, "enc::v100::") {
		t.Errorf("formatted = %q", formatted)
	}
	if got := unprotect(t, protector, formatted); got != "hello, key vault" {
		t.Errorf("decrypted = %q", got)
	}
	if vault.count("wrapkey") != 1 || vault.count("sign") != 1 || vault.count("verify") < 1 || vault.count("unwrapkey") < 1 {
		t.Errorf("Key Vault calls %v; want one wrap and sign, and at least one verify and unwrap", vault.calls)
	}
}

func TestAzureKeyVault_PipelineEncryptedConfiguration_DecryptsThroughItsKeyVaultWrappedKeyFile(t *testing.T) {
	vault := newLocalKeyVault(t)
	wrapper := azureWrapper(t, vault, azureContext, trustThisAccount(t))
	keyFile, values := runPipelineWith(t, wrapper, "v3.key", map[string]string{"ConnectionStrings:Admin": "Server=db;Password=hunter2"})

	ring, err := buildKMSRing(t, dek.Config{KeyWrapper: wrapper, KeyFiles: map[int]string{keyFileVersion: keyFile}})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if got := mustReveal(t, configReader(t, ring, values), "ConnectionStrings:Admin"); got != "Server=db;Password=hunter2" {
		t.Errorf("revealed %q", got)
	}
}

func TestAzureKeyVault_ARingRefusesToBuild_FromAKeyFileNoOneTrustedWrote(t *testing.T) {
	vault := newLocalKeyVault(t)
	keyFile, _ := runPipelineWith(t, azureWrapper(t, vault, azureContext, trustThisAccount(t)), "v3.key", map[string]string{"Secret": "value"})
	if os.Geteuid() == 0 {
		t.Skip("Running as root, whose files are trusted.")
	}

	// The same file, read by a wrapper that trusts administrators only.
	_, err := buildKMSRing(t, dek.Config{KeyWrapper: azureWrapper(t, vault, azureContext, securefile.AdministratorsOnly()),
		KeyFiles: map[int]string{keyFileVersion: keyFile}})
	if !errors.Is(err, securefile.ErrUntrusted) {
		t.Fatalf("Build: %v; want the key file refused as not trusted", err)
	}
}

func TestAzureKeyVault_ARingRefusesToBuild_FromAKeyFileUnderAnotherContext_WithoutUnwrappingIt(t *testing.T) {
	vault := newLocalKeyVault(t)
	keyFile, _ := runPipelineWith(t, azureWrapper(t, vault, azureContext, trustThisAccount(t)), "v3.key", map[string]string{"Secret": "value"})
	unwrapped := vault.count("unwrapkey")

	_, err := buildKMSRing(t, dek.Config{KeyWrapper: azureWrapper(t, vault, "another app", trustThisAccount(t)), KeyFiles: map[int]string{keyFileVersion: keyFile}})
	if !errors.Is(err, azurekeyvault.ErrKeyVault) || !strings.Contains(err.Error(), "signature doesn't verify") {
		t.Fatalf("Build: %v; want the signature refused", err)
	}
	if vault.count("unwrapkey") != unwrapped {
		t.Error("the key file was unwrapped")
	}
}
