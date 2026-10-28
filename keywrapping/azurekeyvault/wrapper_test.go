package azurekeyvault

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/internal/kmstest"
)

// envelopeVersions are the wrapping and signing key versions a wrapped DEK records.
func envelopeVersions(t *testing.T, wrapped []byte) (string, string) {
	t.Helper()
	p, err := parse(wrapped, testFail)
	if err != nil {
		t.Fatal(err)
	}
	return p.wrappingKeyVersion, p.signingKeyVersion
}

func requireOps(t *testing.T, vault *fakeVault, want ...string) {
	t.Helper()
	if got := vault.ops(); !slices.Equal(got, want) {
		t.Errorf("Key Vault was called for %v; want %v", got, want)
	}
}

// --- Construction --------------------------------------------------------------------------------

func TestNew_RefusesMissingOrInvalidArguments(t *testing.T) {
	credential := &fakeCredential{}
	for name, call := range map[string]func() (*KeyWrapper, error){
		"no wrapping key": func() (*KeyWrapper, error) { return New("", signKeyID, credential, Options{}) },
		"no signing key":  func() (*KeyWrapper, error) { return New(wrapKeyID, "", credential, Options{}) },
		"a secret":        func() (*KeyWrapper, error) { return New(vaultURL+"/secrets/s", signKeyID, credential, Options{}) },
		"a signing key URL": func() (*KeyWrapper, error) {
			return New(wrapKeyID, "http://myvault.vault.azure.net/keys/s", credential, Options{})
		},
		"no credential": func() (*KeyWrapper, error) { return New(wrapKeyID, signKeyID, nil, Options{}) },
		"a context not UTF-8": func() (*KeyWrapper, error) {
			return New(wrapKeyID, signKeyID, credential, Options{Context: "\xff"})
		},
		"a context too long": func() (*KeyWrapper, error) {
			return New(wrapKeyID, signKeyID, credential, Options{Context: strings.Repeat("x", 65536)})
		},
	} {
		if wrapper, err := call(); !errors.Is(err, ErrInvalidArgument) || wrapper != nil {
			t.Errorf("%s: %v, %v; want ErrInvalidArgument", name, wrapper, err)
		}
	}
}

func TestNew_RefusesTheSameKeyForWrappingAndSigning_InAnyVersionOrCase(t *testing.T) {
	for _, signing := range []string{wrapKeyID, wrapKeyID + "/" + testWrapVersion, strings.ToUpper(vaultURL) + "/keys/" + strings.ToUpper(wrapName)} {
		_, err := New(wrapKeyID, signing, &fakeCredential{}, Options{})
		if !errors.Is(err, ErrInvalidArgument) || !strings.Contains(err.Error(), "both '"+wrapName+"'") {
			t.Errorf("%s: %v", signing, err)
		}
	}
}

func TestNew_AllowsKeysWithTheSameNameInDifferentVaults(t *testing.T) {
	if _, err := New(wrapKeyID, "https://other.vault.azure.net/keys/"+wrapName, &fakeCredential{}, Options{}); err != nil {
		t.Fatal(err)
	}
}

func TestNew_MakesNoCallUntilTheWrapperIsUsed(t *testing.T) {
	vault := newFakeVault(t)
	credential := &fakeCredential{}
	if _, err := New(wrapKeyID, signKeyID, credential, Options{ClientOptions: clientOptions(vault)}); err != nil {
		t.Fatal(err)
	}
	if len(vault.recorded()) != 0 || len(vault.challenges) != 0 || len(credential.requests) != 0 {
		t.Error("a call was made")
	}
}

func TestNew_IsAKeyWrapper_KeepingTheIdentifiersAsGiven(t *testing.T) {
	given := "HTTPS://MyVault.vault.azure.net/keys/" + wrapName + "/"
	wrapper := newWrapperOver(t, newFakeVault(t), given, signKeyID)
	var _ hkdfguard.KeyWrapper = wrapper
	if wrapper.WrappingKeyID() != given || wrapper.SigningKeyID() != signKeyID {
		t.Errorf("%q, %q", wrapper.WrappingKeyID(), wrapper.SigningKeyID())
	}
}

// --- Wrap and unwrap -----------------------------------------------------------------------------

func TestKeyWrapper_RoundTripsADEK(t *testing.T) {
	wrapper := newWrapper(t, newFakeVault(t), withContext())
	dek := random(32)
	revealed := make([]byte, 32)
	n, err := wrapper.Unwrap(t.Context(), wrapWith(t, wrapper, dek), revealed)
	if err != nil || n != 32 || !bytes.Equal(revealed, dek) {
		t.Fatalf("%d, %v; want the DEK", n, err)
	}
}

func TestWrap_SendsKeyVaultTheDEK_AndLeavesTheCallersPlaintextAlone(t *testing.T) {
	vault := newFakeVault(t)
	dek := random(32)
	original := bytes.Clone(dek)
	wrapWith(t, newWrapper(t, vault), dek)

	requests := vault.recorded()
	if requests[0].op != "wrapkey" || requests[0].body["alg"] != "RSA-OAEP-256" || !bytes.Equal(vault.plaintexts[0], original) {
		t.Errorf("wrapkey request %+v", requests[0])
	}
	if requests[1].op != "sign" || requests[1].body["alg"] != "ES256" {
		t.Errorf("sign request %+v", requests[1])
	}
	if !bytes.Equal(dek, original) {
		t.Error("the caller's plaintext was modified")
	}
}

func TestWrap_WrapsAndSignsUnderEachKeysCurrentVersion_AndRecordsTheVersionsKeyVaultReports(t *testing.T) {
	vault := newFakeVault(t)
	wrapped := wrapWith(t, newWrapper(t, vault, withContext()), random(32))

	requests := vault.recorded()
	if requests[0].name != wrapName || requests[0].version != "" || requests[1].name != signName || requests[1].version != "" {
		t.Errorf("requests went to %s/%s and %s/%s; want both keys' current versions", requests[0].name, requests[0].version, requests[1].name, requests[1].version)
	}
	wrapVersion, signVersion := envelopeVersions(t, wrapped)
	if wrapVersion != vault.current(wrapName) || signVersion != vault.current(signName) {
		t.Errorf("recorded %s and %s; want the current versions", wrapVersion, signVersion)
	}
	if len(wrapped) != 256+overhead {
		t.Errorf("an RSA-2048 key's wrapped DEK is %d bytes; want 359", len(wrapped))
	}
}

func TestWrap_UnderVersionsNamedAtConstruction_UsesThoseVersions_WhateverIsCurrent(t *testing.T) {
	vault := newFakeVault(t)
	wrapVersion, signVersion := vault.current(wrapName), vault.current(signName)
	vault.rotate(t, wrapName)
	vault.rotate(t, signName)
	wrapper := newWrapperOver(t, vault, wrapKeyID+"/"+wrapVersion, signKeyID+"/"+signVersion)

	wrapped := wrapWith(t, wrapper, random(32))
	if requests := vault.recorded(); requests[0].version != wrapVersion || requests[1].version != signVersion {
		t.Errorf("requests went to versions %s and %s", requests[0].version, requests[1].version)
	}
	if w, s := envelopeVersions(t, wrapped); w != wrapVersion || s != signVersion {
		t.Errorf("recorded %s and %s", w, s)
	}
}

func TestWrap_FollowsARotation_AndOlderKeyFilesStillReveal(t *testing.T) {
	vault := newFakeVault(t)
	wrapper := newWrapper(t, vault)
	dek := random(32)
	before := wrapWith(t, wrapper, dek)
	newWrap, newSign := vault.rotate(t, wrapName), vault.rotate(t, signName)

	after := wrapWith(t, wrapper, random(32))
	if w, s := envelopeVersions(t, after); w != newWrap || s != newSign {
		t.Errorf("recorded %s and %s after a rotation; want %s and %s", w, s, newWrap, newSign)
	}
	revealed := make([]byte, 32)
	if n, err := wrapper.Unwrap(t.Context(), before, revealed); err != nil || n != 32 || !bytes.Equal(revealed, dek) {
		t.Fatalf("%d, %v; want the DEK wrapped before the rotation", n, err)
	}
}

func TestUnwrap_VerifiesTheSignatureFirst_ThenUnwraps_BothUnderTheRecordedVersions(t *testing.T) {
	vault := newFakeVault(t)
	wrapper := newWrapper(t, vault, withContext())
	wrapped := wrapWith(t, wrapper, random(32))
	wrapVersion, signVersion := envelopeVersions(t, wrapped)
	vault.rotate(t, wrapName)
	vault.rotate(t, signName)

	if _, err := wrapper.Unwrap(t.Context(), wrapped, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	requests := vault.recorded()[2:]
	if requests[0].op != "verify" || requests[0].name != signName || requests[0].version != signVersion || requests[0].body["alg"] != "ES256" {
		t.Errorf("first %+v; want verify under the recorded signing version", requests[0])
	}
	if requests[1].op != "unwrapkey" || requests[1].name != wrapName || requests[1].version != wrapVersion || requests[1].body["alg"] != "RSA-OAEP-256" {
		t.Errorf("then %+v; want unwrapkey under the recorded wrapping version", requests[1])
	}
	p, _ := parse(wrapped, testFail)
	if !bytes.Equal(requests[1].value, p.wrappedDEK) {
		t.Error("unwrapkey was not sent the wrapped DEK")
	}
	digest := sha256.Sum256(signedData(wrapped[:p.unsignedLength], []byte("hkdfguard.test")))
	if !bytes.Equal(decode(requests[0].body["digest"].(string)), digest[:]) || !bytes.Equal(requests[0].value, p.signature) {
		t.Error("verify was not sent the digest of the signed data and the signature")
	}
}

func TestGenerateAndWrap_ProducesA32ByteDEKThatReveals(t *testing.T) {
	vault := newFakeVault(t)
	wrapper := newWrapper(t, vault)
	result := make([]byte, hkdfguard.MaxWrappedKeyBytes)
	n, err := wrapper.GenerateAndWrap(t.Context(), result)
	if err != nil {
		t.Fatal(err)
	}
	revealed := make([]byte, 32)
	if m, err := wrapper.Unwrap(t.Context(), result[:n], revealed); err != nil || m != GeneratedKeyLength || hkdfguard.IsZero(revealed) {
		t.Fatalf("%d, %v; want %d non-zero bytes", m, err, GeneratedKeyLength)
	}
	if !bytes.Equal(vault.plaintexts[0], revealed) {
		t.Error("the DEK revealed is not the one wrapped")
	}
}

func TestUnwrap_WritesIntoTheStartOfALargerResult(t *testing.T) {
	wrapper := newWrapper(t, newFakeVault(t))
	dek := random(32)
	result := filled(64)
	n, err := wrapper.Unwrap(t.Context(), wrapWith(t, wrapper, dek), result)
	if err != nil || n != 32 || !bytes.Equal(result[:32], dek) || !bytes.Equal(result[32:], filled(32)) {
		t.Fatalf("%d, %v, %x", n, err, result)
	}
}

func TestWrap_WritesIntoTheStartOfALargerResult(t *testing.T) {
	result := filled(hkdfguard.MaxWrappedKeyBytes + 100)
	n, err := newWrapper(t, newFakeVault(t)).Wrap(t.Context(), random(32), result)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result[n:], filled(len(result)-n)) {
		t.Error("bytes past the wrapped DEK were changed")
	}
}

func TestWrap_AcceptsTheLargestPlaintextRSAOAEP256WrapsUnderA2048BitKey(t *testing.T) {
	wrapper := newWrapper(t, newFakeVault(t))
	dek := random(MaxPlaintextLength)
	revealed := make([]byte, MaxPlaintextLength)
	if n, err := wrapper.Unwrap(t.Context(), wrapWith(t, wrapper, dek), revealed); err != nil || n != MaxPlaintextLength || !bytes.Equal(revealed, dek) {
		t.Fatalf("%d, %v", n, err)
	}
}

func TestWrap_UnderAnRSA3072KeyFitsAKeyFile(t *testing.T) {
	vault := newFakeVault(t)
	vault.addRSA(t, vaultURL, "big", 3072)
	wrapper := newWrapperOver(t, vault, vaultURL+"/keys/big", signKeyID)
	wrapped := wrapWith(t, wrapper, random(32))
	if len(wrapped) != 384+overhead {
		t.Errorf("an RSA-3072 key's wrapped DEK is %d bytes; want 487", len(wrapped))
	}
	if n, err := wrapper.Unwrap(t.Context(), wrapped, make([]byte, 32)); err != nil || n != 32 {
		t.Fatalf("%d, %v", n, err)
	}
}

func TestKeyWrapper_KeysInTwoVaults_EachGetTheirOwnClientAndChallenge(t *testing.T) {
	vault := newFakeVault(t)
	vault.addEC(t, "https://other.vault.azure.net", signName)
	wrapper := newWrapperOver(t, vault, wrapKeyID, "https://OTHER.vault.azure.net/keys/"+signName)
	wrapped := wrapWith(t, wrapper, random(32))
	if _, err := wrapper.Unwrap(t.Context(), wrapped, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if vault.challenges["myvault.vault.azure.net"] != 1 || vault.challenges["other.vault.azure.net"] != 1 {
		t.Errorf("challenges %v; want one per vault", vault.challenges)
	}
}

// --- Unwrap refuses ------------------------------------------------------------------------------

func TestUnwrap_RefusesAWrappedDEKForgedFromThePublicKey_WithoutUnwrappingIt(t *testing.T) {
	vault := newFakeVault(t)
	wrapper := newWrapper(t, vault)
	// Anyone can wrap a DEK of their choosing under the public key; they can't sign it.
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, vault.publicRSA(wrapName), random(32), nil)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := mustBuild(t, vault.current(wrapName), ciphertext)
	forged := make([]byte, len(unsigned)+80)
	if _, err := write(unsigned, vault.current(signName), random(64), forged, testFail); err != nil {
		t.Fatal(err)
	}
	result := filled(32)

	_, err = wrapper.Unwrap(t.Context(), forged, result)
	kvErr := requireKeyVaultError(t, err, fmt.Sprintf("The wrapped DEK's signature doesn't verify under '%s' version %s: ...", signName, vault.current(signName)))
	if kvErr.Op != "verify" || kvErr.KeyID != signKeyID+"/"+vault.current(signName) || kvErr.Err != nil {
		t.Errorf("Op %q, KeyID %q, Err %v", kvErr.Op, kvErr.KeyID, kvErr.Err)
	}
	requireOps(t, vault, "verify")
	if !hkdfguard.IsZero(result) {
		t.Error("the result was not zeroed")
	}
}

func TestUnwrap_RefusesAWrappedDEKChangedAnywhere_WithoutUnwrappingIt_ZeroingTheResult(t *testing.T) {
	vault := newFakeVault(t)
	wrapper := newWrapper(t, vault, withContext())
	wrapped := wrapWith(t, wrapper, random(32))
	for i := range wrapped {
		changed := bytes.Clone(wrapped)
		changed[i] ^= 1
		result := filled(32)
		_, err := wrapper.Unwrap(t.Context(), changed, result)
		if !errors.Is(err, ErrKeyVault) {
			t.Fatalf("byte %d: %v; want an *azurekeyvault.Error", i, err)
		}
		if !hkdfguard.IsZero(result) {
			t.Fatalf("byte %d: the result was not zeroed", i)
		}
	}
	if slices.Contains(vault.ops(), "unwrapkey") {
		t.Error("a changed wrapped DEK was unwrapped")
	}
}

func TestUnwrap_RefusesAWrappedDEKMadeUnderAnotherContext_OrNone(t *testing.T) {
	vault := newFakeVault(t)
	wrapped := wrapWith(t, newWrapper(t, vault, withContext()), random(32))
	for _, options := range []Options{{}, {Context: "hkdfguard.test.other"}, {Context: "hkdfguard.test "}} {
		_, err := newWrapper(t, vault, options).Unwrap(t.Context(), wrapped, make([]byte, 32))
		requireKeyVaultError(t, err, "...signature doesn't verify")
	}
	if slices.Contains(vault.ops(), "unwrapkey") {
		t.Error("a wrapped DEK was unwrapped under another context")
	}
}

func TestKeyWrapper_NoContextAndAnEmptyContextAreTheSame(t *testing.T) {
	vault := newFakeVault(t)
	wrapped := wrapWith(t, newWrapper(t, vault, Options{}), random(32))
	if _, err := newWrapper(t, vault, Options{Context: ""}).Unwrap(t.Context(), wrapped, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
}

func TestUnwrap_RefusesAWrappedDEKMadeWithOtherKeys(t *testing.T) {
	wrapped := wrapWith(t, newWrapper(t, newFakeVault(t)), random(32))
	vault := newFakeVault(t)
	_, err := newWrapper(t, vault).Unwrap(t.Context(), wrapped, make([]byte, 32))
	requireKeyVaultError(t, err, "Azure Key Vault verify failed for key '"+signName+"': KeyNotFound (HTTP 404).")
	requireOps(t, vault, "verify")
}

func TestUnwrap_RefusesAWrappedDEKWhoseRecordedVersionHasBeenPurged(t *testing.T) {
	vault := newFakeVault(t)
	wrapper := newWrapper(t, vault)
	wrapped := wrapWith(t, wrapper, random(32))
	wrapVersion, _ := envelopeVersions(t, wrapped)
	vault.rotate(t, wrapName)
	vault.purge(wrapName, wrapVersion)

	_, err := wrapper.Unwrap(t.Context(), wrapped, make([]byte, 32))
	kvErr := requireKeyVaultError(t, err, "Azure Key Vault unwrap failed for key '"+wrapName+"': KeyNotFound (HTTP 404).")
	if kvErr.KeyID != wrapKeyID+"/"+wrapVersion {
		t.Errorf("KeyID %q", kvErr.KeyID)
	}
}

func TestUnwrap_RefusesWhatIsntAWrappedDEK_WithoutCallingKeyVault_ZeroingTheResult(t *testing.T) {
	vault := newFakeVault(t)
	wrapper := newWrapper(t, vault)
	for _, wrapped := range [][]byte{nil, {}, random(300), []byte("HGKV"), make([]byte, overhead)} {
		result := filled(32)
		_, err := wrapper.Unwrap(t.Context(), wrapped, result)
		kvErr := requireKeyVaultError(t, err, "This is not a wrapped DEK written by AzureKeyVaultKeyWrapper.")
		if kvErr.Op != "unwrap" || kvErr.KeyID != wrapKeyID {
			t.Errorf("Op %q, KeyID %q", kvErr.Op, kvErr.KeyID)
		}
		if !hkdfguard.IsZero(result) {
			t.Error("the result was not zeroed")
		}
	}
	if len(vault.recorded()) != 0 {
		t.Error("Key Vault was called")
	}
}

func TestUnwrap_RefusesAResultTooSmallForTheRevealedKey_ZeroingIt(t *testing.T) {
	wrapper := newWrapper(t, newFakeVault(t))
	wrapped := wrapWith(t, wrapper, random(32))
	result := filled(16)
	if _, err := wrapper.Unwrap(t.Context(), wrapped, result); !errors.Is(err, ErrInvalidArgument) ||
		!strings.Contains(err.Error(), "The revealed key is 32 bytes; result holds 16.") {
		t.Fatalf("got %v", err)
	}
	if !hkdfguard.IsZero(result) {
		t.Error("the result was not zeroed")
	}
}

func TestUnwrap_RefusesAnAnswerWithNoKey_ZeroingTheResult(t *testing.T) {
	vault := newFakeVault(t)
	wrapper := newWrapper(t, vault)
	wrapped := wrapWith(t, wrapper, random(32))
	for _, body := range []map[string]any{{"kid": wrapKeyID}, {"kid": wrapKeyID, "value": ""}} {
		vault.onRequest = func(r fakeRequest) *fakeAnswer {
			if r.op == "unwrapkey" {
				return &fakeAnswer{http.StatusOK, body}
			}
			return nil
		}
		result := filled(32)
		_, err := wrapper.Unwrap(t.Context(), wrapped, result)
		requireKeyVaultError(t, err, "Azure Key Vault unwrap for key '"+wrapName+"' returned no key.")
		if !hkdfguard.IsZero(result) {
			t.Error("the result was not zeroed")
		}
	}
}

func TestUnwrap_RefusesAVerifyAnswerThatIsntTrue(t *testing.T) {
	vault := newFakeVault(t)
	wrapper := newWrapper(t, vault)
	wrapped := wrapWith(t, wrapper, random(32))
	for _, body := range []map[string]any{{"value": false}, {}} {
		vault.onRequest = func(r fakeRequest) *fakeAnswer {
			if r.op == "verify" {
				return &fakeAnswer{http.StatusOK, body}
			}
			return nil
		}
		_, err := wrapper.Unwrap(t.Context(), wrapped, make([]byte, 32))
		requireKeyVaultError(t, err, "...signature doesn't verify")
	}
	if slices.Contains(vault.ops(), "unwrapkey") {
		t.Error("a wrapped DEK was unwrapped without a verified signature")
	}
}

// --- Wrap refuses --------------------------------------------------------------------------------

func TestWrap_RefusesAPlaintextRSAOAEP256CantWrap_WithoutCallingKeyVault(t *testing.T) {
	vault := newFakeVault(t)
	wrapper := newWrapper(t, vault)
	for _, length := range []int{0, MaxPlaintextLength + 1} {
		_, err := wrapper.Wrap(t.Context(), make([]byte, length), make([]byte, hkdfguard.MaxWrappedKeyBytes))
		if !errors.Is(err, ErrInvalidArgument) || !strings.Contains(err.Error(), fmt.Sprintf("wraps 1-190 bytes; got %d.", length)) {
			t.Errorf("%d bytes: %v", length, err)
		}
	}
	if len(vault.recorded()) != 0 {
		t.Error("Key Vault was called")
	}
}

func TestKeyWrapper_RefusesAResultTooSmallForTheWrappedDEK_LeavingItAsItWas(t *testing.T) {
	wrapper := newWrapper(t, newFakeVault(t))
	result := filled(358)
	if _, err := wrapper.Wrap(t.Context(), random(32), result); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("wrap: %v; want ErrInvalidArgument", err)
	}
	if _, err := wrapper.GenerateAndWrap(t.Context(), result); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("generate-and-wrap: %v; want ErrInvalidArgument", err)
	}
	if !bytes.Equal(result, filled(358)) {
		t.Error("the result was changed")
	}
}

func TestWrap_RefusesAnRSAKeyTooLargeForAKeyFile_BeforeSigning(t *testing.T) {
	vault := newFakeVault(t)
	vault.onRequest = func(r fakeRequest) *fakeAnswer {
		if r.op == "wrapkey" { // an RSA-4096 key's ciphertext
			return &fakeAnswer{http.StatusOK, map[string]any{"kid": wrapKeyID + "/" + vault.current(wrapName), "value": encode(random(512))}}
		}
		return nil
	}
	_, err := newWrapper(t, vault).Wrap(t.Context(), random(32), make([]byte, 1024))
	requireKeyVaultError(t, err, "The wrapped DEK would be 615 bytes; a wrapped DEK is at most 512. Use a 2048- or 3072-bit RSA key for '"+wrapName+"'.")
	requireOps(t, vault, "wrapkey")
}

func TestWrap_RefusesASignatureThatIsntES256s(t *testing.T) {
	vault := newFakeVault(t)
	vault.onRequest = func(r fakeRequest) *fakeAnswer {
		if r.op == "sign" { // an ES384 signature, from a P-384 key
			return &fakeAnswer{http.StatusOK, map[string]any{"kid": signKeyID + "/" + vault.current(signName), "value": encode(random(96))}}
		}
		return nil
	}
	result := filled(512)
	_, err := newWrapper(t, vault).Wrap(t.Context(), random(32), result)
	kvErr := requireKeyVaultError(t, err, "Azure Key Vault returned a 96-byte signature; an ES256 signature is 64. The signing key must be an EC P-256 key.")
	if kvErr.Op != "sign" || kvErr.KeyID != signKeyID+"/"+vault.current(signName) {
		t.Errorf("Op %q, KeyID %q", kvErr.Op, kvErr.KeyID)
	}
	if !bytes.Equal(result, filled(512)) {
		t.Error("the result was changed")
	}
}

func TestWrap_RefusesAKeyKeyVaultReportsAsAnotherKey(t *testing.T) {
	for op, reported := range map[string]string{
		"wrapkey": vaultURL + "/keys/another/" + testWrapVersion,
		"sign":    "https://other.vault.azure.net/keys/" + signName + "/" + testSignVersion,
	} {
		vault := newFakeVault(t)
		vault.onRequest = reportKid(t, vault, op, reported)
		_, err := newWrapper(t, vault).Wrap(t.Context(), random(32), make([]byte, 512))
		requireKeyVaultError(t, err, "...reported key '"+reported+"' instead.")
	}
}

func TestWrap_RefusesAnotherVersionThanTheOneNamed(t *testing.T) {
	vault := newFakeVault(t)
	named := vault.current(wrapName)
	vault.onRequest = reportKid(t, vault, "wrapkey", wrapKeyID+"/"+testWrapVersion)
	_, err := newWrapperOver(t, vault, wrapKeyID+"/"+named, signKeyID).Wrap(t.Context(), random(32), make([]byte, 512))
	requireKeyVaultError(t, err, "Azure Key Vault wrap for key '"+wrapName+"' reported key '"+wrapKeyID+"/"+testWrapVersion+"' instead.")
}

func TestWrap_RefusesAKeyKeyVaultReportsWithNoVersion_OrAnIdentifierThatIsntOne(t *testing.T) {
	for reported, message := range map[string]string{
		wrapKeyID:          "Azure Key Vault wrap for key '" + wrapName + "' didn't report which version it used.",
		"":                 "Azure Key Vault wrap for key '" + wrapName + "' reported key \"\", which isn't a key identifier.",
		"not a key at all": "Azure Key Vault wrap for key '" + wrapName + "' reported key \"not a key at all\", which isn't a key identifier.",
	} {
		vault := newFakeVault(t)
		vault.onRequest = reportKid(t, vault, "wrapkey", reported)
		_, err := newWrapper(t, vault).Wrap(t.Context(), random(32), make([]byte, 512))
		requireKeyVaultError(t, err, message)
		requireOps(t, vault, "wrapkey")
	}
}

func TestWrap_RefusesAKeyVersionAWrappedDEKCantRecord(t *testing.T) {
	vault := newFakeVault(t)
	vault.onRequest = reportKid(t, vault, "sign", signKeyID+"/abc123")
	_, err := newWrapper(t, vault).Wrap(t.Context(), random(32), make([]byte, 512))
	requireKeyVaultError(t, err, `Azure Key Vault returned key version "abc123", not 32 hex digits.`)
}

func TestWrap_RefusesAKeyKeyVaultMayNotWrapWith(t *testing.T) {
	// The two identifiers swapped: Key Vault refuses an EC key's wrapkey, as it does here.
	vault := newFakeVault(t)
	_, err := newWrapperOver(t, vault, signKeyID, wrapKeyID).Wrap(t.Context(), random(32), make([]byte, 512))
	requireKeyVaultError(t, err, "Azure Key Vault wrap failed for key '"+signName+"': Forbidden (HTTP 403).")
	var responseErr *azcore.ResponseError
	if !errors.As(err, &responseErr) || !strings.Contains(responseErr.Error(), "KeyOperationForbidden") {
		t.Errorf("the SDK's error doesn't carry Key Vault's inner code: %v", responseErr)
	}
}

// reportKid answers op as the vault does, but reporting kid as the key used.
func reportKid(t *testing.T, vault *fakeVault, op, kid string) func(fakeRequest) *fakeAnswer {
	t.Helper()
	return func(r fakeRequest) *fakeAnswer {
		if r.op != op {
			return nil
		}
		status, body := vault.answer(strings.TrimPrefix(vaultURL, "https://"), r)
		answer := body.(map[string]any)
		if kid == "" {
			delete(answer, "kid")
		} else {
			answer["kid"] = kid
		}
		return &fakeAnswer{status, answer}
	}
}

// --- Failures ------------------------------------------------------------------------------------

func TestFailures_AKeyVaultRefusalIsAnErrorNamingTheOperationTheKeyTheCodeAndTheStatus(t *testing.T) {
	for _, op := range []string{"wrapkey", "sign", "verify", "unwrapkey"} {
		vault := newFakeVault(t)
		wrapper := newWrapper(t, vault)
		wrapped := wrapWith(t, wrapper, random(32))
		wrapVersion, signVersion := envelopeVersions(t, wrapped)
		vault.onRequest = func(r fakeRequest) *fakeAnswer {
			if r.op == op {
				status, body := errorBody(http.StatusForbidden, "Forbidden", "Caller is not authorized to perform action on resource.")
				return &fakeAnswer{status, body}
			}
			return nil
		}
		result := filled(512)
		var err error
		if op == "wrapkey" || op == "sign" {
			_, err = wrapper.Wrap(t.Context(), random(32), result)
		} else {
			_, err = wrapper.Unwrap(t.Context(), wrapped, result)
		}

		want := map[string]struct{ op, name, keyID string }{
			"wrapkey":   {"wrap", wrapName, wrapKeyID},
			"sign":      {"sign", signName, signKeyID},
			"verify":    {"verify", signName, signKeyID + "/" + signVersion},
			"unwrapkey": {"unwrap", wrapName, wrapKeyID + "/" + wrapVersion},
		}[op]
		kvErr := requireKeyVaultError(t, err, fmt.Sprintf("Azure Key Vault %s failed for key '%s': Forbidden (HTTP 403).", want.op, want.name))
		if kvErr.Op != want.op || kvErr.KeyID != want.keyID {
			t.Errorf("%s: Op %q, KeyID %q", op, kvErr.Op, kvErr.KeyID)
		}
		var responseErr *azcore.ResponseError
		if !errors.As(err, &responseErr) || responseErr.StatusCode != 403 || kvErr.Err == nil {
			t.Errorf("%s: the SDK's error is not the cause", op)
		}
		if (op == "verify" || op == "unwrapkey") && !hkdfguard.IsZero(result) {
			t.Errorf("%s: the result was not zeroed", op)
		}
	}
}

func TestFailures_ARefusalWithoutAnErrorCodeIsStillNamed(t *testing.T) {
	vault := newFakeVault(t)
	vault.onRequest = func(fakeRequest) *fakeAnswer { return &fakeAnswer{http.StatusServiceUnavailable, map[string]any{}} }
	_, err := newWrapper(t, vault).Wrap(t.Context(), random(32), make([]byte, 512))
	requireKeyVaultError(t, err, "Azure Key Vault wrap failed for key '"+wrapName+"': error (HTTP 503).")
}

func TestFailures_ACredentialThatCantGetATokenIsAnErrorWithItsMessage(t *testing.T) {
	vault := newFakeVault(t)
	tokenErr := errors.New("DefaultAzureCredential: failed to acquire a token")
	wrapper, err := New(wrapKeyID, signKeyID, &fakeCredential{err: tokenErr}, Options{ClientOptions: clientOptions(vault)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = wrapper.Wrap(t.Context(), random(32), make([]byte, 512))
	requireKeyVaultError(t, err, "Azure Key Vault wrap failed for key '"+wrapName+"': ...")
	if !errors.Is(err, tokenErr) || !strings.Contains(err.Error(), tokenErr.Error()) {
		t.Errorf("got %v; want the credential's error as the cause, and its message", err)
	}
	if len(vault.recorded()) != 0 {
		t.Error("an operation was sent without a token")
	}
}

func TestFailures_ARefusedConnectionIsAnError(t *testing.T) {
	vault := newFakeVault(t)
	refused := &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connect: connection refused")}
	vault.failure = refused
	result := filled(32)
	_, err := newWrapper(t, vault).Unwrap(t.Context(), wrapWithAnother(t), result)
	requireKeyVaultError(t, err, "Azure Key Vault verify failed for key '"+signName+"': dial tcp: connect: connection refused")
	var opErr *net.OpError
	if !errors.As(err, &opErr) {
		t.Errorf("got %v; want the connection's error as the cause", err)
	}
	if !hkdfguard.IsZero(result) {
		t.Error("the result was not zeroed")
	}
}

// wrapWithAnother is a wrapped DEK made with a fake vault of its own.
func wrapWithAnother(t *testing.T) []byte {
	t.Helper()
	return wrapWith(t, newWrapper(t, newFakeVault(t)), random(32))
}

func TestFailures_AnEndedContextMakesNoCall(t *testing.T) {
	vault := newFakeVault(t)
	credential := &fakeCredential{}
	wrapper, err := New(wrapKeyID, signKeyID, credential, Options{ClientOptions: clientOptions(vault)})
	if err != nil {
		t.Fatal(err)
	}
	kmstest.RequireEndedContextRefused(t, wrapper, random(359))
	if len(vault.challenges) != 0 || len(credential.requests) != 0 {
		t.Error("Key Vault was called")
	}
}

func TestFailures_ACancellationOrTimeoutInFlightIsReturnedAsTheSDKReportsIt_AndUnwrapZeroesTheResult(t *testing.T) {
	wrapped := wrapWithAnother(t)
	vault := newFakeVault(t)
	vault.hang = true
	wrapper := newWrapper(t, vault)

	ctx, cancel := context.WithCancel(t.Context())
	time.AfterFunc(50*time.Millisecond, cancel)
	result := filled(32)
	if _, err := wrapper.Unwrap(ctx, wrapped, result); !errors.Is(err, context.Canceled) || errors.Is(err, ErrKeyVault) {
		t.Errorf("unwrap: %v; want the SDK's cancellation, as it is", err)
	}
	if !hkdfguard.IsZero(result) {
		t.Error("the result was not zeroed")
	}

	ctx, cancel = context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if _, err := wrapper.GenerateAndWrap(ctx, make([]byte, 512)); !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrKeyVault) {
		t.Errorf("generate-and-wrap: %v; want the SDK's timeout, as it is", err)
	}
}

// --- Key Vault clients ---------------------------------------------------------------------------

func TestClients_AnswerKeyVaultsChallengeOnce_AndAskForAVaultToken(t *testing.T) {
	vault := newFakeVault(t)
	credential := &fakeCredential{}
	wrapper, err := New(wrapKeyID, signKeyID, credential, Options{ClientOptions: clientOptions(vault)})
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if _, err := wrapper.Unwrap(t.Context(), wrapWith(t, wrapper, random(32)), make([]byte, 32)); err != nil {
			t.Fatal(err)
		}
	}
	if vault.challenges["myvault.vault.azure.net"] != 1 {
		t.Errorf("challenged %d times; want once", vault.challenges["myvault.vault.azure.net"])
	}
	request := credential.requests[0]
	if !slices.Equal(request.Scopes, []string{"https://vault.azure.net/.default"}) || request.TenantID != tenantID {
		t.Errorf("token request %+v", request)
	}
	for _, r := range vault.recorded() {
		if r.apiVersion == "" {
			t.Errorf("%s: no api-version", r.op)
		}
	}
}

type headerPolicy struct{}

func (headerPolicy) Do(request *policy.Request) (*http.Response, error) {
	request.Raw().Header.Set("X-Hkdfguard-Test", "given")
	return request.Next()
}

func TestClients_AreGivenTheClientOptions_CopiedByNew(t *testing.T) {
	vault := newFakeVault(t)
	options := clientOptions(vault)
	options.PerCallPolicies = []policy.Policy{headerPolicy{}}
	wrapper := newWrapper(t, vault, Options{ClientOptions: options})
	options.Transport = nil
	options.DisableChallengeResourceVerification = true

	wrapWith(t, wrapper, random(32))
	for _, r := range vault.recorded() {
		if r.header.Get("X-Hkdfguard-Test") != "given" {
			t.Errorf("%s: the client options' policy did not run", r.op)
		}
	}
}

func TestClients_VerifyTheChallengeResource_UnlessTheOptionsSayNot(t *testing.T) {
	// A vault host that isn't under the challenge's resource, vault.azure.net.
	vault := newFakeVault(t)
	vault.addRSA(t, "https://myvault.example.com", wrapName, 2048)
	vault.addEC(t, "https://myvault.example.com", signName)
	wrapping, signing := "https://myvault.example.com/keys/"+wrapName, "https://myvault.example.com/keys/"+signName

	_, err := newWrapperOver(t, vault, wrapping, signing).Wrap(t.Context(), random(32), make([]byte, 512))
	requireKeyVaultError(t, err, "...doesn't match the requested domain")

	options := clientOptions(vault)
	options.DisableChallengeResourceVerification = true
	wrapper := newWrapperOver(t, vault, wrapping, signing, Options{ClientOptions: options})
	if _, err := wrapper.Unwrap(t.Context(), wrapWith(t, wrapper, random(32)), make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
}
