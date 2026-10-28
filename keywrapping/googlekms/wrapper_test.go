package googlekms

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/auth"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/googleapis/gax-go/v2/apierror"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/runsecure/hkdfguard-go"
)

// aad is the AAD a wrapper binds for context.
func aad(context string) []byte { return []byte("HkdfGuard-GoogleKms-wrap-v1\x00" + context) }

// --- Construction --------------------------------------------------------------------------------

func TestNew_RefusesMissingOrInvalidArguments(t *testing.T) {
	stub := newStub(newFakeKMS(t))
	for name, call := range map[string]func() (*KeyWrapper, error){
		"no client":           func() (*KeyWrapper, error) { return New(nil, testKeyName, Options{}) },
		"a context not UTF-8": func() (*KeyWrapper, error) { return New(stub, testKeyName, Options{Context: "\xff"}) },
		"a context too long": func() (*KeyWrapper, error) {
			return New(stub, testKeyName, Options{Context: strings.Repeat("x", MaxContextLength+1)})
		},
	} {
		if wrapper, err := call(); !errors.Is(err, ErrInvalidArgument) || wrapper != nil {
			t.Errorf("%s: %v, %v; want ErrInvalidArgument", name, wrapper, err)
		}
	}
}

func TestNew_RefusesANameThatIsntAKeysResourceName_AKeyVersionsIncluded(t *testing.T) {
	stub := newStub(newFakeKMS(t))
	for _, name := range []string{
		"",
		"wrap",
		testKeyName + "/cryptoKeyVersions/1",
		testKeyName + "/",
		"/" + testKeyName,
		" " + testKeyName,
		"projects//locations/us-east1/keyRings/hkdfguard/cryptoKeys/wrap",
		"projects/p/locations/l/keyRings/r",
		"projects/p/locations/l/keyRings/r/cryptoKeys/",
		"projects/p/locations/l/keyRings/r/cryptokeys/k",
		"//cloudkms.googleapis.com/" + testKeyName,
		"https://cloudkms.googleapis.com/v1/" + testKeyName,
	} {
		_, err := New(stub, name, Options{})
		if !errors.Is(err, ErrInvalidArgument) || !strings.Contains(err.Error(), "isn't a Cloud KMS key's resource name") {
			t.Errorf("%q: %v", name, err)
		}
	}
}

func TestNew_AcceptsAnyKeyNameCloudKMSCouldHaveMade(t *testing.T) {
	stub := newStub(newFakeKMS(t))
	for _, name := range []string{
		testKeyName,
		"projects/my-project-123/locations/global/keyRings/a_b-C/cryptoKeys/K-1_x",
		"projects/p/locations/europe-west4/keyRings/r/cryptoKeys/k",
	} {
		if _, err := New(stub, name, Options{}); err != nil {
			t.Errorf("%q: %v", name, err)
		}
	}
}

func TestNew_AcceptsTheLongestContext(t *testing.T) {
	fake := newFakeKMS(t)
	wrapper := newWrapper(t, fake.client(t), Options{Context: strings.Repeat("x", MaxContextLength)})
	dek := random(32)
	revealed := make([]byte, 32)
	if n, err := wrapper.Unwrap(t.Context(), wrapWith(t, wrapper, dek), revealed); err != nil || n != 32 || !bytes.Equal(revealed, dek) {
		t.Fatalf("%d, %v; want the DEK", n, err)
	}
	if got := len(fake.encryptRequests()[0].AdditionalAuthenticatedData); got != len(aad(""))+MaxContextLength {
		t.Errorf("the AAD is %d bytes; want the label and the whole context", got)
	}
}

func TestNew_IsAKeyWrapper_KeepingTheNameAsGiven_AndMakesNoCall(t *testing.T) {
	fake := newFakeKMS(t)
	wrapper := newWrapper(t, fake.client(t))
	var _ hkdfguard.KeyWrapper = wrapper
	if wrapper.KeyName() != testKeyName {
		t.Errorf("KeyName() = %q", wrapper.KeyName())
	}
	if fake.calls() != 0 {
		t.Error("a call was made")
	}
}

// --- Wrap and unwrap -----------------------------------------------------------------------------

func TestKeyWrapper_RoundTripsADEK_OverGRPCAndREST(t *testing.T) {
	fake := newFakeKMS(t)
	for transport, client := range map[string]Client{"gRPC": fake.client(t), "REST": fake.restClient(t)} {
		wrapper := newWrapper(t, client, withContext())
		dek := random(32)
		revealed := make([]byte, 32)
		if n, err := wrapper.Unwrap(t.Context(), wrapWith(t, wrapper, dek), revealed); err != nil || n != 32 || !bytes.Equal(revealed, dek) {
			t.Errorf("%s: %d, %v; want the DEK", transport, n, err)
		}
	}
}

func TestKeyWrapper_SendsTheKeyThePlaintextAndTheLabelAndContextAsAAD_WithAChecksumOfEach(t *testing.T) {
	fake := newFakeKMS(t)
	wrapper := newWrapper(t, fake.client(t), withContext())
	dek := random(32)
	wrapped := wrapWith(t, wrapper, dek)
	if _, err := wrapper.Unwrap(t.Context(), wrapped, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}

	encrypt := fake.encryptRequests()[0]
	if encrypt.Name != testKeyName || !bytes.Equal(encrypt.Plaintext, dek) || encrypt.PlaintextCrc32C.GetValue() != crc32c(dek) ||
		!bytes.Equal(encrypt.AdditionalAuthenticatedData, aad(testContext)) ||
		encrypt.AdditionalAuthenticatedDataCrc32C.GetValue() != crc32c(aad(testContext)) {
		t.Errorf("Encrypt request %v", encrypt)
	}
	decrypt := fake.decryptRequests()[0]
	if decrypt.Name != testKeyName || !bytes.Equal(decrypt.Ciphertext, wrapped) || decrypt.CiphertextCrc32C.GetValue() != crc32c(wrapped) ||
		!bytes.Equal(decrypt.AdditionalAuthenticatedData, aad(testContext)) ||
		decrypt.AdditionalAuthenticatedDataCrc32C.GetValue() != crc32c(aad(testContext)) {
		t.Errorf("Decrypt request %v", decrypt)
	}
}

func TestWrap_ZeroesItsCopyOfThePlaintextOnceTheCallReturns_AndLeavesTheCallersAlone(t *testing.T) {
	stub := newStub(newFakeKMS(t))
	var sent []byte
	stub.encrypt = func(request *kmspb.EncryptRequest) (*kmspb.EncryptResponse, error) {
		sent = bytes.Clone(request.Plaintext)
		return newStub(newFakeKMS(t)).encrypt(request)
	}
	dek := random(32)
	original := bytes.Clone(dek)
	wrapWith(t, newWrapper(t, stub), dek)

	if !bytes.Equal(sent, original) {
		t.Error("the client wasn't sent the DEK")
	}
	if &stub.encrypts[0].Plaintext[0] == &dek[0] {
		t.Error("the client was sent the caller's own slice")
	}
	if !hkdfguard.IsZero(stub.encrypts[0].Plaintext) {
		t.Error("the wrapper's copy of the DEK was not zeroed")
	}
	if !bytes.Equal(dek, original) {
		t.Error("the caller's plaintext was modified")
	}
}

func TestWrap_ZeroesItsCopyOfThePlaintext_WhenTheCallFails(t *testing.T) {
	stub := newStub(newFakeKMS(t))
	stub.encrypt = func(*kmspb.EncryptRequest) (*kmspb.EncryptResponse, error) {
		return nil, status.Error(codes.PermissionDenied, "Permission denied.")
	}
	if _, err := newWrapper(t, stub).Wrap(t.Context(), random(32), make([]byte, 512)); err == nil {
		t.Fatal("the wrap succeeded")
	}
	if !hkdfguard.IsZero(stub.encrypts[0].Plaintext) {
		t.Error("the wrapper's copy of the DEK was not zeroed")
	}
}

func TestKeyWrapper_NoContextAndAnEmptyContextAreTheSame_BindingTheLabelAlone(t *testing.T) {
	fake := newFakeKMS(t)
	client := fake.client(t)
	wrapped := wrapWith(t, newWrapper(t, client), random(32))
	if _, err := newWrapper(t, client, Options{Context: ""}).Unwrap(t.Context(), wrapped, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if got := fake.encryptRequests()[0].AdditionalAuthenticatedData; !bytes.Equal(got, aad("")) {
		t.Errorf("AAD %q; want the label alone", got)
	}
}

func TestKeyWrapper_EncodesTheContextAsUTF8AfterTheLabel(t *testing.T) {
	fake := newFakeKMS(t)
	context := "café € \U0001F511"
	wrapWith(t, newWrapper(t, fake.client(t), Options{Context: context}), random(32))
	want := append([]byte("HkdfGuard-GoogleKms-wrap-v1\x00"), "caf\xc3\xa9 \xe2\x82\xac \xf0\x9f\x94\x91"...)
	if got := fake.encryptRequests()[0].AdditionalAuthenticatedData; !bytes.Equal(got, want) {
		t.Errorf("AAD % x; want % x", got, want)
	}
}

func TestKeyWrapper_SendsAFreshCopyOfTheAADWithEveryRequest(t *testing.T) {
	fake := newFakeKMS(t)
	stub := newStub(fake)
	normal := stub.encrypt
	stub.encrypt = func(request *kmspb.EncryptRequest) (*kmspb.EncryptResponse, error) {
		response, err := normal(request)
		request.AdditionalAuthenticatedData[0] ^= 1 // whatever the client does with one request's AAD
		return response, err
	}
	wrapper := newWrapper(t, stub, withContext())
	wrapWith(t, wrapper, random(32))
	wrapped := wrapWith(t, wrapper, random(32))
	if _, err := wrapper.Unwrap(t.Context(), wrapped, make([]byte, 32)); err != nil {
		t.Fatalf("the AAD changed for later requests: %v", err)
	}
	if &stub.encrypts[0].AdditionalAuthenticatedData[0] == &stub.encrypts[1].AdditionalAuthenticatedData[0] {
		t.Error("two requests share an AAD slice")
	}
}

func TestGenerateAndWrap_GeneratesA32ByteDEKInTheProcess_WrapsIt_AndZeroesIt(t *testing.T) {
	fake := newFakeKMS(t)
	stub := newStub(fake)
	wrapper := newWrapper(t, stub, withContext())
	wrapped := generate(t, wrapper)

	sent := stub.encrypts[0].Plaintext
	if len(sent) != GeneratedKeyLength || !hkdfguard.IsZero(sent) {
		t.Errorf("the generated DEK sent was %d bytes, and not zeroed once wrapped", len(sent))
	}
	revealed := make([]byte, 32)
	if n, err := newWrapper(t, fake.client(t), withContext()).Unwrap(t.Context(), wrapped, revealed); err != nil || n != 32 || hkdfguard.IsZero(revealed) {
		t.Fatalf("%d, %v; want 32 non-zero bytes", n, err)
	}
	if !bytes.Equal(wrapped[:1], []byte{1}) || bytes.Equal(generate(t, wrapper), wrapped) {
		t.Error("each generated DEK should be fresh")
	}
}

func TestUnwrap_KeepsUnwrappingKeyFilesMadeBeforeTheKeyRotated(t *testing.T) {
	fake := newFakeKMS(t)
	wrapper := newWrapper(t, fake.client(t), withContext())
	dek := random(32)
	before := wrapWith(t, wrapper, dek)
	fake.rotate()
	after := wrapWith(t, wrapper, random(32))

	if names := []string{fake.encryptRequests()[0].Name, fake.encryptRequests()[1].Name}; names[0] != testKeyName || names[1] != testKeyName {
		t.Errorf("Encrypt was called for %v; want the key, never a version", names)
	}
	if before[0] != 1 || after[0] != 2 {
		t.Errorf("made under versions %d and %d; want 1 then 2", before[0], after[0])
	}
	revealed := make([]byte, 32)
	if n, err := wrapper.Unwrap(t.Context(), before, revealed); err != nil || n != 32 || !bytes.Equal(revealed, dek) {
		t.Fatalf("%d, %v; want the DEK", n, err)
	}
}

func TestWrap_ResendsTheSamePlaintextWhenTheClientRetries(t *testing.T) {
	fake := newFakeKMS(t)
	attempts := 0
	fake.answerEncrypt(func(request *kmspb.EncryptRequest) (*kmspb.EncryptResponse, error) {
		if attempts++; attempts == 1 {
			return nil, status.Error(codes.Unavailable, "The service is unavailable.")
		}
		return fake.encryptNormally(request)
	})
	dek := random(32)
	wrapWith(t, newWrapper(t, fake.client(t)), dek)
	requests := fake.encryptRequests()
	if len(requests) != 2 || !bytes.Equal(requests[0].Plaintext, dek) || !bytes.Equal(requests[1].Plaintext, dek) {
		t.Errorf("%d requests; want the DEK sent twice", len(requests))
	}
}

func TestUnwrap_WritesIntoTheStartOfALargerResult_AndZeroesWhatTheClientDecodedOnceCopied(t *testing.T) {
	fake := newFakeKMS(t)
	stub := newStub(fake)
	var decoded []byte
	stub.decrypt = func(request *kmspb.DecryptRequest) (*kmspb.DecryptResponse, error) {
		response, err := fake.decryptNormally(request)
		if err == nil {
			decoded = response.Plaintext
		}
		return response, err
	}
	wrapper := newWrapper(t, stub)
	dek := random(32)
	result := filled(64)
	n, err := wrapper.Unwrap(t.Context(), wrapWith(t, wrapper, dek), result)
	if err != nil || n != 32 || !bytes.Equal(result[:32], dek) || !bytes.Equal(result[32:], filled(32)) {
		t.Fatalf("%d, %v, % x", n, err, result)
	}
	if len(decoded) != 32 || !hkdfguard.IsZero(decoded) {
		t.Error("the plaintext the client decoded was not zeroed")
	}
}

func TestWrap_WritesIntoTheStartOfALargerResult(t *testing.T) {
	wrapper := newWrapper(t, newFakeKMS(t).client(t))
	result := filled(hkdfguard.MaxWrappedKeyBytes)
	n, err := wrapper.Wrap(t.Context(), random(32), result)
	if err != nil || n == 0 || !bytes.Equal(result[n:], filled(len(result)-n)) {
		t.Fatalf("%d, %v", n, err)
	}
}

func TestWrap_SendsTheLargestPlaintextCloudKMSAccepts_AndRefusesACiphertextOverTheKeyFileLimit(t *testing.T) {
	fake := newFakeKMS(t)
	_, err := newWrapper(t, fake.client(t)).Wrap(t.Context(), random(MaxPlaintextLength), make([]byte, 512))
	requireCloudKMSError(t, err, "Cloud KMS wrap for key '"+testKeyName+"' returned 65565 bytes; a wrapped DEK is at most 512.")
	if requests := fake.encryptRequests(); len(requests) != 1 || len(requests[0].Plaintext) != MaxPlaintextLength {
		t.Error("the largest plaintext was not sent")
	}
}

// --- Refusals ------------------------------------------------------------------------------------

func TestUnwrap_RefusesADEKWrappedUnderAnotherKey_NamingTheStatus_AndZeroesTheResult(t *testing.T) {
	fake := newFakeKMS(t)
	client := fake.client(t)
	wrapped := wrapWith(t, newWrapperOver(t, client, otherKeyName, withContext()), random(32))
	result := filled(32)
	_, err := newWrapper(t, client, withContext()).Unwrap(t.Context(), wrapped, result)
	kmsErr := requireCloudKMSError(t, err, "Cloud KMS unwrap failed for key '"+testKeyName+"': INVALID_ARGUMENT: Decryption failed.")
	if kmsErr.Op != "unwrap" || kmsErr.KeyName != testKeyName || status.Code(err) != codes.InvalidArgument {
		t.Errorf("Op %q, KeyName %q, status %v", kmsErr.Op, kmsErr.KeyName, status.Code(err))
	}
	if !hkdfguard.IsZero(result) {
		t.Error("the result was not zeroed")
	}
	if fake.decryptRequests()[0].Name != testKeyName {
		t.Error("Decrypt wasn't pinned to the wrapper's key")
	}
}

func TestUnwrap_RefusesADEKWrappedUnderAnotherContext_OrNone(t *testing.T) {
	client := newFakeKMS(t).client(t)
	for _, contexts := range [][2]string{{testContext, testContext + ".other"}, {testContext, ""}, {"", testContext}} {
		wrapped := wrapWith(t, newWrapper(t, client, Options{Context: contexts[0]}), random(32))
		_, err := newWrapper(t, client, Options{Context: contexts[1]}).Unwrap(t.Context(), wrapped, make([]byte, 32))
		requireCloudKMSError(t, err, "...INVALID_ARGUMENT: Decryption failed.")
	}
}

func TestUnwrap_RefusesACiphertextTheKeyMadeWithoutTheHkdfGuardLabel(t *testing.T) {
	fake := newFakeKMS(t)
	wrapper := newWrapper(t, fake.client(t), withContext())
	for _, made := range [][]byte{fake.sealDirectly(random(32), testKeyName, []byte(testContext)), fake.sealDirectly(random(32), testKeyName, nil)} {
		_, err := wrapper.Unwrap(t.Context(), made, make([]byte, 32))
		requireCloudKMSError(t, err, "...INVALID_ARGUMENT: Decryption failed.")
	}
}

func TestUnwrap_RefusesATamperedDEK_ZeroingTheResult(t *testing.T) {
	wrapper := newWrapper(t, newFakeKMS(t).client(t), withContext())
	wrapped := wrapWith(t, wrapper, random(32))
	for _, i := range []int{0, 1, 13, len(wrapped) - 1} {
		tampered := bytes.Clone(wrapped)
		tampered[i] ^= 1
		result := filled(32)
		_, err := wrapper.Unwrap(t.Context(), tampered, result)
		requireCloudKMSError(t, err, "...INVALID_ARGUMENT: Decryption failed.")
		if !hkdfguard.IsZero(result) {
			t.Errorf("byte %d: the result was not zeroed", i)
		}
	}
	if _, err := wrapper.Unwrap(t.Context(), wrapped[:len(wrapped)-1], make([]byte, 32)); err == nil {
		t.Error("a truncated DEK was revealed")
	}
}

func TestUnwrap_RefusesAWrappedDEKOutOfBounds_WithoutCallingCloudKMS_ZeroingTheResult(t *testing.T) {
	fake := newFakeKMS(t)
	wrapper := newWrapper(t, fake.client(t))
	for _, wrapped := range [][]byte{nil, {}, random(hkdfguard.MaxWrappedKeyBytes + 1)} {
		result := filled(32)
		_, err := wrapper.Unwrap(t.Context(), wrapped, result)
		kmsErr := requireCloudKMSError(t, err, "A wrapped DEK is 1-512 bytes; got ...")
		if kmsErr.Op != "unwrap" || kmsErr.Err != nil {
			t.Errorf("Op %q, Err %v", kmsErr.Op, kmsErr.Err)
		}
		if !hkdfguard.IsZero(result) {
			t.Error("the result was not zeroed")
		}
	}
	if fake.calls() != 0 {
		t.Error("Cloud KMS was called")
	}
}

func TestUnwrap_RefusesAResultTooSmallForTheRevealedKey_ZeroingItAndWhatTheClientDecoded(t *testing.T) {
	fake := newFakeKMS(t)
	stub := newStub(fake)
	var decoded []byte
	stub.decrypt = func(request *kmspb.DecryptRequest) (*kmspb.DecryptResponse, error) {
		response, err := fake.decryptNormally(request)
		decoded = response.Plaintext
		return response, err
	}
	wrapper := newWrapper(t, stub)
	result := filled(31)
	_, err := wrapper.Unwrap(t.Context(), wrapWith(t, wrapper, random(32)), result)
	if !errors.Is(err, ErrInvalidArgument) || !strings.Contains(err.Error(), "The revealed key is 32 bytes; result holds 31.") {
		t.Fatalf("got %v; want ErrInvalidArgument", err)
	}
	if !hkdfguard.IsZero(result) || !hkdfguard.IsZero(decoded) {
		t.Error("the result, or what the client decoded, was not zeroed")
	}
}

func TestUnwrap_RefusesAResponseWithNoPlaintext_OrOneThatDoesntMatchItsChecksum_ZeroingTheResult(t *testing.T) {
	fake := newFakeKMS(t)
	wrapper := newWrapper(t, fake.client(t))
	wrapped := wrapWith(t, wrapper, random(32))
	corrupted := "Cloud KMS unwrap for key '" + testKeyName + "' returned a plaintext that doesn't match its checksum: it was corrupted in transit."
	for message, change := range map[string]func(*kmspb.DecryptResponse){
		"Cloud KMS unwrap for key '" + testKeyName + "' returned no plaintext.": func(r *kmspb.DecryptResponse) { r.Plaintext = nil },
		corrupted:                    func(r *kmspb.DecryptResponse) { r.Plaintext[0] ^= 1 },
		corrupted + " (no checksum)": func(r *kmspb.DecryptResponse) { r.PlaintextCrc32C = nil },
		corrupted + " (another)":     func(r *kmspb.DecryptResponse) { r.PlaintextCrc32C = wrapperspb.Int64(r.PlaintextCrc32C.Value + 1) },
	} {
		fake.answerDecrypt(func(request *kmspb.DecryptRequest) (*kmspb.DecryptResponse, error) {
			response, err := fake.decryptNormally(request)
			change(response)
			return response, err
		})
		result := filled(32)
		_, err := wrapper.Unwrap(t.Context(), wrapped, result)
		message, _, _ = strings.Cut(message, " (")
		requireCloudKMSError(t, err, message)
		if !hkdfguard.IsZero(result) {
			t.Errorf("%s: the result was not zeroed", message)
		}
	}
}

func TestUnwrap_AcceptsAPlaintextWhoseChecksumIsZero(t *testing.T) {
	// The checksum of these four bytes is 0, so a missing checksum (which reads as 0) must not pass
	// for it - and a present one must.
	zero := []byte{0xab, 0x9b, 0xe0, 0x9b}
	if crc32c(zero) != 0 {
		t.Fatalf("crc32c(% x) = %#x; want 0", zero, crc32c(zero))
	}
	fake := newFakeKMS(t)
	wrapper := newWrapper(t, fake.client(t))
	wrapped := wrapWith(t, wrapper, zero)
	revealed := make([]byte, 4)
	if n, err := wrapper.Unwrap(t.Context(), wrapped, revealed); err != nil || n != 4 || !bytes.Equal(revealed, zero) {
		t.Fatalf("%d, %v", n, err)
	}
	fake.answerDecrypt(func(request *kmspb.DecryptRequest) (*kmspb.DecryptResponse, error) {
		response, err := fake.decryptNormally(request)
		response.PlaintextCrc32C = nil
		return response, err
	})
	_, err := wrapper.Unwrap(t.Context(), wrapped, revealed)
	requireCloudKMSError(t, err, "...corrupted in transit.")
}

func TestWrap_RefusesAPlaintextCloudKMSWouldRefuse_WithoutCallingIt(t *testing.T) {
	fake := newFakeKMS(t)
	wrapper := newWrapper(t, fake.client(t))
	for _, plaintext := range [][]byte{nil, {}, random(MaxPlaintextLength + 1)} {
		_, err := wrapper.Wrap(t.Context(), plaintext, make([]byte, 512))
		if !errors.Is(err, ErrInvalidArgument) || !strings.Contains(err.Error(), "Cloud KMS wraps 1-65536 bytes") {
			t.Errorf("%d bytes: %v", len(plaintext), err)
		}
	}
	if fake.calls() != 0 {
		t.Error("Cloud KMS was called")
	}
}

func TestKeyWrapper_RefusesAResultTooSmallForTheWrappedDEK_LeavingItAsItWas(t *testing.T) {
	wrapper := newWrapper(t, newFakeKMS(t).client(t))
	for name, call := range map[string]func([]byte) (int, error){
		"wrap":              func(result []byte) (int, error) { return wrapper.Wrap(t.Context(), random(32), result) },
		"generate-and-wrap": func(result []byte) (int, error) { return wrapper.GenerateAndWrap(t.Context(), result) },
	} {
		result := filled(60)
		if _, err := call(result); !errors.Is(err, ErrInvalidArgument) || !strings.Contains(err.Error(), "The wrapped DEK is 61 bytes; result holds 60.") {
			t.Errorf("%s: %v", name, err)
		}
		if !bytes.Equal(result, filled(60)) {
			t.Errorf("%s: the result was changed", name)
		}
	}
}

// answerEncryptWith makes the fake answer Encrypt normally, then change the response.
func answerEncryptWith(fake *fakeKMS, change func(*kmspb.EncryptResponse)) {
	fake.answerEncrypt(func(request *kmspb.EncryptRequest) (*kmspb.EncryptResponse, error) {
		response, err := fake.encryptNormally(request)
		change(response)
		return response, err
	})
}

func TestWrap_RefusesAResponseNamingAVersionOfAnotherKey_OrNoVersion(t *testing.T) {
	fake := newFakeKMS(t)
	wrapper := newWrapper(t, fake.client(t))
	for _, name := range []string{
		"",
		testKeyName,
		testKeyName + "/cryptoKeyVersions/",
		testKeyName + "/cryptoKeyVersions/1/x",
		testKeyName + "x/cryptoKeyVersions/1",
		otherKeyName + "/cryptoKeyVersions/1",
		strings.ToUpper(testKeyName) + "/cryptoKeyVersions/1",
		"x" + testKeyName + "/cryptoKeyVersions/1",
	} {
		answerEncryptWith(fake, func(r *kmspb.EncryptResponse) { r.Name = name })
		_, err := wrapper.Wrap(t.Context(), random(32), make([]byte, 512))
		requireCloudKMSError(t, err, "Cloud KMS wrap for key '"+testKeyName+"' reported key version '"+name+"' instead.")
	}
}

func TestWrap_AcceptsAnyVersionOfThisKey(t *testing.T) {
	fake := newFakeKMS(t)
	wrapper := newWrapper(t, fake.client(t))
	for _, version := range []string{"1", "17", "abc"} {
		answerEncryptWith(fake, func(r *kmspb.EncryptResponse) { r.Name = testKeyName + "/cryptoKeyVersions/" + version })
		if _, err := wrapper.Wrap(t.Context(), random(32), make([]byte, 512)); err != nil {
			t.Errorf("%s: %v", version, err)
		}
	}
}

func TestWrap_RefusesAResponseThatDidntVerifyTheRequestsChecksums(t *testing.T) {
	fake := newFakeKMS(t)
	wrapper := newWrapper(t, fake.client(t))
	for _, change := range []func(*kmspb.EncryptResponse){
		func(r *kmspb.EncryptResponse) { r.VerifiedPlaintextCrc32C = false },
		func(r *kmspb.EncryptResponse) { r.VerifiedAdditionalAuthenticatedDataCrc32C = false },
	} {
		answerEncryptWith(fake, change)
		_, err := wrapper.Wrap(t.Context(), random(32), make([]byte, 512))
		requireCloudKMSError(t, err, "Cloud KMS wrap for key '"+testKeyName+"' didn't verify the request's checksums: it was corrupted in transit.")
	}
}

func TestWrap_RefusesACiphertextThatDoesntMatchItsChecksum(t *testing.T) {
	fake := newFakeKMS(t)
	wrapper := newWrapper(t, fake.client(t))
	for _, change := range []func(*kmspb.EncryptResponse){
		func(r *kmspb.EncryptResponse) { r.Ciphertext[5] ^= 1 },
		func(r *kmspb.EncryptResponse) { r.CiphertextCrc32C = nil },
		func(r *kmspb.EncryptResponse) { r.CiphertextCrc32C = wrapperspb.Int64(r.CiphertextCrc32C.Value ^ 1) },
	} {
		answerEncryptWith(fake, change)
		result := filled(512)
		_, err := wrapper.Wrap(t.Context(), random(32), result)
		requireCloudKMSError(t, err, "Cloud KMS wrap for key '"+testKeyName+"' returned a ciphertext that doesn't match its checksum: it was corrupted in transit.")
		if !bytes.Equal(result, filled(512)) {
			t.Error("the result was changed")
		}
	}
}

func TestWrap_RefusesAResponseWithNoCiphertext_OrOneOverTheKeyFileLimit(t *testing.T) {
	fake := newFakeKMS(t)
	wrapper := newWrapper(t, fake.client(t))
	answerEncryptWith(fake, func(r *kmspb.EncryptResponse) { r.Ciphertext, r.CiphertextCrc32C = nil, wrapperspb.Int64(0) })
	_, err := wrapper.Wrap(t.Context(), random(32), make([]byte, 512))
	requireCloudKMSError(t, err, "Cloud KMS wrap for key '"+testKeyName+"' returned no ciphertext.")

	answerEncryptWith(fake, func(r *kmspb.EncryptResponse) {
		r.Ciphertext = random(hkdfguard.MaxWrappedKeyBytes + 1)
		r.CiphertextCrc32C = wrapperspb.Int64(crc32c(r.Ciphertext))
	})
	_, err = wrapper.GenerateAndWrap(t.Context(), make([]byte, 1024))
	requireCloudKMSError(t, err, "Cloud KMS wrap for key '"+testKeyName+"' returned 513 bytes; a wrapped DEK is at most 512.")

	answerEncryptWith(fake, func(r *kmspb.EncryptResponse) {
		r.Ciphertext = random(hkdfguard.MaxWrappedKeyBytes)
		r.CiphertextCrc32C = wrapperspb.Int64(crc32c(r.Ciphertext))
	})
	if n, err := wrapper.Wrap(t.Context(), random(32), make([]byte, 512)); err != nil || n != 512 {
		t.Errorf("%d, %v; want the largest wrapped DEK accepted", n, err)
	}
}

// --- Failures ------------------------------------------------------------------------------------

func TestFailures_ARefusalNamesTheOperationTheKeyTheStatusAndGooglesDescription_WithTheClientsErrorAsTheCause(t *testing.T) {
	fake := newFakeKMS(t)
	for transport, client := range map[string]Client{"gRPC": fake.client(t), "REST": fake.restClient(t)} {
		wrapper := newWrapper(t, client)
		fake.answerEncrypt(nil)
		wrapped := wrapWith(t, wrapper, random(32))
		denied := status.Error(codes.PermissionDenied, "Permission 'cloudkms.cryptoKeyVersions.useToEncrypt' denied on resource.")
		fake.answerEncrypt(func(*kmspb.EncryptRequest) (*kmspb.EncryptResponse, error) { return nil, denied })
		fake.answerDecrypt(func(*kmspb.DecryptRequest) (*kmspb.DecryptResponse, error) {
			return nil, status.Error(codes.NotFound, "CryptoKey "+testKeyName+" not found.")
		})

		_, err := wrapper.GenerateAndWrap(t.Context(), make([]byte, 512))
		kmsErr := requireCloudKMSError(t, err, "Cloud KMS wrap failed for key '"+testKeyName+
			"': PERMISSION_DENIED: Permission 'cloudkms.cryptoKeyVersions.useToEncrypt' denied on resource.")
		var apiErr *apierror.APIError
		if kmsErr.Op != "wrap" || kmsErr.Err == nil || !errors.As(err, &apiErr) || status.Code(err) != codes.PermissionDenied {
			t.Errorf("%s: Op %q, cause %v; want the client's error", transport, kmsErr.Op, kmsErr.Err)
		}

		result := filled(32)
		_, err = wrapper.Unwrap(t.Context(), wrapped, result)
		requireCloudKMSError(t, err, "Cloud KMS unwrap failed for key '"+testKeyName+"': NOT_FOUND: CryptoKey "+testKeyName+" not found.")
		if !hkdfguard.IsZero(result) {
			t.Errorf("%s: the result was not zeroed", transport)
		}
		fake.answerDecrypt(nil)
	}
}

func TestFailures_AChecksumCloudKMSFoundDidntMatchIsReported(t *testing.T) {
	fake := newFakeKMS(t)
	fake.answerEncrypt(func(request *kmspb.EncryptRequest) (*kmspb.EncryptResponse, error) {
		request.PlaintextCrc32C = wrapperspb.Int64(request.PlaintextCrc32C.Value ^ 1) // corrupted on the way
		return fake.encryptNormally(request)
	})
	_, err := newWrapper(t, fake.client(t)).Wrap(t.Context(), random(32), make([]byte, 512))
	requireCloudKMSError(t, err, "Cloud KMS wrap failed for key '"+testKeyName+
		"': INVALID_ARGUMENT: The checksum in field plaintext_crc32c did not match the data in field plaintext.")
}

func TestFailures_AFailureWithNoGRPCStatusIsNamedByItsMessage(t *testing.T) {
	stub := newStub(newFakeKMS(t))
	broken := errors.New("the connection was reset")
	stub.decrypt = func(*kmspb.DecryptRequest) (*kmspb.DecryptResponse, error) { return nil, broken }
	result := filled(32)
	_, err := newWrapper(t, stub).Unwrap(t.Context(), random(61), result)
	requireCloudKMSError(t, err, "Cloud KMS unwrap failed for key '"+testKeyName+"': the connection was reset")
	if !errors.Is(err, broken) || !hkdfguard.IsZero(result) {
		t.Errorf("got %v; want the client's error as the cause, and the result zeroed", err)
	}
}

func TestFailures_ACredentialThatCantGetATokenIsAnErrorWithItsMessage_MakingNoCall(t *testing.T) {
	fake := newFakeKMS(t)
	tokenErr := errors.New("credentials: could not find default credentials")
	credentials := auth.NewCredentials(&auth.CredentialsOptions{
		TokenProvider: tokenProviderFunc(func(context.Context) (*auth.Token, error) { return nil, tokenErr }),
	})
	client := fake.restClient(t, option.WithAuthCredentials(credentials))
	_, err := newWrapper(t, client).Wrap(t.Context(), random(32), make([]byte, 512))
	requireCloudKMSError(t, err, "Cloud KMS wrap failed for key '"+testKeyName+"': ...")
	if !errors.Is(err, tokenErr) || !strings.Contains(err.Error(), tokenErr.Error()) {
		t.Errorf("got %v; want the credential's error as the cause, and its message", err)
	}
	if fake.calls() != 0 {
		t.Error("a request was sent without a token")
	}
}

type tokenProviderFunc func(context.Context) (*auth.Token, error)

func (f tokenProviderFunc) Token(ctx context.Context) (*auth.Token, error) { return f(ctx) }

func TestFailures_AClientThatReturnsNoResponse(t *testing.T) {
	stub := newStub(newFakeKMS(t))
	stub.encrypt = func(*kmspb.EncryptRequest) (*kmspb.EncryptResponse, error) { return nil, nil }
	stub.decrypt = func(*kmspb.DecryptRequest) (*kmspb.DecryptResponse, error) { return nil, nil }
	wrapper := newWrapper(t, stub)
	_, err := wrapper.Wrap(t.Context(), random(32), make([]byte, 512))
	requireCloudKMSError(t, err, "Cloud KMS wrap for key '"+testKeyName+"' returned no response.")
	result := filled(32)
	_, err = wrapper.Unwrap(t.Context(), random(61), result)
	requireCloudKMSError(t, err, "Cloud KMS unwrap for key '"+testKeyName+"' returned no response.")
	if !hkdfguard.IsZero(result) {
		t.Error("the result was not zeroed")
	}
}

func TestFailures_AnEndedContextMakesNoCall(t *testing.T) {
	fake := newFakeKMS(t)
	wrapper := newWrapper(t, fake.client(t))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	result := filled(hkdfguard.MaxWrappedKeyBytes)

	if _, err := wrapper.Wrap(ctx, random(32), result); !errors.Is(err, context.Canceled) {
		t.Errorf("wrap: %v", err)
	}
	if _, err := wrapper.GenerateAndWrap(ctx, result); !errors.Is(err, context.Canceled) {
		t.Errorf("generate-and-wrap: %v", err)
	}
	if _, err := wrapper.ReadKeyFile(ctx, "v1.key"); !errors.Is(err, context.Canceled) {
		t.Errorf("read key file: %v", err)
	}
	if _, err := wrapper.Unwrap(ctx, random(61), result); !errors.Is(err, context.Canceled) {
		t.Errorf("unwrap: %v", err)
	}
	if !hkdfguard.IsZero(result) {
		t.Error("unwrap did not zero the result")
	}
	if fake.calls() != 0 {
		t.Error("Cloud KMS was called")
	}
}

func TestFailures_ACancellationOrTimeoutInFlightMatchesTheContextsError_AndUnwrapZeroesTheResult(t *testing.T) {
	fake := newFakeKMS(t)
	fake.hangCalls()
	for transport, client := range map[string]Client{"gRPC": fake.client(t), "REST": fake.restClient(t)} {
		wrapper := newWrapper(t, client)

		ctx, cancel := context.WithCancel(t.Context())
		time.AfterFunc(50*time.Millisecond, cancel)
		result := filled(32)
		_, err := wrapper.Unwrap(ctx, random(61), result)
		if !errors.Is(err, context.Canceled) || errors.Is(err, ErrCloudKMS) {
			t.Errorf("%s unwrap: %v (%T); want the cancellation", transport, err, err)
		}
		if !hkdfguard.IsZero(result) {
			t.Errorf("%s: the result was not zeroed", transport)
		}

		ctx, cancel = context.WithTimeout(t.Context(), 50*time.Millisecond)
		_, err = wrapper.GenerateAndWrap(ctx, make([]byte, 512))
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrCloudKMS) {
			t.Errorf("%s generate-and-wrap: %v (%T); want the timeout", transport, err, err)
		}
	}
}

// --- CRC32C --------------------------------------------------------------------------------------

func TestCRC32C_MatchesTheStandardCheckValues(t *testing.T) {
	ascending, descending := make([]byte, 32), make([]byte, 32)
	for i := range 32 {
		ascending[i], descending[i] = byte(i), byte(31-i)
	}
	// RFC 3720, appendix B.4, and the CRC catalogue's check value.
	for _, c := range []struct {
		data []byte
		want int64
	}{
		{make([]byte, 32), 0x8a9136aa},
		{bytes.Repeat([]byte{0xff}, 32), 0x62a8ab43},
		{ascending, 0x46dd794e},
		{descending, 0x113fdb5c},
		{[]byte("123456789"), 0xe3069283},
		{nil, 0},
	} {
		if got := crc32c(c.data); got != c.want {
			t.Errorf("crc32c(% x) = %#x; want %#x", c.data, got, c.want)
		}
	}
}
