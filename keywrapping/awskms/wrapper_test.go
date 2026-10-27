package awskms

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"

	"github.com/runsecure/hkdfguard-go"
)

// --- Construction --------------------------------------------------------------------------------

func TestNew_RefusesMissingOrInvalidArguments(t *testing.T) {
	fake := newFakeKMS(t)
	for name, call := range map[string]func() (*KeyWrapper, error){
		"no client":      func() (*KeyWrapper, error) { return New(nil, keyARN, Options{}) },
		"empty key":      func() (*KeyWrapper, error) { return New(fake, "", Options{}) },
		"whitespace key": func() (*KeyWrapper, error) { return New(fake, " \t\n", Options{}) },
		"empty context key": func() (*KeyWrapper, error) {
			return New(fake, keyARN, Options{EncryptionContext: map[string]string{"": "x"}})
		},
		"one empty among many": func() (*KeyWrapper, error) {
			return New(fake, keyARN, Options{EncryptionContext: map[string]string{"a": "1", "": "2"}})
		},
	} {
		if wrapper, err := call(); !errors.Is(err, ErrInvalidArgument) || wrapper != nil {
			t.Errorf("%s: %v, %v; want ErrInvalidArgument", name, wrapper, err)
		}
	}
}

func TestNew_IsAKeyWrapperOverAnyClient_ARealKmsClientIncluded(t *testing.T) {
	var _ hkdfguard.KeyWrapper = newWrapper(t, newFakeKMS(t))
	wrapper := newWrapper(t, kms.New(kms.Options{Region: "us-east-1"}))
	if wrapper.KeyID() != keyARN {
		t.Errorf("KeyID() = %q", wrapper.KeyID())
	}
}

// --- Wrap, unwrap and generate-and-wrap ----------------------------------------------------------

func TestKeyWrapper_RoundTripsADEK(t *testing.T) {
	wrapper := newWrapper(t, newFakeKMS(t), withContext())
	dek := random(32)
	revealed := make([]byte, 32)
	n, err := wrapper.Unwrap(t.Context(), wrapWith(t, wrapper, dek), revealed)
	if err != nil || n != 32 || !bytes.Equal(revealed, dek) {
		t.Fatalf("%d, %v, %x; want the DEK", n, err, revealed)
	}
}

func TestWrap_SendsTheKeyContextAndAlgorithm_AndZeroesItsCopyOfThePlaintextOnceTheCallReturns(t *testing.T) {
	fake := newFakeKMS(t)
	wrapper := newWrapper(t, fake, withContext())
	dek := random(32)
	original := bytes.Clone(dek)
	wrapWith(t, wrapper, dek)

	request := fake.encryptRequests[0]
	if aws.ToString(request.KeyId) != keyARN || request.EncryptionAlgorithm != types.EncryptionAlgorithmSpecSymmetricDefault ||
		!maps.Equal(request.EncryptionContext, testContext) {
		t.Errorf("request %+v", request)
	}
	if !bytes.Equal(fake.encryptPlaintexts[0], original) {
		t.Error("KMS was not sent the plaintext")
	}
	if !hkdfguard.IsZero(request.Plaintext) {
		t.Error("the wrapper's copy of the plaintext was not zeroed")
	}
	if !bytes.Equal(dek, original) {
		t.Error("the caller's plaintext was modified")
	}
}

func TestWrap_ZeroesItsCopyOfThePlaintextWhenKmsRefuses(t *testing.T) {
	fake := newFakeKMS(t)
	fake.onEncrypt = func(*kms.EncryptInput) (*kms.EncryptOutput, error) {
		return nil, serviceError("Encrypt", &types.DisabledException{}, 400)
	}
	_, err := newWrapper(t, fake).Wrap(t.Context(), random(32), make([]byte, hkdfguard.MaxWrappedKeyBytes))
	requireKMSError(t, err, fmt.Sprintf("AWS KMS wrap failed for key '%s': DisabledException (HTTP 400).", keyARN))
	if !hkdfguard.IsZero(fake.encryptRequests[0].Plaintext) {
		t.Error("the wrapper's copy of the plaintext was not zeroed")
	}
}

func TestWrap_WritesIntoTheStartOfALargerResult(t *testing.T) {
	wrapper := newWrapper(t, newFakeKMS(t))
	result := filled(hkdfguard.MaxWrappedKeyBytes + 100)
	n, err := wrapper.Wrap(t.Context(), random(32), result)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result[n:], filled(len(result)-n)) {
		t.Error("bytes past the wrapped DEK were changed")
	}
}

func TestKeyWrapper_SendsNoContext_WhenGivenNoneOrAnEmptyOne(t *testing.T) {
	for _, options := range []Options{{}, {EncryptionContext: map[string]string{}}} {
		fake := newFakeKMS(t)
		wrapper := newWrapper(t, fake, options)
		wrapped := wrapWith(t, wrapper, random(32))
		if _, err := wrapper.Unwrap(t.Context(), wrapped, make([]byte, 32)); err != nil {
			t.Fatal(err)
		}
		if _, err := wrapper.GenerateAndWrap(t.Context(), make([]byte, hkdfguard.MaxWrappedKeyBytes)); err != nil {
			t.Fatal(err)
		}
		if fake.encryptRequests[0].EncryptionContext != nil || fake.decryptRequests[0].EncryptionContext != nil ||
			fake.generateRequests[0].EncryptionContext != nil {
			t.Errorf("%+v: a context was sent", options)
		}
	}
}

func TestKeyWrapper_CopiesTheContextAtConstruction_AndForEveryRequest(t *testing.T) {
	fake := newFakeKMS(t)
	given := map[string]string{"purpose": "hkdfguard.test"}
	wrapper := newWrapper(t, fake, Options{EncryptionContext: given})
	given["purpose"] = "changed"
	given["extra"] = "added"

	wrapWith(t, wrapper, random(32))
	fake.encryptRequests[0].EncryptionContext["purpose"] = "changed by a middleware"
	wrapWith(t, wrapper, random(32))

	if !maps.Equal(fake.encryptRequests[1].EncryptionContext, testContext) {
		t.Errorf("second request bound %v; want %v", fake.encryptRequests[1].EncryptionContext, testContext)
	}
}

func TestGenerateAndWrap_AsksKmsForAWrappedAes256KeyOnly(t *testing.T) {
	fake := newFakeKMS(t)
	wrapper := newWrapper(t, fake, withContext())
	result := make([]byte, hkdfguard.MaxWrappedKeyBytes)
	n, err := wrapper.GenerateAndWrap(t.Context(), result)
	if err != nil {
		t.Fatal(err)
	}
	request := fake.generateRequests[0]
	if aws.ToString(request.KeyId) != keyARN || request.KeySpec != types.DataKeySpecAes256 || request.NumberOfBytes != nil ||
		!maps.Equal(request.EncryptionContext, testContext) {
		t.Errorf("request %+v", request)
	}
	revealed := make([]byte, 32)
	if m, err := wrapper.Unwrap(t.Context(), result[:n], revealed); err != nil || m != GeneratedKeyLength || hkdfguard.IsZero(revealed) {
		t.Errorf("%d, %v; want %d non-zero bytes", m, err, GeneratedKeyLength)
	}
}

func TestUnwrap_PinsTheKey_SendingItsOwnCopyOfTheWrappedDEK(t *testing.T) {
	fake := newFakeKMS(t)
	wrapper := newWrapper(t, fake, withContext())
	wrapped := wrapWith(t, wrapper, random(32))
	if _, err := wrapper.Unwrap(t.Context(), wrapped, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	request := fake.decryptRequests[0]
	if aws.ToString(request.KeyId) != keyARN || request.EncryptionAlgorithm != types.EncryptionAlgorithmSpecSymmetricDefault ||
		!maps.Equal(request.EncryptionContext, testContext) || !bytes.Equal(request.CiphertextBlob, wrapped) {
		t.Errorf("request %+v", request)
	}
	if &request.CiphertextBlob[0] == &wrapped[0] {
		t.Error("the caller's wrapped DEK was sent, not a copy")
	}
}

func TestUnwrap_RefusesADEKWrappedUnderAnotherKey_ZeroingTheResult(t *testing.T) {
	fake := newFakeKMS(t)
	other, err := New(fake, "arn:aws:kms:us-east-1:111122223333:key/another", withContext())
	if err != nil {
		t.Fatal(err)
	}
	wrapped := wrapWith(t, other, random(32))
	result := filled(32)

	_, err = newWrapper(t, fake, withContext()).Unwrap(t.Context(), wrapped, result)
	kmsErr := requireKMSError(t, err, fmt.Sprintf("AWS KMS unwrap failed for key '%s': InvalidCiphertextException (HTTP 400).", keyARN))
	if kmsErr.Op != "unwrap" || kmsErr.KeyID != keyARN {
		t.Errorf("Op %q, KeyID %q", kmsErr.Op, kmsErr.KeyID)
	}
	var invalid *types.InvalidCiphertextException
	if !errors.As(err, &invalid) {
		t.Error("the SDK's error is not reachable with errors.As")
	}
	if !hkdfguard.IsZero(result) {
		t.Error("the result was not zeroed")
	}
}

func TestUnwrap_RefusesADEKWrappedUnderAnotherContext_OrNone(t *testing.T) {
	fake := newFakeKMS(t)
	wrapped := wrapWith(t, newWrapper(t, fake, withContext()), random(32))
	for _, options := range []Options{{}, {EncryptionContext: map[string]string{"purpose": "hkdfguard.test.other"}}} {
		_, err := newWrapper(t, fake, options).Unwrap(t.Context(), wrapped, make([]byte, 32))
		requireKMSError(t, err, "AWS KMS unwrap failed for key '"+keyARN+"': ...")
	}
}

func TestUnwrap_RefusesATamperedDEK(t *testing.T) {
	wrapper := newWrapper(t, newFakeKMS(t), withContext())
	wrapped := wrapWith(t, wrapper, random(32))
	wrapped[len(wrapped)-1] ^= 1
	_, err := wrapper.Unwrap(t.Context(), wrapped, make([]byte, 32))
	requireKMSError(t, err, "AWS KMS unwrap failed for key '"+keyARN+"': InvalidCiphertextException (HTTP 400).")
}

func TestUnwrap_RefusesAWrappedDEKOutOfBounds_WithoutCallingKms_ZeroingTheResult(t *testing.T) {
	fake := newFakeKMS(t)
	wrapper := newWrapper(t, fake)
	for _, length := range []int{0, hkdfguard.MaxWrappedKeyBytes + 1} {
		result := filled(32)
		_, err := wrapper.Unwrap(t.Context(), make([]byte, length), result)
		requireKMSError(t, err, fmt.Sprintf("A wrapped DEK is 1-%d bytes; got %d.", hkdfguard.MaxWrappedKeyBytes, length))
		if !hkdfguard.IsZero(result) {
			t.Errorf("%d bytes: the result was not zeroed", length)
		}
	}
	if len(fake.decryptRequests) != 0 {
		t.Error("KMS was called")
	}
}

func TestUnwrap_RefusesAResultTooSmallForTheRevealedKey_ZeroingItAndTheSdksPlaintext(t *testing.T) {
	fake := newFakeKMS(t)
	revealed := random(32)
	fake.onDecrypt = func(*kms.DecryptInput) (*kms.DecryptOutput, error) {
		return &kms.DecryptOutput{Plaintext: revealed}, nil
	}
	result := filled(16)

	_, err := newWrapper(t, fake).Unwrap(t.Context(), random(184), result)
	if !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("got %v; want ErrInvalidArgument", err)
	}
	if !hkdfguard.IsZero(result) || !hkdfguard.IsZero(revealed) {
		t.Error("the result or the SDK's plaintext was not zeroed")
	}
}

func TestUnwrap_ZeroesThePlaintextTheSdkDecoded_OnceItIsCopiedIntoTheResult(t *testing.T) {
	fake := newFakeKMS(t)
	key := random(32)
	revealed := bytes.Clone(key)
	fake.onDecrypt = func(*kms.DecryptInput) (*kms.DecryptOutput, error) {
		return &kms.DecryptOutput{Plaintext: revealed}, nil
	}
	result := make([]byte, 32)

	if n, err := newWrapper(t, fake).Unwrap(t.Context(), random(184), result); err != nil || n != 32 {
		t.Fatalf("%d, %v", n, err)
	}
	if !bytes.Equal(result, key) || !hkdfguard.IsZero(revealed) {
		t.Error("the key was not copied, or the SDK's plaintext was not zeroed")
	}
}

func TestUnwrap_WritesTheRevealedKeyIntoTheStartOfALargerResult(t *testing.T) {
	wrapper := newWrapper(t, newFakeKMS(t))
	dek := random(32)
	result := filled(64)
	n, err := wrapper.Unwrap(t.Context(), wrapWith(t, wrapper, dek), result)
	if err != nil || n != 32 || !bytes.Equal(result[:32], dek) || !bytes.Equal(result[32:], filled(32)) {
		t.Fatalf("%d, %v, %x", n, err, result)
	}
}

func TestUnwrap_FailsZeroingTheResult_WhenKmsReturnsNoPlaintext(t *testing.T) {
	for name, output := range map[string]*kms.DecryptOutput{"nil": {}, "empty": {Plaintext: []byte{}}} {
		fake := newFakeKMS(t)
		fake.onDecrypt = func(*kms.DecryptInput) (*kms.DecryptOutput, error) { return output, nil }
		result := filled(32)
		_, err := newWrapper(t, fake).Unwrap(t.Context(), random(184), result)
		requireKMSError(t, err, fmt.Sprintf("AWS KMS unwrap for key '%s' returned no plaintext.", keyARN))
		if !hkdfguard.IsZero(result) {
			t.Errorf("%s: the result was not zeroed", name)
		}
	}
}

func TestUnwrap_ZeroesTheResultWhateverTheFailure(t *testing.T) {
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	for name, run := range map[string]func(*fakeKMS, []byte) error{
		"cancelled": func(f *fakeKMS, result []byte) error {
			_, err := newWrapper(t, f).Unwrap(cancelled, random(184), result)
			return err
		},
		"an unexpected error": func(f *fakeKMS, result []byte) error {
			f.onDecrypt = func(*kms.DecryptInput) (*kms.DecryptOutput, error) { return nil, errors.New("boom") }
			_, err := newWrapper(t, f).Unwrap(t.Context(), random(184), result)
			return err
		},
		"no response": func(f *fakeKMS, result []byte) error {
			f.onDecrypt = func(*kms.DecryptInput) (*kms.DecryptOutput, error) { return nil, nil }
			_, err := newWrapper(t, f).Unwrap(t.Context(), random(184), result)
			return err
		},
	} {
		result := filled(32)
		if err := run(newFakeKMS(t), result); err == nil {
			t.Errorf("%s: no error", name)
		}
		if !hkdfguard.IsZero(result) {
			t.Errorf("%s: the result was not zeroed", name)
		}
	}
}

func TestWrap_RefusesAPlaintextKmsWouldRefuse_WithoutCallingIt(t *testing.T) {
	fake := newFakeKMS(t)
	wrapper := newWrapper(t, fake)
	for _, length := range []int{0, MaxPlaintextLength + 1} {
		_, err := wrapper.Wrap(t.Context(), make([]byte, length), make([]byte, hkdfguard.MaxWrappedKeyBytes))
		if !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("%d bytes: %v; want ErrInvalidArgument", length, err)
		}
	}
	if len(fake.encryptRequests) != 0 {
		t.Error("KMS was called")
	}
}

func TestWrap_AcceptsTheLargestPlaintextKmsDoes(t *testing.T) {
	fake := newFakeKMS(t)
	fake.onEncrypt = func(*kms.EncryptInput) (*kms.EncryptOutput, error) {
		return &kms.EncryptOutput{CiphertextBlob: random(184)}, nil
	}
	if _, err := newWrapper(t, fake).Wrap(t.Context(), random(MaxPlaintextLength), make([]byte, hkdfguard.MaxWrappedKeyBytes)); err != nil {
		t.Fatal(err)
	}
}

func TestKeyWrapper_RefusesAResultTooSmallForTheWrappedDEK(t *testing.T) {
	wrapper := newWrapper(t, newFakeKMS(t))
	if _, err := wrapper.Wrap(t.Context(), random(32), make([]byte, 16)); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("wrap: %v; want ErrInvalidArgument", err)
	}
	if _, err := wrapper.GenerateAndWrap(t.Context(), make([]byte, 16)); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("generate-and-wrap: %v; want ErrInvalidArgument", err)
	}
}

func TestKeyWrapper_RefusesACiphertextOverTheKeyFileLimit(t *testing.T) {
	fake := newFakeKMS(t)
	fake.onEncrypt = func(*kms.EncryptInput) (*kms.EncryptOutput, error) {
		return &kms.EncryptOutput{CiphertextBlob: random(hkdfguard.MaxWrappedKeyBytes + 1)}, nil
	}
	fake.onGenerate = func(*kms.GenerateDataKeyWithoutPlaintextInput) (*kms.GenerateDataKeyWithoutPlaintextOutput, error) {
		return &kms.GenerateDataKeyWithoutPlaintextOutput{CiphertextBlob: random(hkdfguard.MaxWrappedKeyBytes + 1)}, nil
	}
	wrapper := newWrapper(t, fake)
	big := make([]byte, 2*hkdfguard.MaxWrappedKeyBytes)
	_, err := wrapper.Wrap(t.Context(), random(32), big)
	requireKMSError(t, err, fmt.Sprintf("AWS KMS wrap for key '%s' returned 513 bytes; a wrapped DEK is at most 512.", keyARN))
	_, err = wrapper.GenerateAndWrap(t.Context(), big)
	requireKMSError(t, err, fmt.Sprintf("AWS KMS generate-and-wrap for key '%s' returned 513 bytes; a wrapped DEK is at most 512.", keyARN))
}

func TestKeyWrapper_FailsWhenKmsReturnsNoCiphertext_OrNoResponse(t *testing.T) {
	fake := newFakeKMS(t)
	fake.onEncrypt = func(*kms.EncryptInput) (*kms.EncryptOutput, error) { return &kms.EncryptOutput{}, nil }
	fake.onGenerate = func(*kms.GenerateDataKeyWithoutPlaintextInput) (*kms.GenerateDataKeyWithoutPlaintextOutput, error) {
		return nil, nil
	}
	wrapper := newWrapper(t, fake)
	result := make([]byte, hkdfguard.MaxWrappedKeyBytes)
	_, err := wrapper.Wrap(t.Context(), random(32), result)
	requireKMSError(t, err, fmt.Sprintf("AWS KMS wrap for key '%s' returned no ciphertext.", keyARN))
	_, err = wrapper.GenerateAndWrap(t.Context(), result)
	requireKMSError(t, err, fmt.Sprintf("AWS KMS generate-and-wrap for key '%s' returned no response.", keyARN))
}

// --- Cancellation --------------------------------------------------------------------------------

type contextKey struct{}

func TestKeyWrapper_RefusesAnEndedContext_WithoutCallingKms(t *testing.T) {
	fake := newFakeKMS(t)
	wrapper := newWrapper(t, fake)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	result := make([]byte, hkdfguard.MaxWrappedKeyBytes)

	if _, err := wrapper.Wrap(ctx, random(32), result); !errors.Is(err, context.Canceled) {
		t.Errorf("wrap: %v", err)
	}
	if _, err := wrapper.Unwrap(ctx, random(184), result); !errors.Is(err, context.Canceled) {
		t.Errorf("unwrap: %v", err)
	}
	if _, err := wrapper.GenerateAndWrap(ctx, result); !errors.Is(err, context.Canceled) {
		t.Errorf("generate-and-wrap: %v", err)
	}
	if _, err := wrapper.ReadKeyFile(ctx, "v1.key"); !errors.Is(err, context.Canceled) {
		t.Errorf("read key file: %v", err)
	}
	if len(fake.contexts) != 0 {
		t.Error("KMS was called")
	}
}

func TestKeyWrapper_PassesTheContextToTheSdk_AndLeavesItsCancellationAsItIs(t *testing.T) {
	fake := newFakeKMS(t)
	ctx, cancel := context.WithCancel(context.WithValue(t.Context(), contextKey{}, "mine"))
	defer cancel()
	sdkErr := &smithy.OperationError{ServiceID: "KMS", OperationName: "GenerateDataKeyWithoutPlaintext", Err: context.Canceled}
	fake.onGenerate = func(*kms.GenerateDataKeyWithoutPlaintextInput) (*kms.GenerateDataKeyWithoutPlaintextOutput, error) {
		cancel() // as if the caller cancelled while the request was in flight
		return nil, sdkErr
	}

	_, err := newWrapper(t, fake).GenerateAndWrap(ctx, make([]byte, hkdfguard.MaxWrappedKeyBytes))
	if err != error(sdkErr) {
		t.Errorf("got %v; want the SDK's error as it is", err)
	}
	if fake.contexts[0].Value(contextKey{}) != "mine" {
		t.Error("the caller's context was not passed to the SDK")
	}
}

// --- Failures ------------------------------------------------------------------------------------

func TestFailures_TurnAServiceRefusalIntoAnErrorNamingTheCodeAndTheHttpStatus(t *testing.T) {
	fake := newFakeKMS(t)
	sdkErr := serviceError("Decrypt", &types.IncorrectKeyException{Message: aws.String("wrong key")}, 400)
	fake.onDecrypt = func(*kms.DecryptInput) (*kms.DecryptOutput, error) { return nil, sdkErr }

	_, err := newWrapper(t, fake).Unwrap(t.Context(), random(184), make([]byte, 32))
	kmsErr := requireKMSError(t, err, fmt.Sprintf("AWS KMS unwrap failed for key '%s': IncorrectKeyException (HTTP 400).", keyARN))
	if kmsErr.Err != sdkErr {
		t.Errorf("cause %v; want the SDK's error", kmsErr.Err)
	}
	var incorrect *types.IncorrectKeyException
	if !errors.As(err, &incorrect) {
		t.Error("the modeled error is not reachable with errors.As")
	}
}

func TestFailures_NameAServerFaultAndAnUnmodeledErrorTheSameWay(t *testing.T) {
	fake := newFakeKMS(t)
	fake.onGenerate = func(*kms.GenerateDataKeyWithoutPlaintextInput) (*kms.GenerateDataKeyWithoutPlaintextOutput, error) {
		return nil, serviceError("GenerateDataKeyWithoutPlaintext", &types.KMSInternalException{}, 500)
	}
	fake.onEncrypt = func(*kms.EncryptInput) (*kms.EncryptOutput, error) {
		return nil, serviceError("Encrypt", &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "no", Fault: smithy.FaultClient}, 400)
	}
	wrapper := newWrapper(t, fake)
	_, err := wrapper.GenerateAndWrap(t.Context(), make([]byte, hkdfguard.MaxWrappedKeyBytes))
	requireKMSError(t, err, fmt.Sprintf("AWS KMS generate-and-wrap failed for key '%s': KMSInternalException (HTTP 500).", keyARN))
	_, err = wrapper.Wrap(t.Context(), random(32), make([]byte, hkdfguard.MaxWrappedKeyBytes))
	requireKMSError(t, err, fmt.Sprintf("AWS KMS wrap failed for key '%s': AccessDeniedException (HTTP 400).", keyARN))
}

func TestFailures_SaySoWhenARefusalHasNoHttpStatus(t *testing.T) {
	for name, sdkErr := range map[string]error{
		"no response":      serviceError("Decrypt", &types.DisabledException{}, 0),
		"no response type": &smithy.OperationError{ServiceID: "KMS", OperationName: "Decrypt", Err: &types.DisabledException{}},
	} {
		fake := newFakeKMS(t)
		fake.onDecrypt = func(*kms.DecryptInput) (*kms.DecryptOutput, error) { return nil, sdkErr }
		_, err := newWrapper(t, fake).Unwrap(t.Context(), random(184), make([]byte, 32))
		requireKMSError(t, err, fmt.Sprintf("AWS KMS unwrap failed for key '%s': DisabledException (HTTP unknown).", keyARN))
		_ = name
	}
}

func TestFailures_TurnAFailureOnTheWayToKmsIntoAnError(t *testing.T) {
	fake := newFakeKMS(t)
	sdkErr := &smithy.OperationError{ServiceID: "KMS", OperationName: "Encrypt", Err: errors.New("failed to refresh cached credentials, no EC2 IMDS role found")}
	fake.onEncrypt = func(*kms.EncryptInput) (*kms.EncryptOutput, error) { return nil, sdkErr }

	_, err := newWrapper(t, fake).Wrap(t.Context(), random(32), make([]byte, hkdfguard.MaxWrappedKeyBytes))
	kmsErr := requireKMSError(t, err, fmt.Sprintf("AWS KMS wrap failed for key '%s': %v", keyARN, sdkErr))
	if kmsErr.Err != sdkErr || !errors.Is(err, sdkErr) {
		t.Error("the SDK's error is not the cause")
	}
}

func TestFailures_WrapAnyOtherErrorTheClientReturns(t *testing.T) {
	// Go has no exception taxonomy that tells a bug in a test double from an SDK failure: whatever
	// the client returns is reported as a KMS failure, with it as the cause.
	fake := newFakeKMS(t)
	boom := errors.New("boom")
	fake.onEncrypt = func(*kms.EncryptInput) (*kms.EncryptOutput, error) { return nil, boom }
	_, err := newWrapper(t, fake).Wrap(t.Context(), random(32), make([]byte, hkdfguard.MaxWrappedKeyBytes))
	requireKMSError(t, err, fmt.Sprintf("AWS KMS wrap failed for key '%s': boom", keyARN))
	if !errors.Is(err, boom) {
		t.Error("the client's error is not the cause")
	}
}
