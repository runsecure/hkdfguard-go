package integration

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"hash/crc32"
	"os"
	"strings"
	"sync"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/runsecure/hkdfguard-go/dek"
	"github.com/runsecure/hkdfguard-go/keywrapping/googlekms"
	"github.com/runsecure/hkdfguard-go/securefile"
)

// The Google Cloud KMS key wrapper with the rest of HkdfGuard: a release pipeline wrapping its key
// through Cloud KMS into a key file, and an application building a ring from it - and generating a
// runtime key - through the same wrapper. Cloud KMS is an in-process stand-in for the client,
// holding a real AES-256 key and checking every checksum as the service does, so these run
// everywhere; the real-Cloud KMS round trips are keywrapping/googlekms's integration tests, and the
// client's own transports are covered by its unit tests.

const (
	googleKeyName = "projects/hkdfguard-e2e/locations/us-east1/keyRings/hkdfguard/cryptoKeys/wrap"
	googleContext = "hkdfguard.integrationtest"
)

var googleCastagnoli = crc32.MakeTable(crc32.Castagnoli)

// localCloudKMS stands in for Cloud KMS holding one version of one symmetric key, answering Encrypt
// and Decrypt as a googlekms.Client: AES-256-GCM, the key version and the AAD bound into every
// ciphertext, and every request and response checksummed.
type localCloudKMS struct {
	aead  cipher.AEAD
	mu    sync.Mutex
	calls map[string]int
}

func newLocalCloudKMS(t *testing.T) *localCloudKMS {
	t.Helper()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return &localCloudKMS{aead: aead, calls: map[string]int{}}
}

func googleCRC32C(data []byte) *wrapperspb.Int64Value {
	return wrapperspb.Int64(int64(crc32.Checksum(data, googleCastagnoli)))
}

func checksumMatches(data []byte, checksum *wrapperspb.Int64Value) bool {
	return checksum == nil || checksum.GetValue() == googleCRC32C(data).GetValue()
}

func (k *localCloudKMS) count(op string) int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.calls[op]
}

func (k *localCloudKMS) called(op, name string) error {
	k.mu.Lock()
	k.calls[op]++
	k.mu.Unlock()
	if name != googleKeyName {
		return status.Errorf(codes.NotFound, "%s not found.", name)
	}
	return nil
}

func (k *localCloudKMS) Encrypt(_ context.Context, request *kmspb.EncryptRequest, _ ...gax.CallOption) (*kmspb.EncryptResponse, error) {
	if err := k.called("encrypt", request.Name); err != nil {
		return nil, err
	}
	if !checksumMatches(request.Plaintext, request.PlaintextCrc32C) ||
		!checksumMatches(request.AdditionalAuthenticatedData, request.AdditionalAuthenticatedDataCrc32C) {
		return nil, status.Error(codes.InvalidArgument, "The checksum in field plaintext or additional_authenticated_data did not match the data.")
	}
	nonce := make([]byte, k.aead.NonceSize())
	_, _ = rand.Read(nonce)
	ciphertext := k.aead.Seal(nonce, nonce, request.Plaintext, request.AdditionalAuthenticatedData)
	return &kmspb.EncryptResponse{
		Name:                    googleKeyName + "/cryptoKeyVersions/1",
		Ciphertext:              ciphertext,
		CiphertextCrc32C:        googleCRC32C(ciphertext),
		VerifiedPlaintextCrc32C: request.PlaintextCrc32C != nil,
		VerifiedAdditionalAuthenticatedDataCrc32C: request.AdditionalAuthenticatedDataCrc32C != nil,
	}, nil
}

func (k *localCloudKMS) Decrypt(_ context.Context, request *kmspb.DecryptRequest, _ ...gax.CallOption) (*kmspb.DecryptResponse, error) {
	if err := k.called("decrypt", request.Name); err != nil {
		return nil, err
	}
	if !checksumMatches(request.Ciphertext, request.CiphertextCrc32C) ||
		!checksumMatches(request.AdditionalAuthenticatedData, request.AdditionalAuthenticatedDataCrc32C) {
		return nil, status.Error(codes.InvalidArgument, "The checksum in field ciphertext or additional_authenticated_data did not match the data.")
	}
	size := k.aead.NonceSize()
	if len(request.Ciphertext) < size {
		return nil, status.Error(codes.InvalidArgument, "Decryption failed: the ciphertext is invalid.")
	}
	plaintext, err := k.aead.Open(nil, request.Ciphertext[:size], request.Ciphertext[size:], request.AdditionalAuthenticatedData)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "Decryption failed: the ciphertext is invalid.")
	}
	return &kmspb.DecryptResponse{Plaintext: plaintext, PlaintextCrc32C: googleCRC32C(plaintext)}, nil
}

func googleWrapper(t *testing.T, kms *localCloudKMS, context string, trust securefile.KeyFileTrust) *googlekms.KeyWrapper {
	t.Helper()
	wrapper, err := googlekms.New(kms, googleKeyName, googlekms.Options{Context: context, KeyFileTrust: trust})
	if err != nil {
		t.Fatal(err)
	}
	return wrapper
}

func TestGoogleKMS_LetsACryptoProviderGenerateAndRevealItsDEKThroughCloudKMS(t *testing.T) {
	kms := newLocalCloudKMS(t)
	ring, err := buildKMSRing(t, dek.Config{KeyWrapper: googleWrapper(t, kms, googleContext, securefile.AdministratorsOnly()), EphemeralKeys: []int{100}})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	protector, err := ring.CreateProtector("customer-notes")
	if err != nil {
		t.Fatal(err)
	}
	formatted := protect(t, protector, "hello, cloud kms")
	if !strings.HasPrefix(formatted, "enc::v100::") {
		t.Errorf("formatted = %q", formatted)
	}
	if got := unprotect(t, protector, formatted); got != "hello, cloud kms" {
		t.Errorf("decrypted = %q", got)
	}
	if kms.count("encrypt") != 1 || kms.count("decrypt") < 1 {
		t.Errorf("Cloud KMS calls %v; want one encrypt and at least one decrypt", kms.calls)
	}
}

func TestGoogleKMS_PipelineEncryptedConfiguration_DecryptsThroughItsCloudKMSWrappedKeyFile(t *testing.T) {
	kms := newLocalCloudKMS(t)
	wrapper := googleWrapper(t, kms, googleContext, trustThisAccount(t))
	keyFile, values := runPipelineWith(t, wrapper, "v3.key", map[string]string{"ConnectionStrings:Admin": "Server=db;Password=hunter2"})

	ring, err := buildKMSRing(t, dek.Config{KeyWrapper: wrapper, KeyFiles: map[int]string{keyFileVersion: keyFile}})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if got := mustReveal(t, configReader(t, ring, values), "ConnectionStrings:Admin"); got != "Server=db;Password=hunter2" {
		t.Errorf("revealed %q", got)
	}
}

func TestGoogleKMS_ARingRefusesToBuild_FromAKeyFileNoOneTrustedWrote(t *testing.T) {
	kms := newLocalCloudKMS(t)
	keyFile, _ := runPipelineWith(t, googleWrapper(t, kms, googleContext, trustThisAccount(t)), "v3.key", map[string]string{"Secret": "value"})
	if os.Geteuid() == 0 {
		t.Skip("Running as root, whose files are trusted.")
	}

	// The same file, read by a wrapper that trusts administrators only.
	_, err := buildKMSRing(t, dek.Config{KeyWrapper: googleWrapper(t, kms, googleContext, securefile.AdministratorsOnly()),
		KeyFiles: map[int]string{keyFileVersion: keyFile}})
	if !errors.Is(err, securefile.ErrUntrusted) {
		t.Fatalf("Build: %v; want the key file refused as not trusted", err)
	}
}

func TestGoogleKMS_ARingRefusesToBuild_FromAKeyFileUnderAnotherContext(t *testing.T) {
	kms := newLocalCloudKMS(t)
	keyFile, _ := runPipelineWith(t, googleWrapper(t, kms, googleContext, trustThisAccount(t)), "v3.key", map[string]string{"Secret": "value"})

	_, err := buildKMSRing(t, dek.Config{KeyWrapper: googleWrapper(t, kms, "another app", trustThisAccount(t)), KeyFiles: map[int]string{keyFileVersion: keyFile}})
	if !errors.Is(err, googlekms.ErrCloudKMS) || !strings.Contains(err.Error(), "INVALID_ARGUMENT") {
		t.Fatalf("Build: %v; want the key file refused by Cloud KMS", err)
	}
}
