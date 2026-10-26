package integration

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/cryptoprovider/aesgcm256"
	"github.com/runsecure/hkdfguard-go/dek"
	"github.com/runsecure/hkdfguard-go/keywrapping/awskms"
	"github.com/runsecure/hkdfguard-go/securefile"
)

// The AWS KMS key wrapper with the rest of HkdfGuard: a release pipeline wrapping its key through
// KMS into a key file, and an application building a ring from it - and generating a runtime key -
// through the same wrapper. KMS is an in-process stand-in that really encrypts (AES-GCM, binding
// the key ID and encryption context), so these run everywhere; the real-KMS round trips are
// keywrapping/awskms's integration tests.

const kmsKeyARN = "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"

var kmsContext = map[string]string{"purpose": "hkdfguard.integrationtest"}

// localKMS stands in for a symmetric KMS key, implementing the three calls awskms makes.
type localKMS struct {
	aead      cipher.AEAD
	mu        sync.Mutex
	generated int
	decrypted int
}

func newLocalKMS(t *testing.T) *localKMS {
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
	return &localKMS{aead: aead}
}

func (k *localKMS) aad(keyID *string, encryptionContext map[string]string) []byte {
	var b strings.Builder
	b.WriteString(aws.ToString(keyID))
	for _, key := range slices.Sorted(maps.Keys(encryptionContext)) {
		b.WriteString("\x00" + key + "=" + encryptionContext[key])
	}
	return []byte(b.String())
}

func (k *localKMS) seal(plaintext []byte, keyID *string, encryptionContext map[string]string) []byte {
	nonce := make([]byte, k.aead.NonceSize())
	_, _ = rand.Read(nonce)
	return k.aead.Seal(nonce, nonce, plaintext, k.aad(keyID, encryptionContext))
}

func (k *localKMS) Encrypt(_ context.Context, input *kms.EncryptInput, _ ...func(*kms.Options)) (*kms.EncryptOutput, error) {
	return &kms.EncryptOutput{KeyId: input.KeyId, CiphertextBlob: k.seal(input.Plaintext, input.KeyId, input.EncryptionContext)}, nil
}

func (k *localKMS) Decrypt(_ context.Context, input *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	k.mu.Lock()
	k.decrypted++
	k.mu.Unlock()
	size := k.aead.NonceSize()
	if len(input.CiphertextBlob) < size+k.aead.Overhead() {
		return nil, &types.InvalidCiphertextException{Message: aws.String("too short")}
	}
	plaintext, err := k.aead.Open(nil, input.CiphertextBlob[:size], input.CiphertextBlob[size:], k.aad(input.KeyId, input.EncryptionContext))
	if err != nil {
		return nil, &types.InvalidCiphertextException{Message: aws.String("from localKMS")}
	}
	return &kms.DecryptOutput{KeyId: input.KeyId, Plaintext: plaintext}, nil
}

func (k *localKMS) GenerateDataKeyWithoutPlaintext(_ context.Context, input *kms.GenerateDataKeyWithoutPlaintextInput,
	_ ...func(*kms.Options)) (*kms.GenerateDataKeyWithoutPlaintextOutput, error) {
	k.mu.Lock()
	k.generated++
	k.mu.Unlock()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	defer hkdfguard.Wipe(key)
	return &kms.GenerateDataKeyWithoutPlaintextOutput{KeyId: input.KeyId, CiphertextBlob: k.seal(key, input.KeyId, input.EncryptionContext)}, nil
}

func kmsWrapper(t *testing.T, client awskms.Client, trust securefile.KeyFileTrust) *awskms.KeyWrapper {
	t.Helper()
	wrapper, err := awskms.New(client, kmsKeyARN, awskms.Options{EncryptionContext: kmsContext, KeyFileTrust: trust})
	if err != nil {
		t.Fatal(err)
	}
	return wrapper
}

func buildKMSRing(t *testing.T, config dek.Config) (*dek.KeyRing, error) {
	t.Helper()
	config.CryptoProviderFactory = aesgcm256.NewFactory()
	config.KeyRefreshInterval = time.Minute
	ring, err := dek.Build(ctx, config)
	if err == nil {
		t.Cleanup(func() { _ = ring.Close() })
	}
	return ring, err
}

func TestAwsKms_LetsACryptoProviderGenerateAndRevealItsDEKThroughKMS(t *testing.T) {
	local := newLocalKMS(t)
	ring, err := buildKMSRing(t, dek.Config{KeyWrapper: kmsWrapper(t, local, securefile.AdministratorsOnly()), EphemeralKeys: []int{100}})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	protector, err := ring.CreateProtector("customer-notes")
	if err != nil {
		t.Fatal(err)
	}
	formatted := protect(t, protector, "hello, kms")
	if !strings.HasPrefix(formatted, "enc::v100::") {
		t.Errorf("formatted = %q", formatted)
	}
	if got := unprotect(t, protector, formatted); got != "hello, kms" {
		t.Errorf("decrypted = %q", got)
	}
	if local.generated != 1 || local.decrypted < 1 {
		t.Errorf("KMS generated %d and decrypted %d keys; want 1 and at least 1", local.generated, local.decrypted)
	}
}

// runKMSPipeline does what a release pipeline does with KMS: protects configuration under a fresh
// in-memory key, wraps that key through KMS, and writes the wrapped result as the release's key
// file. It returns the key file's path and the configuration values.
func runKMSPipeline(t *testing.T, wrapper *awskms.KeyWrapper, secrets map[string]string) (string, map[string]string) {
	t.Helper()
	pipeline, err := aesgcm256.NewPipelineDataProtector(dek.NewDefaultFormatProvider(), keyFileVersion)
	if err != nil {
		t.Fatal(err)
	}
	defer pipeline.Close()

	values := make(map[string]string, len(secrets))
	for key, secret := range secrets {
		if values[key], err = pipeline.Encrypt(ctx, []byte(secret), key); err != nil {
			t.Fatal(err)
		}
	}

	dekBytes := make([]byte, aesgcm256.KeySize)
	defer hkdfguard.Wipe(dekBytes)
	if n, err := base64.StdEncoding.Decode(dekBytes, pipeline.KeyBase64()); err != nil || n != aesgcm256.KeySize {
		t.Fatalf("decoding the pipeline key: %d, %v", n, err)
	}
	wrapped := make([]byte, hkdfguard.MaxWrappedKeyBytes)
	n, err := wrapper.Wrap(ctx, dekBytes, wrapped)
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(keyFileDirectory(t), "v3.key")
	if err := os.WriteFile(path, wrapped[:n], 0o600); err != nil {
		t.Fatal(err)
	}
	return path, values
}

func TestAwsKms_PipelineEncryptedConfiguration_DecryptsThroughItsKMSWrappedKeyFile(t *testing.T) {
	local := newLocalKMS(t)
	wrapper := kmsWrapper(t, local, trustThisAccount(t))
	keyFile, values := runKMSPipeline(t, wrapper, map[string]string{"ConnectionStrings:Admin": "Server=db;Password=hunter2"})

	ring, err := buildKMSRing(t, dek.Config{KeyWrapper: wrapper, KeyFiles: map[int]string{keyFileVersion: keyFile}})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if got := mustReveal(t, configReader(t, ring, values), "ConnectionStrings:Admin"); got != "Server=db;Password=hunter2" {
		t.Errorf("revealed %q", got)
	}
}

func TestAwsKms_ARingRefusesToBuild_FromAKeyFileNoOneTrustedWrote(t *testing.T) {
	local := newLocalKMS(t)
	keyFile, _ := runKMSPipeline(t, kmsWrapper(t, local, trustThisAccount(t)), map[string]string{"Secret": "value"})
	if os.Geteuid() == 0 {
		t.Skip("Running as root, whose files are trusted.")
	}

	// The same file, read by a wrapper that trusts administrators only.
	_, err := buildKMSRing(t, dek.Config{KeyWrapper: kmsWrapper(t, local, securefile.AdministratorsOnly()), KeyFiles: map[int]string{keyFileVersion: keyFile}})
	if !errors.Is(err, securefile.ErrUntrusted) {
		t.Fatalf("Build: %v; want the key file refused as not trusted", err)
	}
}

func TestAwsKms_ARingRefusesToBuild_FromAKeyFileUnderAnotherEncryptionContext(t *testing.T) {
	local := newLocalKMS(t)
	keyFile, _ := runKMSPipeline(t, kmsWrapper(t, local, trustThisAccount(t)), map[string]string{"Secret": "value"})

	other, err := awskms.New(local, kmsKeyARN, awskms.Options{EncryptionContext: map[string]string{"purpose": "another app"}, KeyFileTrust: trustThisAccount(t)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = buildKMSRing(t, dek.Config{KeyWrapper: other, KeyFiles: map[int]string{keyFileVersion: keyFile}})
	if !errors.Is(err, awskms.ErrKMS) {
		t.Fatalf("Build: %v; want the KMS refusal", err)
	}
}
