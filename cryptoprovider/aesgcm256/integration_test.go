package aesgcm256_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/cryptoprovider/aesgcm256"
	"github.com/runsecure/hkdfguard-go/dek"
	"github.com/runsecure/hkdfguard-go/encryptedconfig"
)

// AES-256-GCM plugged into the dek layer, end to end - and the interop between pipeline-protected
// values and a key ring that is the whole point of the pipeline protector.

const (
	version = 3
	id      = "ConnectionStrings:Admin"
)

// fixedKeyWrapper reveals the same key on every unwrap, as a real wrapper does for one payload.
type fixedKeyWrapper struct{ key []byte }

func (w fixedKeyWrapper) Wrap(context.Context, []byte, []byte) (int, error) {
	return 0, errors.New("unused")
}
func (w fixedKeyWrapper) Unwrap(_ context.Context, _, result []byte) (int, error) {
	return copy(result, w.key), nil
}
func (w fixedKeyWrapper) GenerateAndWrap(_ context.Context, result []byte) (int, error) {
	return copy(result, "wrapped"), nil
}

// ringWithKey returns a ring holding key at version, through AES-256-GCM.
func ringWithKey(t *testing.T, key []byte) *dek.KeyRing {
	t.Helper()
	provider, err := aesgcm256.NewFactory().Create(context.Background(), fixedKeyWrapper{bytes.Clone(key)}, []byte("wrapped"), time.Minute, hkdfguard.RefreshFailurePolicy{})
	if err != nil {
		t.Fatal(err)
	}
	ring := dek.NewKeyRing(dek.NewDefaultFormatProvider())
	if err := ring.Add(context.Background(), version, dek.NewKey(provider)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ring.Close() })
	return ring
}

func decrypt(t *testing.T, p hkdfguard.DataProtector, formatted string) (string, error) {
	t.Helper()
	n, err := p.MaxDecryptedLength(context.Background(), formatted)
	if err != nil {
		return "", err
	}
	result := make([]byte, n)
	n, err = p.Decrypt(context.Background(), formatted, result)
	return string(result[:n]), err
}

func TestBuild_WithAESGCM_ProducesAWorkingRing(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	ring, err := dek.Build(context.Background(), dek.Config{
		KeyWrapper:            fixedKeyWrapper{key},
		CryptoProviderFactory: aesgcm256.NewFactory(),
		KeyRefreshInterval:    time.Minute,
		EphemeralKeys:         []int{1},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ring.Close()

	protector, _ := ring.CreateProtector("end to end")
	formatted, err := protector.Encrypt(context.Background(), []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := decrypt(t, protector, formatted); err != nil || got != "hello" {
		t.Errorf("%q, %v", got, err)
	}
}

// pipelineKey makes a pipeline protector and returns it with its key, decoded from KeyBase64.
func pipelineKey(t *testing.T) (*aesgcm256.PipelineDataProtector, []byte) {
	t.Helper()
	pipeline, err := aesgcm256.NewPipelineDataProtector(dek.NewDefaultFormatProvider(), version)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pipeline.Close() })

	encoded := pipeline.KeyBase64()
	key := make([]byte, 32)
	if n, err := base64.StdEncoding.Decode(key, encoded); err != nil || n != 32 {
		t.Fatalf("KeyBase64 decodes to %d bytes, %v", n, err)
	}
	return pipeline, key
}

func TestPipelineValues_DecryptThroughAKeyRingProtectorForTheIdentifiersPurpose(t *testing.T) {
	pipeline, key := pipelineKey(t)
	formatted, err := pipeline.Encrypt(context.Background(), []byte("hello"), id)
	if err != nil {
		t.Fatal(err)
	}

	purpose, _ := hkdfguard.ConfigurationPurpose(id)
	protector, _ := ringWithKey(t, key).CreateProtector(purpose)
	if got, err := decrypt(t, protector, formatted); err != nil || got != "hello" {
		t.Errorf("%q, %v", got, err)
	}
}

func TestKeyRingValues_ForTheIdentifiersPurpose_DecryptThroughThePipelineProtector(t *testing.T) {
	pipeline, key := pipelineKey(t)
	purpose, _ := hkdfguard.ConfigurationPurpose(id)
	protector, _ := ringWithKey(t, key).CreateProtector(purpose)
	formatted, err := protector.Encrypt(context.Background(), []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}

	result := make([]byte, 16)
	n, err := pipeline.Decrypt(context.Background(), formatted, id, result)
	if err != nil || string(result[:n]) != "hello" {
		t.Errorf("%q, %v", result[:n], err)
	}
}

func TestPipelineValues_DoNotDecryptUnderAPlainPurposeOfTheSameName(t *testing.T) {
	pipeline, key := pipelineKey(t)
	formatted, _ := pipeline.Encrypt(context.Background(), []byte("hello"), id)

	protector, _ := ringWithKey(t, key).CreateProtector(id)
	if _, err := decrypt(t, protector, formatted); !errors.Is(err, hkdfguard.ErrAuthenticationFailed) {
		t.Errorf("error = %v", err)
	}
}

func TestEverySecret_EncryptedByThePipelineIntoJSON_DecryptsAtRuntime(t *testing.T) {
	// Deploy time: the pipeline encrypts each secret for its configuration key into the file.
	pipeline, key := pipelineKey(t)
	secrets := map[string]string{
		"ConnectionStrings:Admin":     "Server=db;Password=hunter2",
		"ConnectionStrings:Reporting": "Server=db;Password=reporting",
		"Payments:ApiKey":             "pk_live_ünïcode_✓",
	}
	protected := map[string]string{}
	for name, secret := range secrets {
		formatted, err := pipeline.Encrypt(context.Background(), []byte(secret), name)
		if err != nil {
			t.Fatal(err)
		}
		protected[name] = formatted
	}
	document := fmt.Sprintf(`{
		"ConnectionStrings": { "Admin": %q, "Reporting": %q },
		"Payments": { "ApiKey": %q },
		"Logging": { "Level": "Information" }
	}`, protected["ConnectionStrings:Admin"], protected["ConnectionStrings:Reporting"], protected["Payments:ApiKey"])
	if strings.Contains(document, "hunter2") {
		t.Fatal("the configuration file holds a plaintext secret")
	}

	// Runtime: the file is read, and each secret decrypted through a ring holding the same key.
	values, err := encryptedconfig.FlattenJSON([]byte(document))
	if err != nil {
		t.Fatal(err)
	}
	lookup, err := encryptedconfig.NewMapLookup(values)
	if err != nil {
		t.Fatal(err)
	}
	reader := encryptedconfig.New(ringWithKey(t, key), lookup)

	for name, want := range secrets {
		for _, spelling := range []string{name, strings.ToLower(name)} {
			n, ok, err := reader.MaxDecryptedLength(context.Background(), spelling)
			if err != nil || !ok {
				t.Fatalf("%s: %v, %v", spelling, ok, err)
			}
			result := make([]byte, n)
			n, err = reader.Decrypt(context.Background(), spelling, result)
			if err != nil || string(result[:n]) != want {
				t.Errorf("%s = %q, %v", spelling, result[:n], err)
			}
		}
	}

	// A secret moved to another key in the file fails rather than decrypting.
	values["ConnectionStrings:Reporting"] = values["ConnectionStrings:Admin"]
	moved, _ := encryptedconfig.NewMapLookup(values)
	if _, err := encryptedconfig.New(ringWithKey(t, key), moved).Decrypt(context.Background(), "ConnectionStrings:Reporting", make([]byte, 64)); !errors.Is(err, hkdfguard.ErrAuthenticationFailed) {
		t.Errorf("moved secret: %v", err)
	}
}
