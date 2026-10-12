package aesgcm256

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/runsecure/hkdfguard-go"
)

const (
	pipelineVersion = 42
	pipelineID      = "Pipeline:Secret"
)

func newTestPipeline(t *testing.T) *PipelineDataProtector {
	t.Helper()
	p, err := NewPipelineDataProtector(testFormatProvider{}, pipelineVersion)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func pipelineDecrypt(p *PipelineDataProtector, formatted, id string) (string, error) {
	maxLength, err := p.MaxDecryptedLength(context.Background(), formatted)
	if err != nil {
		return "", err
	}
	result := make([]byte, maxLength)
	n, err := p.Decrypt(context.Background(), formatted, id, result)
	return string(result[:n]), err
}

func pipelineEncrypt(t *testing.T, p *PipelineDataProtector, plaintext, id string) string {
	t.Helper()
	formatted, err := p.Encrypt(context.Background(), []byte(plaintext), id)
	if err != nil {
		t.Fatal(err)
	}
	return formatted
}

func TestPipeline_RoundTrips(t *testing.T) {
	p := newTestPipeline(t)
	for _, plaintext := range []string{"hello", "héllo wörld ✓ 🔐", ""} {
		if got, err := pipelineDecrypt(p, pipelineEncrypt(t, p, plaintext, pipelineID), pipelineID); err != nil || got != plaintext {
			t.Errorf("%q: got %q, %v", plaintext, got, err)
		}
	}
}

func TestPipeline_LeavesTheCallersPlaintextAlone(t *testing.T) {
	p := newTestPipeline(t)
	plaintext := []byte("caller's copy")

	if _, err := p.Encrypt(context.Background(), plaintext, pipelineID); err != nil || string(plaintext) != "caller's copy" {
		t.Errorf("plaintext = %q, %v", plaintext, err)
	}
}

func TestPipeline_AnEmptyOrInvalidIdentifier_IsRefused(t *testing.T) {
	p := newTestPipeline(t)
	formatted := pipelineEncrypt(t, p, "hello", pipelineID)

	for _, id := range []string{"", "Key\xed\xa0\x80"} {
		if _, err := p.Encrypt(context.Background(), []byte("hello"), id); !errors.Is(err, hkdfguard.ErrInvalidConfigurationKey) {
			t.Errorf("Encrypt(%q): %v", id, err)
		}
		if _, err := pipelineDecrypt(p, formatted, id); !errors.Is(err, hkdfguard.ErrInvalidConfigurationKey) {
			t.Errorf("Decrypt(%q): %v", id, err)
		}
	}
}

func TestPipeline_IdentifiersAreCaseInsensitive_LikeConfigurationKeys(t *testing.T) {
	p := newTestPipeline(t)
	formatted := pipelineEncrypt(t, p, "hello", pipelineID)

	for _, lookup := range []string{"pipeline:secret", "PIPELINE:SECRET"} {
		if got, err := pipelineDecrypt(p, formatted, lookup); err != nil || got != "hello" {
			t.Errorf("%q: %q, %v", lookup, got, err)
		}
	}
}

func TestPipeline_ALongIdentifier_RoundTrips_AndIsExact(t *testing.T) {
	p := newTestPipeline(t)
	long := strings.Repeat("Section:", 60) + "Leaf"
	formatted := pipelineEncrypt(t, p, "hello", long)

	if got, err := pipelineDecrypt(p, formatted, long); err != nil || got != "hello" {
		t.Errorf("got %q, %v", got, err)
	}
	if _, err := pipelineDecrypt(p, formatted, long+"X"); !errors.Is(err, hkdfguard.ErrAuthenticationFailed) {
		t.Errorf("another identifier: %v", err)
	}
}

func TestPipeline_StampsTheKeyVersion_AndNeverRepeatsOutput(t *testing.T) {
	p := newTestPipeline(t)
	formatted := pipelineEncrypt(t, p, "hello", pipelineID)

	if p.KeyVersion() != pipelineVersion || !strings.HasPrefix(formatted, "enc::v42::") || strings.Contains(formatted, "hello") {
		t.Errorf("formatted = %q", formatted)
	}
	if formatted == pipelineEncrypt(t, p, "hello", pipelineID) {
		t.Error("the same value encrypted twice gave the same output")
	}
}

func TestPipeline_OneKeyProtectsManySecrets_EachBoundToItsIdentifier(t *testing.T) {
	p := newTestPipeline(t)
	admin := pipelineEncrypt(t, p, "admin-secret", "ConnectionStrings:Admin")
	reporting := pipelineEncrypt(t, p, "reporting-secret", "ConnectionStrings:Reporting")

	if got, _ := pipelineDecrypt(p, admin, "ConnectionStrings:Admin"); got != "admin-secret" {
		t.Errorf("admin = %q", got)
	}
	if got, _ := pipelineDecrypt(p, reporting, "ConnectionStrings:Reporting"); got != "reporting-secret" {
		t.Errorf("reporting = %q", got)
	}
	if _, err := pipelineDecrypt(p, admin, "ConnectionStrings:Reporting"); !errors.Is(err, hkdfguard.ErrAuthenticationFailed) {
		t.Errorf("moved value: %v", err)
	}
}

func TestPipeline_OtherVersionsInstancesAndMalformedInput_Fail(t *testing.T) {
	p := newTestPipeline(t)
	formatted := pipelineEncrypt(t, p, "hello", pipelineID)

	otherVersion := strings.Replace(formatted, "v42", "v7", 1)
	if _, err := pipelineDecrypt(p, otherVersion, pipelineID); !errors.Is(err, hkdfguard.ErrKeyNotFound) {
		t.Errorf("other version: %v", err)
	}
	if _, err := pipelineDecrypt(newTestPipeline(t), formatted, pipelineID); !errors.Is(err, hkdfguard.ErrAuthenticationFailed) {
		t.Errorf("other instance: %v", err)
	}
	if _, err := p.Decrypt(context.Background(), "not-a-valid-format", pipelineID, make([]byte, 16)); err == nil {
		t.Error("malformed input decrypted")
	}
}

func TestPipeline_KeyBase64_IsTheKey_InOneReusedBuffer(t *testing.T) {
	key := randomKey(t)
	p, err := newPipelineDataProtector(testFormatProvider{}, pipelineVersion, bytes.Clone(key), defaultBudget())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	first, second := p.KeyBase64(), p.KeyBase64()
	if string(first) != base64.StdEncoding.EncodeToString(key) {
		t.Errorf("KeyBase64 = %q", first)
	}
	if &first[0] != &second[0] {
		t.Error("KeyBase64 returned a different buffer the second time")
	}
}

func TestPipeline_CountsAgainstTheKeysBudget(t *testing.T) {
	budget, _ := newEncryptionBudget(1, 2)
	p, _ := newPipelineDataProtector(testFormatProvider{}, pipelineVersion, randomKey(t), budget)
	defer p.Close()

	formatted := pipelineEncrypt(t, p, "one", pipelineID)
	pipelineEncrypt(t, p, "two", pipelineID)

	if _, err := p.Encrypt(context.Background(), []byte("three"), pipelineID); !errors.Is(err, hkdfguard.ErrEncryptionLimitReached) || p.EncryptionCount() != 2 {
		t.Errorf("third encrypt: %v (count %d)", err, p.EncryptionCount())
	}
	if got, _ := pipelineDecrypt(p, formatted, pipelineID); got != "one" {
		t.Errorf("decrypted %q", got)
	}
}

func TestPipeline_Close_ZeroesTheKeyAndBase64_AndFailsLaterUse(t *testing.T) {
	key := randomKey(t)
	p, _ := newPipelineDataProtector(testFormatProvider{}, pipelineVersion, key, defaultBudget())
	formatted := pipelineEncrypt(t, p, "hello", pipelineID)
	encoded := p.KeyBase64()

	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if err := p.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}

	if !hkdfguard.IsZero(key) || !hkdfguard.IsZero(encoded) {
		t.Error("the key or its base64 form was not zeroed")
	}
	if _, err := p.Encrypt(context.Background(), []byte("hello"), pipelineID); !errors.Is(err, hkdfguard.ErrClosed) {
		t.Errorf("Encrypt: %v", err)
	}
	if _, err := pipelineDecrypt(p, formatted, pipelineID); !errors.Is(err, hkdfguard.ErrClosed) {
		t.Errorf("Decrypt: %v", err)
	}
	if p.KeyBase64() != nil {
		t.Error("KeyBase64 after Close is not nil")
	}
}

func TestPipeline_RequiresAFormatProvider(t *testing.T) {
	if _, err := NewPipelineDataProtector(nil, pipelineVersion); err == nil {
		t.Error("a nil format provider was accepted")
	}
}
