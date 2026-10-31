package awssecretsmanager

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"

	"github.com/runsecure/hkdfguard-go/cache"
)

// Real calls against a secret the caller provides. The SDK resolves credentials and region the
// usual way (environment, shared config and credentials files, container or instance role):
//
//	aws configure
//	HKDFGUARD_TEST_AWS_SECRET_NAME=prod/my-secret go test -run TestAwsSecretsManagerIntegration -v ./...
//
// Without HKDFGUARD_TEST_AWS_SECRET_NAME every test here is reported as skipped - never as passed -
// the same variable the .NET integration tests read. Once it names a secret, a failing call is a
// test failure. The principal needs only secretsmanager:GetSecretValue on that secret (and
// kms:Decrypt on its key, if it isn't the AWS managed one); the tests never list, create, alter or
// delete a secret.
//
// To check what the secret holds, not just that it holds something, set
// HKDFGUARD_TEST_AWS_SECRET_JSON to the JSON object its SecretString is expected to hold (a
// key/value secret, as the console stores one): the whole value and each key, read as "name#key",
// are then compared with it.

const (
	secretNameVariable   = "HKDFGUARD_TEST_AWS_SECRET_NAME"
	expectedJSONVariable = "HKDFGUARD_TEST_AWS_SECRET_JSON"
)

// integrationCache is a cache over the configured secret's account and region, through a client
// the test creates as an application would, and the secret's name; it skips the test when no secret
// is configured.
func integrationCache(t *testing.T) (*cache.RemoteCache, string) {
	t.Helper()
	name := os.Getenv(secretNameVariable)
	if name == "" {
		t.Skipf("Set %s to a secret's name to run the AWS Secrets Manager cache integration tests.", secretNameVariable)
	}
	cfg, err := config.LoadDefaultConfig(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(secretsmanager.NewFromConfig(cfg), newRing(t), Options{})
	if err != nil {
		t.Fatal(err)
	}
	return c, name
}

// expectedSecret is the JSON object HKDFGUARD_TEST_AWS_SECRET_JSON holds; it skips the test when
// the variable isn't set.
func expectedSecret(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	text := os.Getenv(expectedJSONVariable)
	if text == "" {
		t.Skipf("Set %s and %s to check a secret's contents.", secretNameVariable, expectedJSONVariable)
	}
	var expected map[string]json.RawMessage
	if err := json.Unmarshal([]byte(text), &expected); err != nil || expected == nil {
		t.Fatalf("%s isn't a JSON object: %v", expectedJSONVariable, err)
	}
	return expected
}

// asCached is a member as the cache caches it: a string as its text, a number, true or false as
// its JSON text; false for null, an object or an array, which aren't cached.
func asCached(raw json.RawMessage) (string, bool) {
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return text, true
	}
	switch trimmed := strings.TrimSpace(string(raw)); {
	case trimmed == "null", strings.HasPrefix(trimmed, "{"), strings.HasPrefix(trimmed, "["):
		return "", false
	default:
		return trimmed, true
	}
}

// sameJSON reports whether a and b are the same JSON value, whatever their whitespace.
func sameJSON(t *testing.T, a, b string) bool {
	t.Helper()
	var x, y any
	if json.Unmarshal([]byte(a), &x) != nil || json.Unmarshal([]byte(b), &y) != nil {
		return false
	}
	return fmt.Sprint(x) == fmt.Sprint(y)
}

func TestAwsSecretsManagerIntegration_RevealsTheSecret(t *testing.T) {
	c, name := integrationCache(t)
	n, ok, err := c.MaxDecryptedLength(t.Context(), name)
	if err != nil || !ok {
		t.Fatalf("%v, %v; want the secret", ok, err)
	}
	if written, err := c.Decrypt(t.Context(), name, make([]byte, n)); err != nil || written == 0 {
		t.Fatalf("%d, %v; want the secret", written, err)
	}
}

func TestAwsSecretsManagerIntegration_RevealsTheExpectedWholeValue_AndEveryKey(t *testing.T) {
	c, name := integrationCache(t)
	expected := expectedSecret(t)

	whole := mustGet(t, c, name)
	wantWhole, _ := json.Marshal(expected)
	if !sameJSON(t, whole, string(wantWhole)) {
		t.Fatal("the secret's whole value isn't the expected JSON object")
	}
	for key, raw := range expected {
		want, cached := asCached(raw)
		if !cached {
			continue
		}
		if got := mustGet(t, c, name+"#"+key); got != want {
			t.Errorf("key %q doesn't hold the expected value", key)
		}
	}
	missing(t, c, name+"#no-such-key")
}

func TestAwsSecretsManagerIntegration_ASecretThatDoesNotExist_IsMissing(t *testing.T) {
	c, name := integrationCache(t)
	// Beside the configured secret, so a policy granting GetSecretValue on its path covers it:
	// without permission, Secrets Manager answers AccessDenied even for a secret that doesn't exist.
	folder := ""
	if slash := strings.LastIndexByte(name, '/'); slash >= 0 {
		folder = name[:slash+1]
	}
	missing(t, c, folder+"hkdfguard-missing-"+strings.ReplaceAll(rand.Text(), "=", ""))
}
