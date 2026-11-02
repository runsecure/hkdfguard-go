package googlesecretmanager

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"testing"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"

	"github.com/runsecure/hkdfguard-go/cache"
	"github.com/runsecure/hkdfguard-go/internal/kmstest"
)

// Real calls against a secret the caller provides, named in google.test.properties at the
// repository root (or the environment; see configuredSecret). Credentials come from Application
// Default Credentials (an attached service account, workload identity federation, or gcloud):
//
//	gcloud auth application-default login
//	go test -run TestGoogleSecretManagerIntegration -v ./...
//
// Without the secret every test here is reported as skipped - never as passed - the same variable
// the .NET integration tests read. The principal needs only secretmanager.versions.access on that
// secret (the Secret Manager Secret Accessor role); the tests never list, create, alter or delete a
// secret.
//
// To check what the secret holds, not just that it holds something, also set expectedJSONVariable
// to the JSON object its latest version's payload is expected to hold: the whole value and each
// member, read as "id#key", are then compared with it.

const (
	secretNameVariable   = "HKDFGUARD_TEST_GOOGLE_SECRET_NAME"
	expectedJSONVariable = "HKDFGUARD_TEST_GOOGLE_SECRET_JSON"
	settingsFile         = "google.test.properties"
)

// setting is name's value from the environment, else from the settings file at the repository root
// (shared with keywrapping/googlekms's integration tests); "" if neither sets it.
func setting(t *testing.T, name string) string {
	t.Helper()
	if value := os.Getenv(name); value != "" {
		return value
	}
	return kmstest.Settings(t, settingsFile)[name]
}

// configuredSecret is the real secret's project and ID, from its resource name,
// projects/{project}/secrets/{secret}; it skips the test unless one is named. A value that isn't a
// secret's resource name (a placeholder left in place, say) fails the test, naming the variable.
func configuredSecret(t *testing.T) (project, secretID string) {
	t.Helper()
	value := setting(t, secretNameVariable)
	if value == "" {
		t.Skipf("Set %s to a secret's resource name, in %s at the repository root or the environment, to run the Google Secret Manager cache integration tests.",
			secretNameVariable, settingsFile)
	}
	project, secretID, ok := parseSecretName(value)
	if !ok {
		t.Fatalf("%s is %q, which isn't a secret's resource name: projects/{project}/secrets/{secret}.", secretNameVariable, value)
	}
	return project, secretID
}

// parseSecretName splits projects/{project}/secrets/{secret}.
func parseSecretName(name string) (project, secretID string, ok bool) {
	secret, ok := secretOfVersion(name + "/versions/latest")
	if !ok || !IsValidSecretName(secret) {
		return "", "", false
	}
	project = name[len("projects/") : len(name)-len("/secrets/")-len(secret)]
	return project, secret, isProjectID(project)
}

// expected is the JSON object the secret holds, by member - each as Decrypt reveals it - and whole;
// it skips the test unless one is set.
func expected(t *testing.T) (members map[string]string, whole map[string]json.RawMessage) {
	t.Helper()
	value := setting(t, expectedJSONVariable)
	if value == "" {
		t.Skipf("Set %s and %s to check a secret's contents.", secretNameVariable, expectedJSONVariable)
	}
	if err := json.Unmarshal([]byte(value), &whole); err != nil {
		t.Fatalf("%s isn't a JSON object: %v", expectedJSONVariable, err)
	}
	members = map[string]string{}
	for key, raw := range whole {
		var s string
		if json.Unmarshal(raw, &s) == nil {
			members[key] = s
		} else if _, err := strconv.ParseFloat(string(raw), 64); err == nil || string(raw) == "true" || string(raw) == "false" {
			members[key] = string(raw)
		}
	}
	return members, whole
}

// integrationCache is a cache over the configured secret's project, through a client the test
// creates as an application would and closes when it ends; it skips the test when no secret is
// configured.
func integrationCache(t *testing.T) (*cache.RemoteCache, string) {
	t.Helper()
	project, secretID := configuredSecret(t)
	client, err := secretmanager.NewClient(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	c, err := New(client, project, newRing(t), Options{})
	if err != nil {
		t.Fatal(err)
	}
	return c, secretID
}

func TestGoogleSecretManagerIntegration_RevealsTheSecret(t *testing.T) {
	c, secretID := integrationCache(t)

	max, ok, err := c.MaxDecryptedLength(t.Context(), secretID)
	if err != nil || !ok || max <= 0 {
		t.Fatalf("%d, %v, %v", max, ok, err)
	}
	if n, err := c.Decrypt(t.Context(), secretID, make([]byte, max)); err != nil || n <= 0 {
		t.Fatalf("%d, %v", n, err)
	}
}

func TestGoogleSecretManagerIntegration_RevealsTheExpectedWholeValue_AndEveryKey(t *testing.T) {
	c, secretID := integrationCache(t)
	members, whole := expected(t)

	var got map[string]json.RawMessage
	if err := json.Unmarshal([]byte(decryptString(t, c, secretID)), &got); err != nil || len(got) != len(whole) {
		t.Fatalf("the whole value: %v, %d members; want %d", err, len(got), len(whole))
	}
	for key, raw := range whole {
		if !bytes.Equal(compact(t, got[key]), compact(t, raw)) {
			t.Errorf("the whole value's %q differs", key)
		}
	}
	for key, want := range members {
		if got := decryptString(t, c, secretID+"#"+key); got != want {
			t.Errorf("%s#%s differs", secretID, key)
		}
	}
	if got := decryptString(t, c, secretID+"#no-such-key"); got != "" {
		t.Error("a key the secret doesn't hold was revealed")
	}
}

func TestGoogleSecretManagerIntegration_ASecretThatDoesNotExist_IsZero(t *testing.T) {
	c, _ := integrationCache(t)
	random := make([]byte, 16)
	_, _ = rand.Read(random)

	if n, err := c.Decrypt(t.Context(), "hkdfguard-missing-"+hex.EncodeToString(random), make([]byte, 16)); n != 0 || err != nil {
		t.Fatalf("%d, %v; want 0 and no error", n, err)
	}
}

func compact(t *testing.T, raw json.RawMessage) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := json.Compact(&b, raw); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}
