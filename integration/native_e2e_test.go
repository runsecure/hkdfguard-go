package integration

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/cache"
	"github.com/runsecure/hkdfguard-go/cryptoprovider/aesgcm256"
	"github.com/runsecure/hkdfguard-go/dek"
	"github.com/runsecure/hkdfguard-go/encryptedconfig"
	"github.com/runsecure/hkdfguard-go/keywrapping/nativev1"
)

// End to end over the real native KEK: the paths a deployment and a running application actually
// take, from a pipeline encrypting configuration through to the application reading it back, and
// the runtime keys a process generates for itself.

const keyFileVersion = 3

var ctx = context.Background()

type ringOptions struct {
	keyFile   string
	ephemeral []int
	refresh   time.Duration
}

// buildRing assembles a ring over the native KEK of service, exactly as an application does.
func buildRing(t *testing.T, service string, o ringOptions) (*dek.KeyRing, error) {
	t.Helper()
	wrapper, err := nativev1.New(service)
	if err != nil {
		t.Fatal(err)
	}
	return buildRingWith(t, wrapper, o)
}

// buildRingWith assembles a ring over wrapper's KEK.
func buildRingWith(t *testing.T, wrapper *nativev1.KeyWrapper, o ringOptions) (*dek.KeyRing, error) {
	t.Helper()
	config := dek.Config{
		KeyWrapper:            wrapper,
		CryptoProviderFactory: aesgcm256.NewFactory(),
		KeyRefreshInterval:    o.refresh,
		EphemeralKeys:         o.ephemeral,
	}
	if config.KeyRefreshInterval == 0 {
		config.KeyRefreshInterval = time.Minute
	}
	if o.keyFile != "" {
		config.KeyFiles = map[int]string{keyFileVersion: o.keyFile}
	}
	ring, err := dek.Build(ctx, config)
	if err == nil {
		t.Cleanup(func() { _ = ring.Close() })
	}
	return ring, err
}

func mustBuildRing(t *testing.T, service string, o ringOptions) *dek.KeyRing {
	t.Helper()
	ring, err := buildRing(t, service, o)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return ring
}

// runPipeline does what the release pipeline does: protects configuration under a fresh in-memory
// key, then hands that key to the native KEK and writes the wrapped result as the release's key
// file. It returns the key file's path and the configuration values.
func runPipeline(t *testing.T, service string, secrets map[string]string) (string, map[string]string) {
	t.Helper()
	wrapper, err := nativev1.New(service)
	if err != nil {
		t.Fatal(err)
	}
	return runPipelineWith(t, wrapper, "wrapped-dek-v3.bin", secrets)
}

// runPipelineWith protects secrets under a fresh in-memory key, wraps that key through wrapper, and
// writes the wrapped result to fileName in a key file directory. It returns the key file's path and
// the configuration values.
func runPipelineWith(t *testing.T, wrapper hkdfguard.KeyWrapper, fileName string, secrets map[string]string) (string, map[string]string) {
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

	path := filepath.Join(keyFileDirectory(t), fileName)
	if err := os.WriteFile(path, wrapped[:n], 0o600); err != nil {
		t.Fatal(err)
	}
	return path, values
}

func configReader(t *testing.T, ring *dek.KeyRing, values map[string]string) *encryptedconfig.Reader {
	t.Helper()
	lookup, err := encryptedconfig.NewMapLookup(values)
	if err != nil {
		t.Fatal(err)
	}
	return encryptedconfig.New(ring, lookup)
}

// reveal decrypts name from source, as an application does: size the buffer, then decrypt.
func reveal(t *testing.T, source hkdfguard.ProtectedReadOnlyCache, name string) (string, error) {
	t.Helper()
	max, ok, err := source.MaxDecryptedLength(ctx, name)
	if err != nil {
		return "", err
	}
	if !ok {
		t.Fatalf("%q is not stored", name)
	}
	result := make([]byte, max)
	n, err := source.Decrypt(ctx, name, result)
	if err != nil {
		return "", err
	}
	return string(result[:n]), nil
}

func mustReveal(t *testing.T, source hkdfguard.ProtectedReadOnlyCache, name string) string {
	t.Helper()
	value, err := reveal(t, source, name)
	if err != nil {
		t.Fatalf("revealing %q: %v", name, err)
	}
	return value
}

func protect(t *testing.T, protector hkdfguard.DataProtector, plaintext string) string {
	t.Helper()
	formatted, err := protector.Encrypt(ctx, []byte(plaintext))
	if err != nil {
		t.Fatal(err)
	}
	return formatted
}

func unprotect(t *testing.T, protector hkdfguard.DataProtector, formatted string) string {
	t.Helper()
	max, err := protector.MaxDecryptedLength(ctx, formatted)
	if err != nil {
		t.Fatal(err)
	}
	result := make([]byte, max)
	n, err := protector.Decrypt(ctx, formatted, result)
	if err != nil {
		t.Fatal(err)
	}
	return string(result[:n])
}

func TestADeployment_PipelineEncryptedConfiguration_DecryptsThroughItsNativelyWrappedKeyFile(t *testing.T) {
	service := testServiceName(t)
	keyFile, values := runPipeline(t, service, map[string]string{
		"ConnectionStrings:Admin": "Server=db;User=admin;Password=s3cret",
		"Api:Key":                 "k-0123456789abcdef",
	})

	ring := mustBuildRing(t, service, ringOptions{keyFile: keyFile})
	reader := configReader(t, ring, values)

	if got := mustReveal(t, reader, "ConnectionStrings:Admin"); got != "Server=db;User=admin;Password=s3cret" {
		t.Errorf("ConnectionStrings:Admin = %q", got)
	}
	if got := mustReveal(t, reader, "Api:Key"); got != "k-0123456789abcdef" {
		t.Errorf("Api:Key = %q", got)
	}
}

func TestADeployment_ValuesMovedToAnotherKey_FailAuthentication(t *testing.T) {
	service := testServiceName(t)
	keyFile, values := runPipeline(t, service, map[string]string{"ConnectionStrings:Admin": "admin-only", "ConnectionStrings:Reports": "reports"})
	values["ConnectionStrings:Reports"] = values["ConnectionStrings:Admin"] // an edited configuration file

	ring := mustBuildRing(t, service, ringOptions{keyFile: keyFile})
	_, err := reveal(t, configReader(t, ring, values), "ConnectionStrings:Reports")

	if !errors.Is(err, hkdfguard.ErrAuthenticationFailed) {
		t.Errorf("error = %v, want ErrAuthenticationFailed", err)
	}
}

func TestARestart_ReadingTheSameKeyFile_RevealsTheSameKey(t *testing.T) {
	service := testServiceName(t)
	keyFile, values := runPipeline(t, service, map[string]string{"Secret": "survives a restart"})

	first := mustBuildRing(t, service, ringOptions{keyFile: keyFile})
	if got := mustReveal(t, configReader(t, first, values), "Secret"); got != "survives a restart" {
		t.Fatalf("before the restart: %q", got)
	}
	_ = first.Close()

	second := mustBuildRing(t, service, ringOptions{keyFile: keyFile})
	if got := mustReveal(t, configReader(t, second, values), "Secret"); got != "survives a restart" {
		t.Errorf("after the restart: %q", got)
	}
}

func TestAKeyFile_WrappedUnderAnotherService_RefusesToBuild(t *testing.T) {
	service := testServiceName(t)
	keyFile, _ := runPipeline(t, service, map[string]string{"Secret": "value"})

	_, err := buildRing(t, otherServiceName(t), ringOptions{keyFile: keyFile})

	var statusErr *nativev1.StatusError
	if !errors.As(err, &statusErr) {
		t.Errorf("error = %v, want a native *StatusError", err)
	}
}

func TestATamperedKeyFile_RefusesToBuild(t *testing.T) {
	service := testServiceName(t)
	keyFile, _ := runPipeline(t, service, map[string]string{"Secret": "value"})
	wrapped, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	wrapped[len(wrapped)/2] ^= 0x01
	if err := os.WriteFile(keyFile, wrapped, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = buildRing(t, service, ringOptions{keyFile: keyFile})

	// Refused when the file is read (a changed header field) or when it is unwrapped (anything
	// else), either way by the native library.
	var statusErr *nativev1.StatusError
	var keyFileErr *nativev1.KeyFileError
	if !errors.As(err, &statusErr) && !errors.As(err, &keyFileErr) {
		t.Errorf("error = %v, want a native *StatusError or *KeyFileError", err)
	}
}

func TestAKeyFile_IsReadThroughTheNativeLibrary_StillWrapped(t *testing.T) {
	service := testServiceName(t)
	keyFile, values := runPipeline(t, service, map[string]string{"Secret": "read natively"})
	wrapper, err := nativev1.New(service)
	if err != nil {
		t.Fatal(err)
	}

	// What dek.Build does for each key file.
	read, err := wrapper.ReadKeyFile(ctx, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	onDisk, err := os.ReadFile(keyFile)
	if err != nil || !bytes.Equal(read, onDisk) {
		t.Fatalf("the native read differs from the file: %v", err)
	}

	ring := mustBuildRing(t, service, ringOptions{keyFile: keyFile})
	if version, err := ring.CurrentVersion(); err != nil || version != keyFileVersion {
		t.Errorf("CurrentVersion = %d, %v; want %d", version, err, keyFileVersion)
	}
	if got := mustReveal(t, configReader(t, ring, values), "Secret"); got != "read natively" {
		t.Errorf("revealed %q", got)
	}
}

func TestRuntimeKeys_GeneratedThroughTheNativeKEK_ProtectValuesAndTheCache(t *testing.T) {
	service := testServiceName(t)
	ring := mustBuildRing(t, service, ringOptions{ephemeral: []int{100}})

	protector, err := ring.CreateProtector("session")
	if err != nil {
		t.Fatal(err)
	}
	formatted := protect(t, protector, "runtime value")
	if !strings.HasPrefix(formatted, "enc::v100::") {
		t.Errorf("formatted = %q", formatted)
	}
	if got := unprotect(t, protector, formatted); got != "runtime value" {
		t.Errorf("decrypted = %q", got)
	}

	protected := cache.New(ring)
	if err := protected.Add(ctx, "token", bytes.Clone([]byte("cached secret"))); err != nil {
		t.Fatal(err)
	}
	if got := mustReveal(t, protected, "token"); got != "cached secret" {
		t.Errorf("cache token = %q", got)
	}
}

func TestADeployedAndARuntimeKey_TogetherInOneRing_EachDoTheirJob(t *testing.T) {
	service := testServiceName(t)
	keyFile, values := runPipeline(t, service, map[string]string{"Secret": "from the release"})

	ring := mustBuildRing(t, service, ringOptions{keyFile: keyFile, ephemeral: []int{100}})

	// Configuration decrypts under the release's key file; new values encrypt under the runtime key.
	if got := mustReveal(t, configReader(t, ring, values), "Secret"); got != "from the release" {
		t.Errorf("Secret = %q", got)
	}
	if current, err := ring.CurrentVersion(); err != nil || current != 100 {
		t.Errorf("CurrentVersion = %d, %v; want 100", current, err)
	}
	protector, err := ring.CreateProtector("new")
	if err != nil {
		t.Fatal(err)
	}
	if formatted := protect(t, protector, "value"); !strings.HasPrefix(formatted, "enc::v100::") {
		t.Errorf("a new value = %q, want version 100", formatted)
	}
}

func TestBackgroundRefresh_AgainstTheRealKEK_KeepsTheKeyInService(t *testing.T) {
	service := testServiceName(t)
	ring := mustBuildRing(t, service, ringOptions{ephemeral: []int{1}, refresh: time.Second})
	protector, err := ring.CreateProtector("refresh")
	if err != nil {
		t.Fatal(err)
	}
	before := protect(t, protector, "written before the refreshes")

	time.Sleep(2500 * time.Millisecond) // two background re-reveals through the native KEK

	if got := unprotect(t, protector, before); got != "written before the refreshes" {
		t.Errorf("before = %q", got)
	}
	if got := unprotect(t, protector, protect(t, protector, "written after")); got != "written after" {
		t.Errorf("after = %q", got)
	}
}
