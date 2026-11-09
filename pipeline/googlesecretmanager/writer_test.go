package googlesecretmanager

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/internal/gsmcheck"
	"github.com/runsecure/hkdfguard-go/pipeline"
	"github.com/runsecure/hkdfguard-go/pipeline/internal/pipelinetest"
)

// contractStore is the writer, with a real gRPC client and its scrubbing codec, against a fake
// Secret Manager served on the loopback address.
type contractStore struct {
	t    *testing.T
	fake *fakeSecretManager
}

func (c contractStore) NewWriter(protector hkdfguard.PipelineDataProtector, secretNames []string) (hkdfguard.SecretPipelineWriter, error) {
	return New(c.fake.client(c.t), testProjectID, protector, secretNames)
}
func (c contractStore) SetText(name, text string) { c.fake.setString(name, text) }
func (c contractStore) SetKeys(name, json string) { c.fake.setString(name, json) }
func (c contractStore) Reads() []string           { return c.fake.gets() }

func (c contractStore) FailReads() {
	c.fake.fail(status.Error(codes.PermissionDenied, "Denied in a test."))
}

func (c contractStore) IsReadFailure(err error) bool {
	return status.Code(err) == codes.PermissionDenied
}

// The writer's contract, with its real gRPC client against a fake Secret Manager.
func TestContract(t *testing.T) {
	pipelinetest.Contract(t, func(t *testing.T) pipelinetest.Store {
		return contractStore{t: t, fake: newFakeSecretManager().serve(t)}
	})
}

func newWriter(t *testing.T, client Client, protector hkdfguard.PipelineDataProtector, names ...string) *pipeline.Writer {
	t.Helper()
	w, err := New(client, testProjectID, protector, names)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// newStubbed is a writer through a stub client over a fresh fake.
func newStubbed(t *testing.T, names ...string) (*pipeline.Writer, *fakeSecretManager, *stubClient, hkdfguard.PipelineDataProtector) {
	t.Helper()
	fake := newFakeSecretManager()
	stub := &stubClient{fake: fake}
	protector := pipelinetest.NewProtector(t)
	return newWriter(t, stub, protector, names...), fake, stub, protector
}

func TestEachSecretsLatestVersion_IsRead_WithTheScrubbingCodec(t *testing.T) {
	w, fake, stub, _ := newStubbed(t, "api-key")
	fake.setString("api-key", "value")

	if err := w.PullSecrets(t.Context()); err != nil {
		t.Fatal(err)
	}

	if got := fake.accessed(); !slices.Equal(got, []string{"projects/hkdfguard-test/secrets/api-key/versions/latest"}) {
		t.Fatalf("accessed %q", got)
	}
	if len(stub.options) != 1 || len(stub.options[0]) != 1 {
		t.Fatalf("call options %v; want the codec's one", stub.options)
	}
}

func TestANameWithoutAKey_ReadsTheWholePayload(t *testing.T) {
	w, fake, _, protector := newStubbed(t, "db_login", "db_login#user")
	fake.setString("db_login", `{"user":"app"}`)

	if err := w.PullSecrets(t.Context()); err != nil {
		t.Fatal(err)
	}

	secrets := w.ProtectedSecrets()
	if got := pipelinetest.Decrypt(t, protector, secrets["db_login"], "db_login"); got != `{"user":"app"}` {
		t.Errorf("db_login is %q", got)
	}
	if got := pipelinetest.Decrypt(t, protector, secrets["db_login__user"], "db_login__user"); got != "app" {
		t.Errorf("db_login__user is %q", got)
	}
}

func requireZeroedPayloads(t *testing.T, stub *stubClient, want int) {
	t.Helper()
	payloads := stub.payloads()
	if len(payloads) != want {
		t.Fatalf("%d payloads; want %d", len(payloads), want)
	}
	for _, payload := range payloads {
		if !hkdfguard.IsZero(payload) {
			t.Fatalf("a payload wasn't zeroed: %q", payload)
		}
	}
}

func TestTheDecodedPayload_IsZeroed(t *testing.T) {
	w, fake, stub, _ := newStubbed(t, "item")
	fake.setString("item", "s3cret")

	if err := w.PullSecrets(t.Context()); err != nil {
		t.Fatal(err)
	}

	requireZeroedPayloads(t, stub, 1)
}

func TestAPayloadThatIsntUTF8Text_IsRefused_AndZeroed(t *testing.T) {
	w, fake, stub, _ := newStubbed(t, "binary")
	fake.set("binary", []byte{0xFF, 0xFE, 0x00, 0x80})

	if err := w.PullSecrets(t.Context()); !errors.Is(err, pipeline.ErrInvalidSecretData) {
		t.Fatalf("PullSecrets: %v; want pipeline.ErrInvalidSecretData", err)
	}

	if len(w.ProtectedSecrets()) != 0 {
		t.Fatal("something was kept")
	}
	requireZeroedPayloads(t, stub, 1)
}

func TestAPayloadNotMatchingItsChecksum_IsRefused_AndZeroed(t *testing.T) {
	w, fake, stub, _ := newStubbed(t, "item")
	fake.setString("item", "s3cret")
	fake.rewrite(func(r *secretmanagerpb.AccessSecretVersionResponse) { *r.Payload.DataCrc32C++ })

	if err := w.PullSecrets(t.Context()); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("PullSecrets: %v; want ErrInvalidResponse", err)
	}

	if len(w.ProtectedSecrets()) != 0 {
		t.Fatal("something was kept")
	}
	requireZeroedPayloads(t, stub, 1)
}

func TestAResponseForAnotherSecret_IsRefused(t *testing.T) {
	for _, name := range []string{"projects/123456789012/secrets/other/versions/1", "not a resource name"} {
		t.Run(name, func(t *testing.T) {
			w, fake, _, _ := newStubbed(t, "item")
			fake.setString("item", "s3cret")
			fake.rewrite(func(r *secretmanagerpb.AccessSecretVersionResponse) { r.Name = name })

			if err := w.PullSecrets(t.Context()); !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("PullSecrets: %v; want ErrInvalidResponse", err)
			}
		})
	}
}

func TestAResponseWithoutAPayload_HoldsNothing_AndOneWithoutAChecksum_IsAccepted(t *testing.T) {
	w, fake, _, protector := newStubbed(t, "none", "unchecked")
	fake.setString("none", "x")
	fake.setString("unchecked", "s3cret")
	fake.rewrite(func(r *secretmanagerpb.AccessSecretVersionResponse) {
		if strings.Contains(r.Name, "/none/") {
			r.Payload = nil
		} else {
			r.Payload.DataCrc32C = nil
		}
	})

	err := w.PullSecrets(t.Context())

	var missing *pipeline.MissingSecretsError
	if !errors.As(err, &missing) || !slices.Equal(missing.SecretNames, []string{"none"}) {
		t.Fatalf("PullSecrets: %v; want none missing", err)
	}
	if got := pipelinetest.Decrypt(t, protector, w.ProtectedSecrets()["unchecked"], "unchecked"); got != "s3cret" {
		t.Fatalf("unchecked is %q", got)
	}
}

func TestOverREST_TheWriterReadsAsOverGRPC(t *testing.T) {
	fake := newFakeSecretManager().serve(t)
	fake.setString("db-login", `{"password":"s3cret"}`)
	protector := pipelinetest.NewProtector(t)
	w := newWriter(t, fake.restClient(t), protector, "db-login#password", "absent")

	err := w.PullSecrets(t.Context())

	if !errors.Is(err, pipeline.ErrSecretNotFound) {
		t.Fatalf("PullSecrets: %v; want absent missing", err)
	}
	if got := pipelinetest.Decrypt(t, protector, w.ProtectedSecrets()["db-login__password"], "db-login__password"); got != "s3cret" {
		t.Fatalf("db-login__password is %q", got)
	}
}

func TestAnEndedContext_FailsThePull_MatchingItsError(t *testing.T) {
	fake := newFakeSecretManager().serve(t)
	fake.hangCalls()
	w := newWriter(t, fake.client(t), pipelinetest.NewProtector(t), "item")
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()

	if err := w.PullSecrets(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("PullSecrets: %v; want context.DeadlineExceeded", err)
	}
}

func TestAnIDSecretManagerCantHold_IsRefused(t *testing.T) {
	stub := &stubClient{fake: newFakeSecretManager()}
	protector := pipelinetest.NewProtector(t)
	for _, secretName := range []string{"prod/app", "db.login"} {
		_, err := New(stub, testProjectID, protector, []string{secretName})
		if !errors.Is(err, ErrInvalidArgument) || !errors.Is(err, pipeline.ErrInvalidArgument) {
			t.Errorf("%q: %v; want ErrInvalidArgument and pipeline.ErrInvalidArgument", secretName, err)
		}
	}
}

func TestIsValidSecretName_IsSecretManagersRule(t *testing.T) {
	for name, want := range map[string]bool{
		"db_login-2":                               true,
		strings.Repeat("a", MaxSecretNameLength):   true,
		strings.Repeat("a", MaxSecretNameLength+1): false,
		"": false,
	} {
		if got := IsValidSecretName(name); got != want {
			t.Errorf("IsValidSecretName(%.20q) = %v; want %v", name, got, want)
		}
	}
}

func TestNew_ChecksTheClientAndProject(t *testing.T) {
	stub := &stubClient{fake: newFakeSecretManager()}
	protector := pipelinetest.NewProtector(t)
	for name, create := range map[string]func() error{
		"no client":       func() error { _, err := New(nil, testProjectID, protector, []string{"item"}); return err },
		"no project":      func() error { _, err := New(stub, "", protector, []string{"item"}); return err },
		"a project path":  func() error { _, err := New(stub, "projects/x", protector, []string{"item"}); return err },
		"a project slash": func() error { _, err := New(stub, "bad/project", protector, []string{"item"}); return err },
	} {
		if err := create(); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("%s: %v; want ErrInvalidArgument", name, err)
		}
	}
}

func TestCRC32C_IsCastagnolis(t *testing.T) {
	if got := gsmcheck.CRC32C([]byte("123456789")); got != 0xE3069283 {
		t.Fatalf("crc32c = %#x; want 0xe3069283", got)
	}
}
