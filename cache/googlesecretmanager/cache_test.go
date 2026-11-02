package googlesecretmanager

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/googleapis/gax-go/v2"
	"github.com/googleapis/gax-go/v2/apierror"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/cache"
	"github.com/runsecure/hkdfguard-go/diagnostics"
)

// A key/value secret as AWS Secrets Manager's console stores one.
const keyValueSecret = `{
  "test-credential-1": "This is my first credential",
  "service-credential-3": "This is my third credential",
  "api-credential-21": "0k4sBPf0vQw6SDn6r7g4lMODn9bB5JrXyYVkvhFl3f0oM2xVhW3vXKz6u4Fuw2VwCs+6xXK8WaF9JUYg9l0L8Q==",
  "domain-credential-17": "fakedomain/thiscredential",
  "port": 5432
}`

func requireZeroed(t *testing.T, payloads [][]byte, count int) {
	t.Helper()
	if len(payloads) != count {
		t.Fatalf("%d payloads; want %d", len(payloads), count)
	}
	for _, payload := range payloads {
		if !hkdfguard.IsZero(payload) {
			t.Errorf("a payload wasn't zeroed: %q", payload)
		}
	}
}

func TestDecrypt_OnMiss_FetchesTheOneSecretsLatestVersion_ThenServesItFromTheCache(t *testing.T) {
	c, fake, _ := newCache(t)
	fake.setString("Db-Password", "s3cret")

	for range 2 {
		if got := decryptString(t, c, "Db-Password"); got != "s3cret" {
			t.Fatalf("got %q", got)
		}
	}
	if got := fake.accessed(); !slices.Equal(got, []string{"projects/hkdfguard-test/secrets/Db-Password/versions/latest"}) {
		t.Errorf("accesses %v", got)
	}
}

func TestThePayload_IsZeroedOnceEncrypted(t *testing.T) {
	c, fake, stub := newCache(t)
	fake.setString("item", "value")

	if got := decryptString(t, c, "item"); got != "value" {
		t.Fatalf("got %q", got)
	}
	requireZeroed(t, stub.payloads(), 1)
}

func TestEveryCall_CarriesTheReceiveBufferScrubber(t *testing.T) {
	c, fake, stub := newCache(t)
	fake.setString("item", "value")
	decryptString(t, c, "item")

	if len(stub.options) != 1 || len(stub.options[0]) != 1 {
		t.Fatalf("call options %v; want the one gRPC option", stub.options)
	}
}

func TestAJSONPayload_IsCachedWholeAndByKey_FromOneCall_AndIsZeroed(t *testing.T) {
	c, fake, stub := newCache(t)
	fake.setString("App-Credentials", keyValueSecret)

	for name, want := range map[string]string{
		"App-Credentials#api-credential-21":    "0k4sBPf0vQw6SDn6r7g4lMODn9bB5JrXyYVkvhFl3f0oM2xVhW3vXKz6u4Fuw2VwCs+6xXK8WaF9JUYg9l0L8Q==",
		"App-Credentials#service-credential-3": "This is my third credential",
		"App-Credentials#port":                 "5432",
		"App-Credentials":                      keyValueSecret,
	} {
		if got := decryptString(t, c, name); got != want {
			t.Errorf("%s: got %q; want %q", name, got, want)
		}
	}
	if got := decryptString(t, c, "App-Credentials#no-such-key"); got != "" {
		t.Errorf("a key the secret doesn't hold: got %q", got)
	}
	if got := fake.gets(); !slices.Equal(got[:1], []string{"App-Credentials"}) {
		t.Errorf("gets %v", got)
	}
	for _, payload := range stub.payloads() {
		if !hkdfguard.IsZero(payload) {
			t.Error("a payload wasn't zeroed")
		}
	}
}

func TestMaxDecryptedLength_OnMiss_FetchesTheSecret(t *testing.T) {
	c, fake, _ := newCache(t)
	fake.setString("api-key", "value")

	max, ok, err := c.MaxDecryptedLength(t.Context(), "api-key")
	if err != nil || !ok || max < 5 {
		t.Fatalf("%d, %v, %v", max, ok, err)
	}
	if got := decryptString(t, c, "api-key"); got != "value" {
		t.Fatalf("got %q", got)
	}
	if len(fake.accessed()) != 1 {
		t.Errorf("accesses %v", fake.accessed())
	}
}

func TestNamesDifferingOnlyInCase_AreDifferentSecrets_AndDifferentEntries(t *testing.T) {
	c, fake, _ := newCache(t)
	fake.setString("Db", "upper")
	fake.setString("db", "lower")

	for _, step := range []struct{ name, want string }{{"Db", "upper"}, {"db", "lower"}, {"DB", ""}, {"Db", "upper"}} {
		if got := decryptString(t, c, step.name); got != step.want {
			t.Errorf("%s: got %q; want %q", step.name, got, step.want)
		}
	}
	if got := fake.gets(); !slices.Equal(got, []string{"Db", "db", "DB"}) {
		t.Errorf("gets %v", got)
	}
}

func TestAMissingSecret_ReturnsZero_AndIsLookedUpAgainUntilItExists(t *testing.T) {
	c, fake, _ := newCache(t)

	if got := decryptString(t, c, "later"); got != "" {
		t.Fatalf("got %q", got)
	}
	if max, ok, err := c.MaxDecryptedLength(t.Context(), "later"); err != nil || ok || max != 0 {
		t.Fatalf("%d, %v, %v", max, ok, err)
	}
	fake.setString("later", "now here")
	if got := decryptString(t, c, "later"); got != "now here" {
		t.Fatalf("got %q", got)
	}
	if len(fake.accessed()) != 3 {
		t.Errorf("accesses %v", fake.accessed())
	}
}

func TestAnEmptyOrAbsentPayload_IsReportedMissing(t *testing.T) {
	c, fake, _ := newCache(t)
	fake.set("empty", nil)
	if got := decryptString(t, c, "empty"); got != "" {
		t.Errorf("empty: got %q", got)
	}

	fake.rewrite(func(response *secretmanagerpb.AccessSecretVersionResponse) { response.Payload = nil })
	fake.setString("no-payload", "value")
	if got := decryptString(t, c, "no-payload"); got != "" {
		t.Errorf("no payload: got %q", got)
	}
}

func TestABinarySecret_IsCachedAsItsBytes(t *testing.T) {
	c, fake, _ := newCache(t)
	fake.set("binary", []byte{0, 1, 254, 255})

	if got := decryptString(t, c, "binary"); got != "\x00\x01\xfe\xff" {
		t.Errorf("got %q", got)
	}
}

func TestAPayloadWithoutAChecksum_IsAccepted(t *testing.T) {
	c, fake, _ := newCache(t)
	fake.setString("item", "value")
	fake.rewrite(func(response *secretmanagerpb.AccessSecretVersionResponse) { response.Payload.DataCrc32C = nil })

	if got := decryptString(t, c, "item"); got != "value" {
		t.Errorf("got %q", got)
	}
}

func TestAPayloadThatDoesNotMatchItsChecksum_IsRefused_AndZeroed(t *testing.T) {
	c, fake, stub := newCache(t)
	fake.setString("item", "value")
	fake.rewrite(func(response *secretmanagerpb.AccessSecretVersionResponse) { *response.Payload.DataCrc32C ^= 1 })

	_, err := c.Decrypt(t.Context(), "item", make([]byte, 16))
	if !errors.Is(err, ErrInvalidResponse) || !strings.Contains(err.Error(), "CRC32C") {
		t.Fatalf("got %v; want ErrInvalidResponse", err)
	}
	requireZeroed(t, stub.payloads(), 1)

	// Nothing was cached: the next lookup fetches again.
	fake.rewrite(nil)
	if got := decryptString(t, c, "item"); got != "value" {
		t.Errorf("got %q", got)
	}
}

func TestAResponseForAnotherSecret_IsRefused_AndZeroed(t *testing.T) {
	for _, reported := range []string{
		"projects/123456789012/secrets/other/versions/1",
		"projects/123456789012/secrets/item",
		"projects/123456789012/secrets/item/versions/",
		"not a resource name",
		"",
	} {
		t.Run(reported, func(t *testing.T) {
			c, fake, stub := newCache(t)
			fake.setString("item", "value")
			fake.rewrite(func(response *secretmanagerpb.AccessSecretVersionResponse) { response.Name = reported })

			if _, err := c.Decrypt(t.Context(), "item", make([]byte, 16)); !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("got %v; want ErrInvalidResponse", err)
			}
			requireZeroed(t, stub.payloads(), 1)
		})
	}
}

func TestANilResponse_IsRefused(t *testing.T) {
	c, err := New(clientFunc(func(context.Context, *secretmanagerpb.AccessSecretVersionRequest) (*secretmanagerpb.AccessSecretVersionResponse, error) {
		return nil, nil
	}), testProjectID, newRing(t), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Decrypt(t.Context(), "item", make([]byte, 16)); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("got %v; want ErrInvalidResponse", err)
	}
}

func TestANameSecretManagerCantHold_IsMissing_WithoutCallingGoogle(t *testing.T) {
	c, fake, _ := newCache(t)
	for _, name := range []string{"", "ConnectionStrings:Admin", "prod/db", "db.password", "has space", "café", "bang!",
		"a!b", strings.Repeat("x", MaxSecretNameLength+1), "item#", "item#has space"} {
		if n, err := c.Decrypt(t.Context(), name, make([]byte, 16)); n != 0 || err != nil {
			t.Errorf("%q: %d, %v", name, n, err)
		}
		if max, ok, err := c.MaxDecryptedLength(t.Context(), name); max != 0 || ok || err != nil {
			t.Errorf("%q: %d, %v, %v", name, max, ok, err)
		}
	}
	if got := fake.accessed(); len(got) != 0 {
		t.Errorf("accesses %v", got)
	}
}

func TestIsValidSecretName_AcceptsLettersDigitsHyphensAndUnderscores_UpTo255(t *testing.T) {
	for name, want := range map[string]bool{
		"a":                                      true,
		"Db_Password-2":                          true,
		strings.Repeat("x", MaxSecretNameLength): true,
		strings.Repeat("x", MaxSecretNameLength+1): false,
		"":            false,
		"db.password": false,
		"prod/db":     false,
		"café":        false,
	} {
		if got := IsValidSecretName(name); got != want {
			t.Errorf("IsValidSecretName(%q) = %v", name, got)
		}
	}
}

func TestAGoogleFailure_Propagates_AndIsRetriedOnTheNextLookup(t *testing.T) {
	// FAILED_PRECONDITION: the latest version is disabled or destroyed.
	for _, code := range []codes.Code{codes.PermissionDenied, codes.FailedPrecondition, codes.Internal} {
		t.Run(code.String(), func(t *testing.T) {
			c, fake, _ := newCache(t)
			fake.setString("item", "value")
			fake.fail(status.Error(code, "refused"))

			_, err := c.Decrypt(t.Context(), "item", make([]byte, 16))
			if status.Code(err) != code || !strings.Contains(err.Error(), "'item'") {
				t.Fatalf("got %v; want %v", err, code)
			}
			fake.fail(nil)
			if got := decryptString(t, c, "item"); got != "value" {
				t.Fatalf("got %q", got)
			}
			if len(fake.accessed()) != 2 {
				t.Errorf("accesses %v", fake.accessed())
			}
		})
	}
}

func TestAFailureOtherThanAStatus_Propagates(t *testing.T) {
	cause := errors.New("no credentials")
	c, err := New(clientFunc(func(context.Context, *secretmanagerpb.AccessSecretVersionRequest) (*secretmanagerpb.AccessSecretVersionResponse, error) {
		return nil, cause
	}), testProjectID, newRing(t), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Decrypt(t.Context(), "item", make([]byte, 16)); !errors.Is(err, cause) {
		t.Fatalf("got %v; want the cause", err)
	}
}

func TestAnEndedContext_FailsMatchingTheContextsError(t *testing.T) {
	c, fake, _ := newCache(t)
	fake.setString("item", "value")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := c.Decrypt(ctx, "item", make([]byte, 16))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v; want context.Canceled", err)
	}
}

func TestConcurrentMissesOnOneName_ShareOneFetch(t *testing.T) {
	c, fake, _ := newCache(t)
	fake.setString("shared", "value")
	release := make(chan struct{})
	fake.whileGetting(func() {
		select {
		case <-release:
		case <-time.After(10 * time.Second):
		}
	})

	var wg sync.WaitGroup
	results := make([]string, 8)
	for i := range results {
		wg.Go(func() { results[i] = decryptString(t, c, "shared") })
	}
	time.Sleep(200 * time.Millisecond)
	close(release)
	wg.Wait()

	for _, got := range results {
		if got != "value" {
			t.Errorf("got %q", got)
		}
	}
	if len(fake.accessed()) != 1 {
		t.Errorf("accesses %v", fake.accessed())
	}
}

func TestALargeSecret_RoundTrips(t *testing.T) {
	c, fake, _ := newCache(t)
	large := strings.Repeat("é-秘密-", 1500)
	fake.setString("large", large)

	if got := decryptString(t, c, "large"); got != large {
		t.Errorf("got %d bytes; want %d", len(got), len(large))
	}
}

func TestInACollection_OnlyNamesTheEarlierSourcesMiss_ReachGoogle(t *testing.T) {
	googleCache, fake, _ := newCache(t)
	fake.setString("from-google", "google value")
	local := cache.New(newRing(t))
	if err := local.Add(t.Context(), "ConnectionStrings:Admin", []byte("local value")); err != nil {
		t.Fatal(err)
	}
	collection := cache.NewCollection(local, googleCache)

	if got := decryptString(t, collection, "ConnectionStrings:Admin"); got != "local value" {
		t.Errorf("got %q", got)
	}
	if got := decryptString(t, collection, "from-google"); got != "google value" {
		t.Errorf("got %q", got)
	}
	if got := fake.gets(); !slices.Equal(got, []string{"from-google"}) {
		t.Errorf("gets %v", got)
	}
}

// recordingHandler is a slog.Handler that keeps every record.
type recordingHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r.Clone())
	return nil
}
func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler      { return h }

// text is every record's message and attributes, one record per line.
func (h *recordingHandler) text(level slog.Level) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var b strings.Builder
	for _, r := range h.records {
		if r.Level != level {
			continue
		}
		b.WriteString(r.Message)
		r.Attrs(func(a slog.Attr) bool {
			b.WriteString(" " + a.String())
			return true
		})
		b.WriteString("\n")
	}
	return b.String()
}

func TestWithSensitiveLogging_AFetchLogsTheNameOnly_AndAFailureLogsAnError(t *testing.T) {
	fake := newFakeSecretManager()
	fake.setString("Item", "never-logged")
	handler := &recordingHandler{}
	c := newCacheOver(t, &stubClient{fake: fake}, Options{Logger: slog.New(handler)})

	original := diagnostics.Cache.SensitiveLoggingEnabled()
	diagnostics.Cache.SetSensitiveLogging(true)
	t.Cleanup(func() { diagnostics.Cache.SetSensitiveLogging(original) })

	if got := decryptString(t, c, "Item"); got != "never-logged" {
		t.Fatalf("got %q", got)
	}
	fake.fail(status.Error(codes.Internal, "boom"))
	if _, err := c.Decrypt(t.Context(), "other", make([]byte, 16)); status.Code(err) != codes.Internal {
		t.Fatalf("got %v", err)
	}

	// The secret's own name, not its escaped entry name.
	if debug := handler.text(slog.LevelDebug); !strings.Contains(debug, "Item") {
		t.Errorf("debug records %q; want the name", debug)
	}
	if errs := handler.text(slog.LevelError); !strings.Contains(errs, "boom") {
		t.Errorf("error records %q; want the failure", errs)
	}
	if all := handler.text(slog.LevelDebug) + handler.text(slog.LevelError) + handler.text(slog.LevelInfo); strings.Contains(all, "never-logged") {
		t.Error("the value was logged")
	}
}

func TestNew_RejectsMissingArguments_AndProjectIDsThatCouldChangeTheResourcePath(t *testing.T) {
	ring := newRing(t)
	stub := &stubClient{fake: newFakeSecretManager()}

	for _, tc := range []struct {
		name    string
		client  Client
		project string
		ring    hkdfguard.KeyRing
	}{
		{"no client", nil, "p", ring},
		{"no ring", stub, "p", nil},
		{"empty project", stub, "", ring},
		{"a path", stub, "p/secrets/other", ring},
		{"a space", stub, "my project", ring},
		{"not ASCII", stub, "projét", ring},
	} {
		if _, err := New(tc.client, tc.project, tc.ring, Options{}); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("%s: got %v; want ErrInvalidArgument", tc.name, err)
		}
	}

	// A project number, and a legacy domain-scoped ID, are both fine.
	for _, project := range []string{"123456789012", "example.com:my-project", "my-project"} {
		if _, err := New(stub, project, ring, Options{}); err != nil {
			t.Errorf("%s: %v", project, err)
		}
	}
}

func TestCRC32C_MatchesTheCastagnoliCheckValue(t *testing.T) {
	if got := crc32c([]byte("123456789")); got != 0xE3069283 {
		t.Errorf("got %#x", got)
	}
}

// Through the real client, over gRPC and REST, against the fake service.

func TestOverTheRealClient_ASecretRoundTrips_AMissingOneIsZero_AndAFailurePropagates(t *testing.T) {
	fake := newFakeSecretManager().serve(t)
	for transport, client := range map[string]Client{"gRPC": fake.client(t), "REST": fake.restClient(t)} {
		t.Run(transport, func(t *testing.T) {
			c := newCacheOver(t, client, Options{})
			fake.setString("App-Credentials", keyValueSecret)

			if got := decryptString(t, c, "App-Credentials#service-credential-3"); got != "This is my third credential" {
				t.Errorf("got %q", got)
			}
			if got := decryptString(t, c, "App-Credentials"); got != keyValueSecret {
				t.Errorf("got %q", got)
			}
			if got := decryptString(t, c, "Missing"); got != "" {
				t.Errorf("missing: got %q", got)
			}

			fake.fail(status.Error(codes.PermissionDenied, "Denied in a test."))
			defer fake.fail(nil)
			_, err := c.Decrypt(t.Context(), "item", make([]byte, 16))
			var apiErr *apierror.APIError
			if !errors.As(err, &apiErr) || status.Code(err) != codes.PermissionDenied {
				t.Fatalf("got %v (%T); want a PERMISSION_DENIED *apierror.APIError", err, errors.Unwrap(err))
			}
		})
	}
}

func TestOverTheRealClient_AResponseForAnotherSecret_IsRefused(t *testing.T) {
	fake := newFakeSecretManager().serve(t)
	c := newCacheOver(t, fake.client(t), Options{})
	fake.setString("item", "value")
	fake.rewrite(func(response *secretmanagerpb.AccessSecretVersionResponse) {
		response.Name = "projects/123456789012/secrets/other/versions/1"
	})

	if _, err := c.Decrypt(t.Context(), "item", make([]byte, 16)); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("got %v; want ErrInvalidResponse", err)
	}
}

func TestOverTheRealClient_AnEndedContext_FailsMatchingTheContextsError(t *testing.T) {
	fake := newFakeSecretManager().serve(t)
	fake.hangCalls()
	c := newCacheOver(t, fake.client(t), Options{})

	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	_, err := c.Decrypt(ctx, "item", make([]byte, 16))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v; want context.DeadlineExceeded", err)
	}
}

// clientFunc is a Client answering with a function.
type clientFunc func(context.Context, *secretmanagerpb.AccessSecretVersionRequest) (*secretmanagerpb.AccessSecretVersionResponse, error)

func (f clientFunc) AccessSecretVersion(ctx context.Context, request *secretmanagerpb.AccessSecretVersionRequest,
	_ ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	return f(ctx, request)
}
