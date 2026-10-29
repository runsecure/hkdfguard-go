package awssecretsmanager

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/smithy-go/logging"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/cache"
	"github.com/runsecure/hkdfguard-go/diagnostics"
)

// newCache is the cache over a real client against a fake Secrets Manager.
func newCache(t *testing.T, configure ...func(*secretsmanager.Options)) (*cache.RemoteCache, *fakeSecretsManager) {
	t.Helper()
	fake := newFakeSecretsManager(t)
	c, err := New(fake.client(configure...), newRing(t), Options{})
	if err != nil {
		t.Fatal(err)
	}
	return c, fake
}

// newRecordedCache is newCache, through a client recording every output the SDK returned.
func newRecordedCache(t *testing.T) (*cache.RemoteCache, *fakeSecretsManager, *recordingClient) {
	t.Helper()
	fake := newFakeSecretsManager(t)
	client := &recordingClient{Client: fake.client()}
	c, err := New(client, newRing(t), Options{})
	if err != nil {
		t.Fatal(err)
	}
	return c, fake, client
}

func missing(t *testing.T, c hkdfguard.ProtectedReadOnlyCache, name string) {
	t.Helper()
	if value, ok := get(t, c, name); ok {
		t.Fatalf("%q holds %q; want nothing", name, value)
	}
	if n, err := c.Decrypt(t.Context(), name, make([]byte, 16)); n != 0 || err != nil {
		t.Fatalf("Decrypt(%q) = %d, %v; want 0, nil", name, n, err)
	}
}

func wantGets(t *testing.T, fake *fakeSecretsManager, want ...string) {
	t.Helper()
	if got := fake.getNames(); !slices.Equal(got, want) {
		t.Fatalf("GetSecretValue was called for %q; want %q", got, want)
	}
}

// A key/value secret as AWS Secrets Manager's console stores one.
const keyValueSecret = `{
  "test-credential-1": "This is my first credential",
  "service-credential-3": "This is my third credential",
  "api-credential-21": "0k4sBPf0vQw6SDn6r7g4lMODn9bB5JrXyYVkvhFl3f0oM2xVhW3vXKz6u4Fuw2VwCs+6xXK8WaF9JUYg9l0L8Q==",
  "domain-credential-17": "fakedomain/thiscredential",
  "port": 5432
}`

func TestDecrypt_OnMiss_FetchesTheOneSecret_ThenServesItFromTheCache(t *testing.T) {
	c, fake := newCache(t)
	fake.setString("prod/Db-Password", "s3cret")

	for range 3 {
		if got := mustGet(t, c, "prod/Db-Password"); got != "s3cret" {
			t.Fatalf("got %q", got)
		}
	}
	wantGets(t, fake, "prod/Db-Password")
	if len(fake.unexpected) != 0 {
		t.Fatalf("unexpected operations: %q", fake.unexpected)
	}
}

func TestTheOutputTheSdkReturns_HoldsTheValueBlanked(t *testing.T) {
	c, fake, client := newRecordedCache(t)
	fake.setString("text", "s3cret")
	fake.setBinary("binary", []byte{1, 2, 3})

	if got := mustGet(t, c, "text"); got != "s3cret" {
		t.Fatalf("got %q", got)
	}
	if got := mustGet(t, c, "binary"); got != "\x01\x02\x03" {
		t.Fatalf("got %q", got)
	}

	if len(client.outputs) != 2 {
		t.Fatalf("%d outputs; want 2", len(client.outputs))
	}
	for _, out := range client.outputs {
		if aws.ToString(out.SecretString) != "" || len(out.SecretBinary) != 0 {
			t.Fatalf("the output holds the secret: %q, %v", aws.ToString(out.SecretString), out.SecretBinary)
		}
		if !strings.HasPrefix(aws.ToString(out.ARN), "arn:aws:secretsmanager:") {
			t.Fatalf("the rest of the output wasn't parsed: ARN %q", aws.ToString(out.ARN))
		}
	}
}

func TestAValueWithJSONEscapes_IsUnescapedExactly(t *testing.T) {
	c, fake := newCache(t)
	const secret = "p\"a\\ss/wörd\n\u0001秘密"
	fake.setString("escaped", secret)

	if got := mustGet(t, c, "escaped"); got != secret {
		t.Fatalf("got %q; want %q", got, secret)
	}
}

func TestABinarySecret_IsCachedAsItsBytes(t *testing.T) {
	c, fake := newCache(t)
	fake.setBinary("binary", []byte{0, 1, 254, 255})

	if got := mustGet(t, c, "binary"); got != "\x00\x01\xfe\xff" {
		t.Fatalf("got %q", got)
	}
}

func TestAKeyValueSecret_IsCachedWholeAndByKey_FromOneCall_AndTheSdkNeverSeesIt(t *testing.T) {
	c, fake, client := newRecordedCache(t)
	fake.setString("prod/App", keyValueSecret)

	for name, want := range map[string]string{
		"prod/App#api-credential-21":    "0k4sBPf0vQw6SDn6r7g4lMODn9bB5JrXyYVkvhFl3f0oM2xVhW3vXKz6u4Fuw2VwCs+6xXK8WaF9JUYg9l0L8Q==",
		"prod/App#test-credential-1":    "This is my first credential",
		"prod/App#service-credential-3": "This is my third credential",
		"prod/App#domain-credential-17": "fakedomain/thiscredential",
		"prod/App#port":                 "5432",
		"prod/App":                      keyValueSecret,
	} {
		if got := mustGet(t, c, name); got != want {
			t.Fatalf("%q holds %q; want %q", name, got, want)
		}
	}
	missing(t, c, "prod/app#port") // another secret

	wantGets(t, fake, "prod/App", "prod/app", "prod/app")
	if out := client.outputs[0]; aws.ToString(out.SecretString) != "" {
		t.Fatalf("the output holds the secret: %q", aws.ToString(out.SecretString))
	}
}

func TestABinarySecretHoldingJSON_IsNotSplit(t *testing.T) {
	c, fake := newCache(t)
	fake.setBinary("binary", []byte(`{"k":"v"}`))

	if got := mustGet(t, c, "binary"); got != `{"k":"v"}` {
		t.Fatalf("got %q", got)
	}
	missing(t, c, "binary#k")
}

func TestMaxDecryptedLength_OnMiss_FetchesTheSecret(t *testing.T) {
	c, fake := newCache(t)
	fake.setString("api-key", "value")

	n, ok, err := c.MaxDecryptedLength(t.Context(), "api-key")
	if err != nil || !ok || n < 5 {
		t.Fatalf("%d, %v, %v; want at least 5", n, ok, err)
	}
	if got := mustGet(t, c, "api-key"); got != "value" {
		t.Fatalf("got %q", got)
	}
	wantGets(t, fake, "api-key")
}

func TestNamesDifferingOnlyInCase_AreDifferentSecrets_AndDifferentEntries(t *testing.T) {
	c, fake := newCache(t)
	fake.setString("prod/Db", "upper")
	fake.setString("prod/db", "lower")

	if got := mustGet(t, c, "prod/Db"); got != "upper" {
		t.Fatalf("got %q", got)
	}
	if got := mustGet(t, c, "prod/db"); got != "lower" {
		t.Fatalf("got %q", got)
	}
	if n, err := c.Decrypt(t.Context(), "PROD/DB", make([]byte, 16)); n != 0 || err != nil {
		t.Fatalf("%d, %v; want 0, nil", n, err)
	}
	if got := mustGet(t, c, "prod/Db"); got != "upper" {
		t.Fatalf("got %q", got)
	}
	wantGets(t, fake, "prod/Db", "prod/db", "PROD/DB")
}

func TestAMissingSecret_IsReportedMissing_AndIsLookedUpAgainUntilItExists(t *testing.T) {
	c, fake := newCache(t)

	if n, err := c.Decrypt(t.Context(), "later", make([]byte, 16)); n != 0 || err != nil {
		t.Fatalf("%d, %v; want 0, nil", n, err)
	}
	if n, ok, err := c.MaxDecryptedLength(t.Context(), "later"); n != 0 || ok || err != nil {
		t.Fatalf("%d, %v, %v; want 0, false, nil", n, ok, err)
	}

	fake.setString("later", "now here")
	if got := mustGet(t, c, "later"); got != "now here" {
		t.Fatalf("got %q", got)
	}
	if got := len(fake.getNames()); got != 3 {
		t.Fatalf("%d calls; want 3", got)
	}
}

func TestAnEmptySecret_IsReportedMissing(t *testing.T) {
	c, fake := newCache(t)
	fake.setEmpty("none")
	fake.setString("empty-string", "")
	fake.setBinary("empty-binary", nil)

	for _, name := range []string{"none", "empty-string", "empty-binary"} {
		missing(t, c, name)
	}
}

func TestAResponseThatCantBeTrusted_IsRefused(t *testing.T) {
	for _, body := range []string{
		`{"SecretString":"a","SecretBinary":"Yg=="}`,
		`{"SecretBinary":"not base64!"}`,
		`{"SecretString":"{\"k\":1,\"k\":2}"}`,
		"not json",
	} {
		t.Run(body, func(t *testing.T) {
			c, fake := newCache(t)
			fake.rawBody = &body

			_, err := c.Decrypt(t.Context(), "item", make([]byte, 16))
			if !errors.Is(err, cache.ErrInvalidSecretData) {
				t.Fatalf("got %v; want cache.ErrInvalidSecretData", err)
			}
		})
	}
}

func TestANameSecretsManagerCantHold_IsMissing_WithoutCallingAws(t *testing.T) {
	for _, name := range []string{
		"", "ConnectionStrings:Admin", "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf",
		"has space", "café", "bang!", strings.Repeat("x", MaxSecretNameLength+1),
	} {
		t.Run(name, func(t *testing.T) {
			c, fake := newCache(t)
			missing(t, c, name)
			wantGets(t, fake)
		})
	}
}

func TestIsValidSecretName_AcceptsTheSecretsManagerCharacterSet_UpTo512(t *testing.T) {
	for name, want := range map[string]bool{
		"a":                                      true,
		"prod/app_1+x=y.z@w-v":                   true,
		"ABCxyz0189":                             true,
		strings.Repeat("x", MaxSecretNameLength): true,
		strings.Repeat("x", MaxSecretNameLength+1): false,
		"":        false,
		"a:b":     false,
		"a#b":     false,
		"a!b":     false,
		"a b":     false,
		"caf\xc3": false,
	} {
		if got := IsValidSecretName(name); got != want {
			t.Errorf("IsValidSecretName(%q) = %v; want %v", name, got, want)
		}
	}
}

func TestAnAwsFailure_Propagates_AndIsRetriedOnTheNextLookup(t *testing.T) {
	c, fake := newCache(t)
	fake.setString("item", "value")
	fake.fail(&awsError{"InvalidRequestException", 400}, 1)

	_, err := c.Decrypt(t.Context(), "item", make([]byte, 16))
	if invalid := (*types.InvalidRequestException)(nil); !errors.As(err, &invalid) {
		t.Fatalf("got %v; want a *types.InvalidRequestException", err)
	}

	if got := mustGet(t, c, "item"); got != "value" {
		t.Fatalf("got %q", got)
	}
	wantGets(t, fake, "item", "item")
}

func TestACancelledContext_Propagates(t *testing.T) {
	c, fake := newCache(t)
	fake.setString("item", "value")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if _, err := c.Decrypt(ctx, "item", make([]byte, 16)); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v; want context.Canceled", err)
	}
	if got := mustGet(t, c, "item"); got != "value" {
		t.Fatalf("got %q", got)
	}
}

func TestACredentialFailure_Propagates(t *testing.T) {
	failure := errors.New("unable to get IAM security credentials")
	c, fake := newCache(t, func(o *secretsmanager.Options) {
		o.Credentials = aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{}, failure
		})
	})

	if _, err := c.Decrypt(t.Context(), "item", make([]byte, 16)); !errors.Is(err, failure) {
		t.Fatalf("got %v; want the credential failure", err)
	}
	wantGets(t, fake)
}

func TestConcurrentMissesOnOneName_ShareOneFetch(t *testing.T) {
	c, fake := newCache(t)
	fake.setString("shared", "value")
	release := make(chan struct{})
	fake.onGet = func() { <-release }

	var wg sync.WaitGroup
	values := make([]string, 8)
	for i := range values {
		wg.Go(func() { values[i] = mustGet(t, c, "shared") })
	}
	time.Sleep(200 * time.Millisecond)
	close(release)
	wg.Wait()

	for _, v := range values {
		if v != "value" {
			t.Fatalf("got %q", v)
		}
	}
	wantGets(t, fake, "shared")
}

func TestALargeSecret_RoundTrips(t *testing.T) {
	c, fake := newCache(t)
	large := strings.Repeat("é-秘密-", 1500)
	fake.setString("large", large)

	if got := mustGet(t, c, "large"); got != large {
		t.Fatalf("got %d bytes; want %d", len(got), len(large))
	}
}

func TestACachedSecret_StillDecryptsAfterTheRingRotates(t *testing.T) {
	fake := newFakeSecretsManager(t)
	ring := newRing(t)
	c, err := New(fake.client(), ring, Options{})
	if err != nil {
		t.Fatal(err)
	}
	fake.setString("before", "v1 value")
	fake.setString("after", "v2 value")

	if got := mustGet(t, c, "before"); got != "v1 value" {
		t.Fatalf("got %q", got)
	}
	if err := ring.Add(t.Context(), 2, newTestKey(t)); err != nil {
		t.Fatal(err)
	}
	if got := mustGet(t, c, "after"); got != "v2 value" {
		t.Fatalf("got %q", got)
	}
	if got := mustGet(t, c, "before"); got != "v1 value" {
		t.Fatalf("got %q", got)
	}
}

func TestInACollection_OnlyNamesTheEarlierSourcesMiss_ReachAws(t *testing.T) {
	remote, fake := newCache(t)
	fake.setString("from-aws", "aws value")
	local := cache.New(newRing(t))
	if err := local.Add(t.Context(), "ConnectionStrings:Admin", []byte("local value")); err != nil {
		t.Fatal(err)
	}
	collection := cache.NewCollection(local, remote)

	if got := mustGet(t, collection, "ConnectionStrings:Admin"); got != "local value" {
		t.Fatalf("got %q", got)
	}
	if got := mustGet(t, collection, "from-aws"); got != "aws value" {
		t.Fatalf("got %q", got)
	}
	wantGets(t, fake, "from-aws")
}

func TestWithSensitiveLogging_AFetchLogsTheNameOnly_AndAFailureLogsAnError(t *testing.T) {
	logs := &logBuffer{}
	fake := newFakeSecretsManager(t)
	c, err := New(fake.client(), newRing(t), Options{Logger: slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))})
	if err != nil {
		t.Fatal(err)
	}
	fake.setString("prod/Item", "never-logged")

	original := diagnostics.Cache.SensitiveLoggingEnabled()
	diagnostics.Cache.SetSensitiveLogging(true)
	t.Cleanup(func() { diagnostics.Cache.SetSensitiveLogging(original) })

	if got := mustGet(t, c, "prod/Item"); got != "never-logged" {
		t.Fatalf("got %q", got)
	}
	fake.fail(&awsError{"InternalServiceError", 500}, 0)
	_, err = c.Decrypt(t.Context(), "other", make([]byte, 16))
	if internal := (*types.InternalServiceError)(nil); !errors.As(err, &internal) {
		t.Fatalf("got %v; want a *types.InternalServiceError", err)
	}

	text := logs.String()
	// The secret's own name, not its case-escaped entry name.
	if !strings.Contains(text, "level=DEBUG") || !strings.Contains(text, "prod/Item") {
		t.Fatalf("no debug record names the secret:\n%s", text)
	}
	if !strings.Contains(text, "level=ERROR") || !strings.Contains(text, "InternalServiceError") {
		t.Fatalf("no error record for the failure:\n%s", text)
	}
	if strings.Contains(text, "never-logged") {
		t.Fatalf("the value was logged:\n%s", text)
	}
}

func TestResponseBodyLogging_IsForcedOff_ForTheCachesCalls(t *testing.T) {
	logs := &logBuffer{}
	c, fake := newCache(t, func(o *secretsmanager.Options) {
		o.ClientLogMode = aws.LogRequestWithBody | aws.LogResponseWithBody | aws.LogResponse
		o.Logger = logging.LoggerFunc(func(_ logging.Classification, format string, v ...any) {
			fmt.Fprintf(logs, format+"\n", v...)
		})
	})
	fake.setString("prod/Logged", "never-logged")

	if got := mustGet(t, c, "prod/Logged"); got != "never-logged" {
		t.Fatalf("got %q", got)
	}

	text := logs.String()
	if !strings.Contains(text, "Response") || !strings.Contains(text, "200 OK") {
		t.Fatalf("the response's headers weren't logged:\n%s", text)
	}
	if strings.Contains(text, "never-logged") || strings.Contains(text, "arn:aws:secretsmanager") {
		t.Fatalf("the response's body was logged:\n%s", text)
	}
}

// bodyReader is an application's own Deserialize middleware that reads every response body.
type bodyReader struct{ bodies *[]string }

func (bodyReader) ID() string { return "ApplicationBodyReader" }

func (r bodyReader) HandleDeserialize(ctx context.Context, in middleware.DeserializeInput, next middleware.DeserializeHandler) (
	middleware.DeserializeOutput, middleware.Metadata, error,
) {
	out, md, err := next.HandleDeserialize(ctx, in)
	if response, ok := out.RawResponse.(*smithyhttp.Response); ok && response.Body != nil {
		body, _ := io.ReadAll(response.Body)
		*r.bodies = append(*r.bodies, string(body))
		response.Body = io.NopCloser(bytes.NewReader(body))
	}
	return out, md, err
}

func TestTheApplicationsOwnDeserializeMiddleware_SeesOnlyTheRedactedBody(t *testing.T) {
	var bodies []string
	c, fake := newCache(t, func(o *secretsmanager.Options) {
		o.APIOptions = append(o.APIOptions, func(stack *middleware.Stack) error {
			return stack.Deserialize.Add(bodyReader{&bodies}, middleware.After)
		})
	})
	fake.setString("prod/App", keyValueSecret)

	if got := mustGet(t, c, "prod/App#port"); got != "5432" {
		t.Fatalf("got %q", got)
	}
	if len(bodies) != 1 || !strings.Contains(bodies[0], `"SecretString":""`) || strings.Contains(bodies[0], "credential") {
		t.Fatalf("the application's middleware saw %q", bodies)
	}
}

func TestEachRetriedAttempt_RunsTheCapture(t *testing.T) {
	c, fake := newCache(t, func(o *secretsmanager.Options) {
		o.RetryMaxAttempts = 3
		o.Retryer = retry.NewStandard(func(s *retry.StandardOptions) {
			s.MaxAttempts = 3
			s.Backoff = retry.BackoffDelayerFunc(func(int, error) (time.Duration, error) { return 0, nil })
		})
	})
	fake.setString("item", "value")
	fake.fail(&awsError{"InternalServiceError", 500}, 1)

	if got := mustGet(t, c, "item"); got != "value" {
		t.Fatalf("got %q", got)
	}
	wantGets(t, fake, "item", "item")
}

// ignoringClient answers GetSecretValue itself, dropping the cache's optFns.
type ignoringClient struct {
	out *secretsmanager.GetSecretValueOutput
}

func (c ignoringClient) GetSecretValue(context.Context, *secretsmanager.GetSecretValueInput,
	...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	return c.out, nil
}

func TestAClientThatDropsTheCapture_IsRefused_AndItsBinaryValueZeroed(t *testing.T) {
	out := &secretsmanager.GetSecretValueOutput{SecretBinary: []byte{1, 2, 3}}
	c, err := New(ignoringClient{out}, newRing(t), Options{})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := c.Decrypt(t.Context(), "item", make([]byte, 16)); !errors.Is(err, ErrNotCaptured) {
		t.Fatalf("got %v; want ErrNotCaptured", err)
	}
	if !hkdfguard.IsZero(out.SecretBinary) {
		t.Fatalf("the binary value wasn't zeroed: %v", out.SecretBinary)
	}
}

func TestNew_RejectsANilClientOrRing(t *testing.T) {
	if _, err := New(nil, newRing(t), Options{}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("got %v; want ErrInvalidArgument", err)
	}
	if _, err := New(newFakeSecretsManager(t).client(), nil, Options{}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("got %v; want ErrInvalidArgument", err)
	}
}

func TestTheDefaults_MakeNoCallUntilASecretIsRequested(t *testing.T) {
	// No region, no credentials: both resolve on the first call, so none is needed for this.
	c, err := New(secretsmanager.NewFromConfig(aws.Config{}), newRing(t), Options{})
	if err != nil {
		t.Fatal(err)
	}
	missing(t, c, "not:a:secret")
}
