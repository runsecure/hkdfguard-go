package awssecretsmanager

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/logging"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/pipeline"
	"github.com/runsecure/hkdfguard-go/pipeline/internal/pipelinetest"
)

// contractStore is the writer, through a real client and its capture middleware, against a fake
// Secrets Manager endpoint.
type contractStore struct{ aws *fakeSecretsManager }

func (c contractStore) NewWriter(protector hkdfguard.PipelineDataProtector, secretNames []string) (hkdfguard.SecretPipelineWriter, error) {
	return New(c.aws.client(), protector, secretNames)
}
func (c contractStore) SetText(name, text string) { c.aws.setString(name, text) }
func (c contractStore) SetKeys(name, json string) { c.aws.setString(name, json) }
func (c contractStore) FailReads()                { c.aws.fail(&awsError{"AccessDeniedException", 400}, 0) }
func (c contractStore) Reads() []string           { return c.aws.getNames() }

func (c contractStore) IsReadFailure(err error) bool {
	var apiErr smithy.APIError
	return errors.As(err, &apiErr) && apiErr.ErrorCode() == "AccessDeniedException"
}

// The writer's contract, with its real client and capture middleware against a fake endpoint.
func TestContract(t *testing.T) {
	pipelinetest.Contract(t, func(t *testing.T) pipelinetest.Store { return contractStore{newFakeSecretsManager(t)} })
}

func newWriter(t *testing.T, client Client, protector hkdfguard.PipelineDataProtector, names ...string) *pipeline.Writer {
	t.Helper()
	w, err := New(client, protector, names)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func TestTheOutputTheSDKReturns_HoldsNothing(t *testing.T) {
	fake := newFakeSecretsManager(t)
	fake.setString("item", "s3cret")
	client := &recordingClient{Client: fake.client()}
	w := newWriter(t, client, pipelinetest.NewProtector(t), "item")

	if err := w.PullSecrets(t.Context()); err != nil {
		t.Fatal(err)
	}

	if len(client.outputs) != 1 {
		t.Fatalf("%d outputs; want 1", len(client.outputs))
	}
	if out := client.outputs[0]; out.SecretString != nil || out.SecretBinary != nil || out.ARN != nil || out.Name != nil {
		t.Fatalf("the SDK parsed more than an empty object: %+v", out)
	}
	if len(fake.unexpected) != 0 {
		t.Fatalf("unexpected operations: %q", fake.unexpected)
	}
}

func TestAnotherCallOnTheApplicationsClient_IsUntouched(t *testing.T) {
	fake := newFakeSecretsManager(t)
	fake.setString("item", "s3cret")
	client := fake.client()
	w := newWriter(t, client, pipelinetest.NewProtector(t), "item")
	if err := w.PullSecrets(t.Context()); err != nil {
		t.Fatal(err)
	}

	out, err := client.GetSecretValue(t.Context(), &secretsmanager.GetSecretValueInput{SecretId: aws.String("item")})

	if err != nil || aws.ToString(out.SecretString) != "s3cret" {
		t.Fatalf("GetSecretValue: %v, %q", err, aws.ToString(out.SecretString))
	}
}

func TestANameWithoutAKey_ReadsTheWholeSecretString(t *testing.T) {
	fake := newFakeSecretsManager(t)
	fake.setString("prod/app", `{"user":"app"}`)
	protector := pipelinetest.NewProtector(t)
	w := newWriter(t, fake.client(), protector, "prod/app", "prod/app#user")

	if err := w.PullSecrets(t.Context()); err != nil {
		t.Fatal(err)
	}

	secrets := w.ProtectedSecrets()
	if got := pipelinetest.Decrypt(t, protector, secrets["prod__app"], "prod__app"); got != `{"user":"app"}` {
		t.Errorf("prod__app is %q", got)
	}
	if got := pipelinetest.Decrypt(t, protector, secrets["prod__app__user"], "prod__app__user"); got != "app" {
		t.Errorf("prod__app__user is %q", got)
	}
	if got := fake.getNames(); !slices.Equal(got, []string{"prod/app"}) {
		t.Fatalf("read %q; want prod/app once", got)
	}
}

func TestAnEmptySecret_IsMissing(t *testing.T) {
	fake := newFakeSecretsManager(t)
	fake.setEmpty("empty")
	w := newWriter(t, fake.client(), pipelinetest.NewProtector(t), "empty")

	if err := w.PullSecrets(t.Context()); !errors.Is(err, pipeline.ErrSecretNotFound) {
		t.Fatalf("PullSecrets: %v; want pipeline.ErrSecretNotFound", err)
	}
}

func TestASecretBinary_IsRefused(t *testing.T) {
	fake := newFakeSecretsManager(t)
	fake.setBinary("binary", []byte{1, 2, 3})
	w := newWriter(t, fake.client(), pipelinetest.NewProtector(t), "binary")

	if err := w.PullSecrets(t.Context()); !errors.Is(err, pipeline.ErrInvalidSecretData) {
		t.Fatalf("PullSecrets: %v; want pipeline.ErrInvalidSecretData", err)
	}
	if len(w.ProtectedSecrets()) != 0 {
		t.Fatal("something was kept")
	}
}

func TestAResponseThatIsntSecretsManagersJSON_IsRefused(t *testing.T) {
	for _, body := range []string{`{"SecretString":"x" `, `["SecretString"]`, ``} {
		t.Run(body, func(t *testing.T) {
			fake := newFakeSecretsManager(t)
			fake.rawBody = &body
			w := newWriter(t, fake.client(), pipelinetest.NewProtector(t), "item")

			if err := w.PullSecrets(t.Context()); !errors.Is(err, pipeline.ErrInvalidSecretData) {
				t.Fatalf("PullSecrets: %v; want pipeline.ErrInvalidSecretData", err)
			}
			if len(w.ProtectedSecrets()) != 0 {
				t.Fatal("something was kept")
			}
		})
	}
}

func TestResponseBodyLogging_IsForcedOff_ForTheWritersCalls(t *testing.T) {
	var logs bytes.Buffer
	fake := newFakeSecretsManager(t)
	fake.setString("prod/Logged", "never-logged")
	client := fake.client(func(o *secretsmanager.Options) {
		o.ClientLogMode = aws.LogRequestWithBody | aws.LogResponseWithBody | aws.LogResponse
		o.Logger = logging.LoggerFunc(func(_ logging.Classification, format string, v ...any) {
			fmt.Fprintf(&logs, format+"\n", v...)
		})
	})
	w := newWriter(t, client, pipelinetest.NewProtector(t), "prod/Logged")

	if err := w.PullSecrets(t.Context()); err != nil {
		t.Fatal(err)
	}

	if text := logs.String(); !strings.Contains(text, "200 OK") || strings.Contains(text, "never-logged") {
		t.Fatalf("the response was logged with its body, or not at all:\n%s", text)
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

func TestTheApplicationsOwnDeserializeMiddleware_SeesOnlyAnEmptyObject(t *testing.T) {
	var bodies []string
	fake := newFakeSecretsManager(t)
	fake.setString("prod/App", `{"password":"s3cret"}`)
	client := fake.client(func(o *secretsmanager.Options) {
		o.APIOptions = append(o.APIOptions, func(stack *middleware.Stack) error {
			return stack.Deserialize.Add(bodyReader{&bodies}, middleware.After)
		})
	})
	w := newWriter(t, client, pipelinetest.NewProtector(t), "prod/App#password")

	if err := w.PullSecrets(t.Context()); err != nil {
		t.Fatal(err)
	}

	if !slices.Equal(bodies, []string{"{}"}) {
		t.Fatalf("the application's middleware saw %q", bodies)
	}
}

func TestEachRetriedAttempt_RunsTheCapture(t *testing.T) {
	fake := newFakeSecretsManager(t)
	fake.setString("item", "value")
	fake.fail(&awsError{"InternalServiceError", 500}, 1)
	client := fake.client(func(o *secretsmanager.Options) {
		o.RetryMaxAttempts = 3
		o.Retryer = retry.NewStandard(func(s *retry.StandardOptions) {
			s.MaxAttempts = 3
			s.Backoff = retry.BackoffDelayerFunc(func(int, error) (time.Duration, error) { return 0, nil })
		})
	})
	protector := pipelinetest.NewProtector(t)
	w := newWriter(t, client, protector, "item")

	if err := w.PullSecrets(t.Context()); err != nil {
		t.Fatal(err)
	}

	if got := pipelinetest.Decrypt(t, protector, w.ProtectedSecrets()["item"], "item"); got != "value" {
		t.Fatalf("item is %q", got)
	}
	if got := fake.getNames(); !slices.Equal(got, []string{"item", "item"}) {
		t.Fatalf("read %q; want item twice", got)
	}
}

// ignoringClient answers GetSecretValue itself, dropping the writer's optFns.
type ignoringClient struct {
	out *secretsmanager.GetSecretValueOutput
}

func (c ignoringClient) GetSecretValue(context.Context, *secretsmanager.GetSecretValueInput,
	...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	return c.out, nil
}

func TestAClientThatDropsTheCapture_IsRefused_AndItsBinaryValueZeroed(t *testing.T) {
	out := &secretsmanager.GetSecretValueOutput{SecretBinary: []byte{1, 2, 3}}
	w := newWriter(t, ignoringClient{out}, pipelinetest.NewProtector(t), "item")

	if err := w.PullSecrets(t.Context()); !errors.Is(err, ErrNotCaptured) {
		t.Fatalf("PullSecrets: %v; want ErrNotCaptured", err)
	}
	if !hkdfguard.IsZero(out.SecretBinary) {
		t.Fatalf("the binary value wasn't zeroed: %v", out.SecretBinary)
	}
}

func TestANameNoFileCanHave_IsRefused(t *testing.T) {
	client := newFakeSecretsManager(t).client()
	protector := pipelinetest.NewProtector(t)
	for _, secretName := range []string{"ConnectionStrings:Admin", "user@example", "a+b", "a=b", ".hidden",
		"arn:aws:secretsmanager:us-east-1:123456789012:secret:item-AbCdEf"} {
		_, err := New(client, protector, []string{secretName})
		if !errors.Is(err, ErrInvalidArgument) || !errors.Is(err, pipeline.ErrInvalidArgument) {
			t.Errorf("%q: %v; want ErrInvalidArgument and pipeline.ErrInvalidArgument", secretName, err)
		}
	}
}

func TestIsValidSecretName_IsSecretsManagersRule(t *testing.T) {
	for name, want := range map[string]bool{
		"prod/a_b+c=d.e@f-g":                       true,
		strings.Repeat("a", MaxSecretNameLength):   true,
		strings.Repeat("a", MaxSecretNameLength+1): false,
		"":    false,
		"a:b": false,
	} {
		if got := IsValidSecretName(name); got != want {
			t.Errorf("IsValidSecretName(%.20q) = %v; want %v", name, got, want)
		}
	}
}

func TestNew_RefusesANilClient(t *testing.T) {
	if _, err := New(nil, pipelinetest.NewProtector(t), []string{"item"}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("New: %v; want ErrInvalidArgument", err)
	}
}
