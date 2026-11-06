package awssecretsmanager

import (
	"bytes"
	"context"
	"io"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/pipeline"
)

// captureMiddlewareID is the capture middleware's ID in the Deserialize step.
const captureMiddlewareID = "HkdfGuardPipelineSecretCapture"

// emptyObject is the body the SDK is handed in place of a captured one: nothing the writer needs is
// in the response.
var emptyObject = []byte("{}")

// captureMiddleware takes one GetSecretValue's secret out of the raw response body before the SDK
// parses it, encrypting it into secret. It belongs to one read - the secret is captured here, never
// shared - and runs on the goroutine that called GetSecretValue, as pipeline.Secret requires:
// smithy's handlers are synchronous.
type captureMiddleware struct {
	ctx    context.Context
	secret *pipeline.Secret
	ran    bool // a 2xx body was read: the output holds nothing the SDK could have parsed
}

// apply is the per-call optFn: it turns response-body logging off and adds the middleware at the
// innermost end of the Deserialize step. The SDK applies APIOptions after its own middleware, and
// this optFn after the client's options - the application's APIOptions included - so Add(After)
// puts it after every other Deserialize middleware: next is the HTTP client itself, and the
// RequestResponseLogger, the interceptors and OperationDeserializer all see the empty object.
func (m *captureMiddleware) apply(o *secretsmanager.Options) {
	o.ClientLogMode &^= aws.LogResponseWithBody
	o.APIOptions = append(o.APIOptions, func(stack *middleware.Stack) error {
		return stack.Deserialize.Add(m, middleware.After)
	})
}

func (*captureMiddleware) ID() string { return captureMiddlewareID }

func (m *captureMiddleware) HandleDeserialize(ctx context.Context, in middleware.DeserializeInput, next middleware.DeserializeHandler) (
	out middleware.DeserializeOutput, metadata middleware.Metadata, err error,
) {
	out, metadata, err = next.HandleDeserialize(ctx, in)
	if err != nil {
		return out, metadata, err
	}
	response, ok := out.RawResponse.(*smithyhttp.Response)
	if !ok || response.Response == nil || response.Body == nil || response.StatusCode < 200 || response.StatusCode > 299 {
		return out, metadata, err // an error answer: the SDK reads its code, which holds no secret
	}

	m.ran = true
	captureErr := m.capture(response.Body)
	_ = response.Body.Close()
	if captureErr != nil {
		response.Body = http.NoBody
		response.ContentLength = 0
		return out, metadata, captureErr
	}
	response.Body = io.NopCloser(bytes.NewReader(emptyObject))
	response.ContentLength = int64(len(emptyObject))
	return out, metadata, nil
}

// capture reads body into a buffer of its own and encrypts its SecretString, whole and by key,
// zeroing the buffer. Each attempt starts afresh: a retried one leaves nothing behind.
func (m *captureMiddleware) capture(body io.Reader) error {
	buffer, err := pipeline.ReadBody(body)
	if err != nil {
		return err
	}
	defer hkdfguard.Wipe(buffer)
	m.secret.Reset()
	return m.secret.ProtectBodyValue(m.ctx, buffer, "SecretString", "SecretBinary")
}
