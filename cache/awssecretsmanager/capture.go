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

	"github.com/runsecure/hkdfguard-go/cache"
)

// captureMiddlewareID is the capture middleware's ID in the Deserialize step.
const captureMiddlewareID = "HkdfGuardSecretCapture"

// captureMiddleware takes one GetSecretValue's secret out of the raw response body before the SDK
// parses it, handing it to sink. It belongs to one fetch - the sink is captured here, never shared -
// and runs on the goroutine that called GetSecretValue, as the sink requires: smithy's handlers are
// synchronous.
type captureMiddleware struct {
	sink *cache.SecretSink
	ran  bool // a 2xx body was read: the output holds nothing the SDK could have parsed
}

// apply is the per-call optFn: it turns response-body logging off and adds the middleware at the
// innermost end of the Deserialize step. The SDK applies APIOptions after its own middleware, and
// this optFn after the client's options - the application's APIOptions included - so Add(After)
// puts it after every other Deserialize middleware: next is the HTTP client itself, and the
// RequestResponseLogger, the interceptors and OperationDeserializer all see the redacted body.
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
	redacted, captureErr := cache.CaptureJSONBody(response.Body, m.sink, nil, "SecretString", "SecretBinary")
	_ = response.Body.Close()
	if captureErr != nil {
		response.Body = http.NoBody
		response.ContentLength = 0
		return out, metadata, captureErr
	}
	response.Body = io.NopCloser(bytes.NewReader(redacted))
	response.ContentLength = int64(len(redacted))
	return out, metadata, nil
}
