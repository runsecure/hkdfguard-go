package azurekeyvault

import (
	"bytes"
	"context"
	"io"
	"net/http"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/pipeline"
)

// captureKey is the context key under which ReadSecret passes its capture to capturePolicy.
type captureKey struct{}

// capture is one read's: the pipeline.Secret its value is encrypted into, and the read's context.
type capture struct {
	ctx    context.Context
	secret *pipeline.Secret
}

// emptyObject is the body the SDK is handed in place of a captured one: nothing the writer needs is
// in the response.
var emptyObject = []byte("{}")

// capturePolicy takes the secret out of a Get Secret response before azsecrets can turn it into a
// string. It acts only on a request whose context carries a capture (ReadSecret's): it stops azcore
// buffering that response, so a 200's body comes straight off the network into a buffer of the
// writer's own (pipeline.ReadBody), its value is encrypted - whole and by key - and the buffer
// zeroed, and the SDK is given an empty object in its place. Any other response to such a request -
// Key Vault's 401 challenge, an error - is buffered as azcore would have, for the SDK's error
// handling. Every other request passes through untouched.
//
// It is one of the client's per-retry policies, so it runs on every try, and azcore's
// body-download policy, which would otherwise read the whole body into a []byte nothing zeroes,
// runs below it - as does azcore's logging policy, which is why New refuses options that log
// bodies.
type capturePolicy struct{}

func (capturePolicy) Do(req *policy.Request) (*http.Response, error) {
	c, _ := req.Raw().Context().Value(captureKey{}).(*capture)
	if c == nil {
		return req.Next()
	}

	// The body-download policy downloads error bodies (status 400 and above) whatever this says.
	runtime.SkipBodyDownload(req)
	resp, err := req.Next()
	if err != nil || resp.Body == nil {
		return resp, err
	}
	if resp.StatusCode != http.StatusOK {
		if _, err := runtime.Payload(resp); err != nil {
			return resp, err
		}
		return resp, nil
	}

	body := resp.Body
	err = c.protect(body)
	_ = body.Close()
	if err != nil {
		// Not retried: a second try would read the same body.
		return nil, &captureError{err: err}
	}
	resp.Body = io.NopCloser(bytes.NewReader(emptyObject))
	resp.ContentLength = int64(len(emptyObject))
	return resp, nil
}

// protect reads body into a buffer of its own and encrypts its top-level value, zeroing the buffer.
// Each try starts afresh: a retried one leaves nothing behind.
func (c *capture) protect(body io.Reader) error {
	buffer, err := pipeline.ReadBody(body)
	if err != nil {
		return err
	}
	defer hkdfguard.Wipe(buffer)
	c.secret.Reset()
	return c.secret.ProtectBodyValue(c.ctx, buffer, "value", "")
}

// captureError is a failure to take the value out of a Get Secret response; azcore's retry policy
// doesn't retry it (it is errorinfo.NonRetriable), and ReadSecret returns the error it holds.
type captureError struct{ err error }

func (e *captureError) Error() string { return e.err.Error() }
func (e *captureError) Unwrap() error { return e.err }

// NonRetriable marks the error as one azcore's retry policy must not retry.
func (*captureError) NonRetriable() {}
