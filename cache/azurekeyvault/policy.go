package azurekeyvault

import (
	"bytes"
	"io"
	"net/http"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"

	"github.com/runsecure/hkdfguard-go/cache"
)

// sinkKey is the context key under which Fetch passes its sink to capturePolicy.
type sinkKey struct{}

// capturePolicy takes the secret out of a Get Secret response before azsecrets can turn it into a
// string. It acts only on a request whose context carries a sink (Fetch's): it stops azcore
// buffering that response, so the body comes straight off the network into
// cache.CaptureJSONBody's own buffer, hands its top-level value to the sink, and gives the SDK the
// body with value blanked. Any other response to such a request - Key Vault's 401 challenge, an
// error - is buffered as azcore would have, for the SDK's error handling. Every other request
// passes through untouched.
//
// It is one of the client's per-retry policies, so it runs on every try, and azcore's
// body-download policy, which would otherwise read the whole body into a []byte nothing zeroes,
// runs below it - as does azcore's logging policy, which is why New refuses options that log
// bodies.
type capturePolicy struct{}

func (capturePolicy) Do(req *policy.Request) (*http.Response, error) {
	sink, _ := req.Raw().Context().Value(sinkKey{}).(*cache.SecretSink)
	if sink == nil {
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
	redacted, err := cache.CaptureJSONBody(body, sink, nil, "value", "")
	_ = body.Close()
	if err != nil {
		// Not retried: the sink may have taken part of the value, and a second try would only be
		// refused by it.
		return nil, &captureError{err: err}
	}
	resp.Body = io.NopCloser(bytes.NewReader(redacted))
	resp.ContentLength = int64(len(redacted))
	return resp, nil
}

// captureError is a failure to take the value out of a Get Secret response; azcore's retry policy
// doesn't retry it (it is errorinfo.NonRetriable), and Fetch returns the error it holds.
type captureError struct{ err error }

func (e *captureError) Error() string { return e.err.Error() }
func (e *captureError) Unwrap() error { return e.err }

// NonRetriable marks the error as one azcore's retry policy must not retry.
func (*captureError) NonRetriable() {}
