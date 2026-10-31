package hashicorpvault

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/hashicorp/vault/api"

	"github.com/runsecure/hkdfguard-go"
)

// errRedirectRefused stops *api.Client following a redirect: refuseRedirect's MarshalJSON fails
// with it.
var errRedirectRefused = errors.New("a redirect isn't followed")

// refuseRedirect is a request's Obj when redirects aren't followed. *api.Client follows one 301,
// 302 or 307 itself unless its Config.DisableRedirects is set - which a client doesn't expose - and
// before resending re-encodes the body from Obj (Request.ResetJSONBody). Failing that encoding stops
// the redirect before anything, the token included, is sent where it points.
type refuseRedirect struct{}

func (refuseRedirect) MarshalJSON() ([]byte, error) { return nil, errRedirectRefused }

// resendBody is a request's Obj when Options.AllowRedirects is set: the body itself, so a redirect
// *api.Client follows resends it. encoding/json copies it - into a pooled buffer of its own, which
// can't be zeroed, and into the new body, which is.
type resendBody []byte

func (b resendBody) MarshalJSON() ([]byte, error) { return b, nil }

// post sends body to Vault at path - "/v1/..." - through the client, and returns Vault's successful
// answer, read off the network into a buffer of the wrapper's own, which the caller zeroes. body is
// the caller's: the client sends it as it is (vault/api, and go-retryablehttp under it, read a
// []byte body through a bytes.Reader on each attempt, without copying it), so it can be zeroed once
// this returns.
//
// The client's retries and timeout apply, and its namespace, token and headers are sent. Vault's
// refusals, an answer that isn't 2xx, and failures to reach Vault become an *Error; a call whose ctx
// ended, an error matching ctx's.
func (w *KeyWrapper) post(ctx context.Context, op, path string, body []byte) ([]byte, error) {
	// Either would have the client return the request - DEK and all - as an error rather than send
	// it, keeping it in a package variable (api.LastOutputStringError, api.LastOutputPolicyError).
	if w.client.OutputCurlString() || w.client.OutputPolicy() {
		return nil, invalidArgument("The Vault client is set to output a curl command or policy instead of sending requests.")
	}

	request := w.client.NewRequest(http.MethodPost, path)
	// Checked on every call, not only by New: the client can be pointed elsewhere (SetAddress), and
	// its SRV lookup can choose another host.
	if err := checkURL(request.URL); err != nil {
		return nil, err
	}
	if request.Headers == nil {
		request.Headers = http.Header{}
	}
	request.Headers.Set("Content-Type", "application/json")
	request.BodyBytes = body
	if w.allowRedirects {
		request.Obj = resendBody(body)
	} else {
		request.Obj = refuseRedirect{}
	}
	defer func() {
		// A redirect the client followed re-encoded the body into a slice of its own.
		if len(request.BodyBytes) > 0 && (len(body) == 0 || &request.BodyBytes[0] != &body[0]) {
			hkdfguard.Wipe(request.BodyBytes)
		}
	}()

	// Ends the client's own timeout context too, once the answer has been read: RawRequestWithContext
	// leaves it to expire.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// RawRequestWithContext, not Logical(): Write JSON-encodes a map, which would turn the DEK into a
	// Go string; WriteRawWithContext ends its context when it returns, before the answer can be read.
	//lint:ignore SA1019 the one call that sends a []byte body as it is and leaves the answer readable
	response, err := w.client.RawRequestWithContext(ctx, request)
	if response != nil && response.Body != nil {
		defer response.Body.Close()
	}
	if err != nil {
		return nil, w.classify(ctx, op, response, err)
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		// The client returns 3xx as success: a redirect DisableRedirects kept it from following,
		// or one it doesn't follow (308).
		return nil, w.notFollowed(op, response)
	}

	// One byte over the limit, so an answer that doesn't fit is noticed rather than truncated.
	answer := make([]byte, maxResponseLength+1)
	n, err := io.ReadFull(response.Body, answer)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		hkdfguard.Wipe(answer)
		return nil, w.classify(ctx, op, nil, err)
	}
	if n > maxResponseLength {
		hkdfguard.Wipe(answer)
		return nil, w.vaultError(op, nil, "Vault's answer for key '%s' is over %d bytes; a transit answer is far smaller.", w.keyName, maxResponseLength)
	}
	return answer[:n], nil
}

// classify turns the client's failures into the *Error every operation fails with: a refusal -
// an *api.ResponseError - names the HTTP status and Vault's errors; the client's own timeout says
// so; anything else (a refused connection, retries spent) gives its message. When ctx itself has
// ended, the failure matches ctx's error.
func (w *KeyWrapper) classify(ctx context.Context, op string, response *api.Response, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		if errors.Is(err, ctxErr) {
			return err
		}
		return &contextError{ctxErr: ctxErr, err: err}
	}
	if errors.Is(err, errRedirectRefused) && response != nil {
		return w.notFollowed(op, response)
	}
	var refusal *api.ResponseError
	if errors.As(err, &refusal) {
		detail := ""
		// A body that isn't Vault's JSON - a proxy's error page - isn't Vault's errors.
		if !refusal.RawError && len(refusal.Errors) > 0 {
			detail = ": " + strings.Join(refusal.Errors, "; ")
		}
		return w.vaultError(op, err, "Vault transit %s failed for key '%s': Vault answered %s%s", op, w.keyName, status(refusal.StatusCode), detail)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return w.vaultError(op, err, "Vault transit %s failed for key '%s': no answer within the client's timeout (%v)", op, w.keyName, w.client.ClientTimeout())
	}
	return w.vaultError(op, err, "Vault transit %s failed for key '%s': %v", op, w.keyName, err)
}

// notFollowed reports an answer that isn't a 2xx and isn't a refusal: a redirect, not followed.
func (w *KeyWrapper) notFollowed(op string, response *api.Response) error {
	where := ""
	if location := response.Header.Get("Location"); location != "" {
		where = " to " + location
	}
	return w.vaultError(op, nil, "Vault transit %s failed for key '%s': Vault answered %s, a redirect%s, which isn't followed: "+
		"it would carry the Vault token there. Set Options.AllowRedirects if every redirect target may see the token.",
		op, w.keyName, status(response.StatusCode), where)
}

func status(code int) string {
	if text := http.StatusText(code); text != "" {
		return fmt.Sprintf("%d %s", code, text)
	}
	return fmt.Sprint(code)
}

// checkAddress refuses a Vault address - as api.Client.Address returns it - that would send tokens
// and DEKs in the clear, or that carries credentials, a query or a fragment.
func checkAddress(address string) error {
	u, err := url.Parse(address)
	if err != nil {
		return invalidArgument("The Vault client's address %q isn't a URL: %v", address, err)
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return invalidArgument("The Vault client's address %q must not hold credentials, a query or a fragment.", u.Redacted())
	}
	return checkURL(u)
}

// checkURL refuses a URL a request would go to that isn't https, or http on a loopback address.
// *api.Client reaches a Unix socket (a unix:// address) as http://localhost, so one passes too: it
// never leaves the host either.
func checkURL(u *url.URL) error {
	if u.Scheme == "https" || (u.Scheme == "http" && isLoopback(u.Hostname())) {
		return nil
	}
	return invalidArgument("The Vault client's address %q must be https; http is allowed only on a loopback address "+
		"(a local Vault Agent or dev server), since every request carries a token and DEKs.", u.Redacted())
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// followsRedirects reports whether the client's HTTP client follows redirects itself: net/http
// does unless CheckRedirect stops it, carrying every header but Authorization and cookies -
// X-Vault-Token included - to wherever they point, and resending the body for a 307 or 308.
// api.DefaultConfig's returns http.ErrUseLastResponse; a client given an HTTP client of its own may
// have none, or one that lets redirects through, which is found by asking it about one. A
// RoundTripper that follows redirects itself can't be told, and is accepted.
func followsRedirects(client *api.Client) bool {
	// CloneConfig copies the HTTP client, its CheckRedirect included.
	httpClient := client.CloneConfig().HttpClient
	if httpClient == nil || httpClient.CheckRedirect == nil {
		return true
	}
	from, err := http.NewRequest(http.MethodPost, "https://vault.invalid/v1/transit/encrypt/k", http.NoBody)
	if err != nil {
		return true
	}
	to, err := http.NewRequest(http.MethodPost, "https://elsewhere.invalid/v1/transit/encrypt/k", http.NoBody)
	if err != nil {
		return true
	}
	return httpClient.CheckRedirect(to, []*http.Request{from}) == nil
}
