package vaultcheck

import (
	"crypto/tls"
	"net/http"
	"strings"
	"testing"
)

type wrappingTransport struct{ inner http.RoundTripper }

func (w wrappingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return w.inner.RoundTrip(r)
}

func TestTLSVerification_RefusesOnlyATransportThatSkipsIt(t *testing.T) {
	skips := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	for name, tc := range map[string]struct {
		client  *http.Client
		refused bool
	}{
		"skips verification":        {&http.Client{Transport: skips}, true},
		"verifies":                  {&http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{}}}, false},
		"no TLS configuration":      {&http.Client{Transport: &http.Transport{}}, false},
		"default transport":         {&http.Client{}, false},
		"no client":                 {nil, false},
		"a wrapper it can't see in": {&http.Client{Transport: wrappingTransport{skips}}, false},
	} {
		reason := TLSVerification(tc.client)
		if (reason != "") != tc.refused {
			t.Errorf("%s: %q", name, reason)
		}
		if tc.refused && !strings.Contains(reason, "VAULT_SKIP_VERIFY") {
			t.Errorf("%s: the reason doesn't say how to fix it: %q", name, reason)
		}
	}
}
