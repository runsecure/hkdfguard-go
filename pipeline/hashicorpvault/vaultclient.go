package hashicorpvault

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strings"

	"github.com/hashicorp/vault/api"
)

// The checks New makes of the application's client: the same as cache/hashicorpvault's, which this
// module doesn't depend on, as keywrapping/hashicorpvault keeps its own (each module stands alone).

// checkAddress refuses an address that would send the token in the clear (http anywhere but
// loopback) or that carries credentials, a query or a fragment. A client whose address is a Unix
// socket (unix://, a local Vault Agent's listener) reports it as http://localhost, and is accepted:
// the token never leaves the host, and the socket's file permissions decide who listens on it.
func checkAddress(address string) error {
	u, err := url.Parse(address)
	if err != nil || u.Host == "" {
		return invalidArgument("the Vault client's address '%s' isn't absolute, e.g. https://vault.example.com:8200.", address)
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && isLoopback(u.Hostname())) {
		return invalidArgument("the Vault client's address '%s' must be https; http is allowed only on a loopback address (a local Vault Agent or dev server), since every request carries a token.", address)
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return invalidArgument("the Vault client's address '%s' must not hold credentials, a query or a fragment.", address)
	}
	return nil
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// checkRedirects refuses a client that would follow a redirect, carrying X-Vault-Token to wherever
// it points. The client follows one 301, 302 or 307 itself unless its api.Config set
// DisableRedirects (VAULT_DISABLE_REDIRECTS); and its HttpClient follows any number unless its
// CheckRedirect stops them, as api.DefaultConfig's does (http.ErrUseLastResponse). Go's HTTP client
// drops only Authorization and cookies on a redirect to another host, never X-Vault-Token.
func checkRedirects(client *api.Client) error {
	if disables, known := disablesRedirects(client); !known {
		return invalidArgument("whether the Vault client follows redirects can't be told with this version of github.com/hashicorp/vault/api; set Options.AllowRedirects only if every redirect target may see the token.")
	} else if !disables {
		return invalidArgument("the Vault client follows a redirect itself, which would send the Vault token wherever it points. Set DisableRedirects on the api.Config it was made from (or VAULT_DISABLE_REDIRECTS=true), or set Options.AllowRedirects if every redirect target may see the token.")
	}
	if followsHTTPRedirects(client.CloneConfig().HttpClient) {
		return invalidArgument("the Vault client's HttpClient follows redirects, which would send the Vault token wherever they point. Make its CheckRedirect return http.ErrUseLastResponse, as api.DefaultConfig's does, or set Options.AllowRedirects if every redirect target may see the token.")
	}
	return nil
}

// disablesRedirects reads the DisableRedirects the client was made with. The client has no getter
// for it, and CloneConfig doesn't copy it, so it is read from the client's configuration by
// reflection - read only, and set only before the client is made, so never written while it is
// read. known is false when this version of the client keeps it elsewhere, which New treats as
// following redirects.
func disablesRedirects(client *api.Client) (disables, known bool) {
	config := reflect.ValueOf(client).Elem().FieldByName("config")
	if config.Kind() != reflect.Pointer || config.IsNil() {
		return false, false
	}
	field := config.Elem().FieldByName("DisableRedirects")
	if field.Kind() != reflect.Bool {
		return false, false
	}
	return field.Bool(), true
}

// followsHTTPRedirects reports whether httpClient would follow a redirect from Vault to another host:
// its CheckRedirect is nil, or lets one through (or panics).
func followsHTTPRedirects(httpClient *http.Client) (follows bool) {
	if httpClient == nil || httpClient.CheckRedirect == nil {
		return true
	}
	defer func() {
		if recover() != nil {
			follows = true
		}
	}()
	from, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://vault.invalid/v1/secret/data/item", nil)
	if err != nil {
		return true
	}
	to, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://redirect.invalid/v1/secret/data/item", nil)
	if err != nil {
		return true
	}
	to.Response = &http.Response{StatusCode: http.StatusTemporaryRedirect, Request: from}
	return httpClient.CheckRedirect(to, []*http.Request{from}) == nil
}

// isValidPath reports whether path is '/'-separated segments, none empty, "." or "..", of ASCII
// letters, digits, '-', '_' and '.': a path that stays where it's put.
func isValidPath(path string) bool {
	for segment := range strings.SplitSeq(path, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
		for i := 0; i < len(segment); i++ {
			c := segment[i]
			if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-' || c == '_' || c == '.') {
				return false
			}
		}
	}
	return true
}
