// Package vaultcheck holds the checks the HashiCorp Vault secret modules - cache/hashicorpvault and
// pipeline/hashicorpvault - make of the application's Vault client and of the paths they are given.
// It needs only the standard library, so neither module takes a dependency for it: the client is
// read by reflection, and each check returns why it refuses ("" when it accepts), which the module
// wraps in its own ErrInvalidArgument.
package vaultcheck

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strings"
)

// Check returns why a module's New refuses the *api.Client client - whose address is address, and
// whose configuration's HttpClient httpClient returns - and the KV engine's mountPath: the first of
// Address, Redirects (unless allowRedirects) and MountPath to refuse; "" when none does.
func Check(address string, client any, httpClient func() *http.Client, allowRedirects bool, mountPath string) string {
	reason := Address(address)
	if reason == "" && !allowRedirects {
		reason = Redirects(client, httpClient)
	}
	if reason == "" {
		reason = MountPath(mountPath)
	}
	return reason
}

// Address returns why a Vault client's address - as api.Client.Address returns it - is refused: it
// would send the token in the clear (http anywhere but loopback), or carries credentials, a query or
// a fragment. A client whose address is a Unix socket (unix://, a local Vault Agent's listener)
// reports it as http://localhost, and is accepted: the token never leaves the host, and the socket's
// file permissions decide who listens on it.
func Address(address string) string {
	u, err := url.Parse(address)
	if err != nil || u.Host == "" {
		return fmt.Sprintf("the Vault client's address '%s' isn't absolute, e.g. https://vault.example.com:8200.", address)
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && isLoopback(u.Hostname())) {
		return fmt.Sprintf("the Vault client's address '%s' must be https; http is allowed only on a loopback address (a local Vault Agent or dev server), since every request carries a token.", address)
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return fmt.Sprintf("the Vault client's address '%s' must not hold credentials, a query or a fragment.", address)
	}
	return ""
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Redirects returns why a Vault client is refused for following a redirect, which would carry
// X-Vault-Token to wherever it points. client is the *api.Client; httpClient is the HttpClient of
// its configuration (client.CloneConfig().HttpClient). The client follows one 301, 302 or 307 itself
// unless its api.Config set DisableRedirects (VAULT_DISABLE_REDIRECTS); and its HttpClient follows
// any number unless its CheckRedirect stops them, as api.DefaultConfig's does
// (http.ErrUseLastResponse). Go's HTTP client drops only Authorization and cookies on a redirect to
// another host, never X-Vault-Token.
func Redirects(client any, httpClient func() *http.Client) string {
	if disables, known := DisablesRedirects(client); !known {
		return "whether the Vault client follows redirects can't be told with this version of github.com/hashicorp/vault/api; set Options.AllowRedirects only if every redirect target may see the token."
	} else if !disables {
		return "the Vault client follows a redirect itself, which would send the Vault token wherever it points. Set DisableRedirects on the api.Config it was made from (or VAULT_DISABLE_REDIRECTS=true), or set Options.AllowRedirects if every redirect target may see the token."
	}
	if followsHTTPRedirects(httpClient()) {
		return "the Vault client's HttpClient follows redirects, which would send the Vault token wherever they point. Make its CheckRedirect return http.ErrUseLastResponse, as api.DefaultConfig's does, or set Options.AllowRedirects if every redirect target may see the token."
	}
	return ""
}

// DisablesRedirects reads the DisableRedirects the *api.Client client was made with. The client has
// no getter for it, and CloneConfig doesn't copy it, so it is read from the client's configuration
// by reflection - read only, and set only before the client is made, so never written while it is
// read. known is false when this version of the client keeps it elsewhere, which the modules treat
// as following redirects.
func DisablesRedirects(client any) (disables, known bool) {
	c := reflect.ValueOf(client)
	if c.Kind() != reflect.Pointer || c.IsNil() || c.Elem().Kind() != reflect.Struct {
		return false, false
	}
	config := c.Elem().FieldByName("config")
	if config.Kind() != reflect.Pointer || config.IsNil() || config.Elem().Kind() != reflect.Struct {
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

// MountPath returns why mountPath is refused as a KV engine's mount path: it isn't a Vault path (see
// IsValidPath).
func MountPath(mountPath string) string {
	if IsValidPath(mountPath) {
		return ""
	}
	return fmt.Sprintf("the mount path '%s' isn't a Vault path: '/'-separated segments of ASCII letters, digits, '-', '_' and '.', none \".\" or \"..\".", mountPath)
}

// IsValidPath reports whether path is '/'-separated segments, none empty, "." or "..", of ASCII
// letters, digits, '-', '_' and '.': a path that stays where it's put.
func IsValidPath(path string) bool {
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
