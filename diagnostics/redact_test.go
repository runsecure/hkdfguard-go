package diagnostics

import (
	"errors"
	"strings"
	"testing"
)

func withSensitive(t *testing.T, c *Component, enabled bool) {
	t.Helper()
	original := c.SensitiveLoggingEnabled()
	c.SetSensitiveLogging(enabled)
	t.Cleanup(func() { c.SetSensitiveLogging(original) })
}

func TestLoggedError_WithSensitiveLoggingOn_IsTheErrorItself(t *testing.T) {
	withSensitive(t, Cache, true)
	err := errors.New("couldn't read 'myapp/db'")
	if got := Cache.LoggedError(err, "myapp/db"); got != err {
		t.Errorf("got %v", got)
	}
}

func TestLoggedError_WithSensitiveLoggingOff_RemovesEveryNameInEverySpelling(t *testing.T) {
	withSensitive(t, Cache, false)
	for _, tc := range []struct {
		names         []string
		message, want string
	}{
		{[]string{"myapp/db"}, "couldn't read 'myapp/db' from Vault: GET https://v/v1/secret/data/myapp/db: 503",
			"couldn't read '[redacted]' from Vault: GET https://v/v1/secret/data/[redacted]: 503"},
		{[]string{"Db-Password"}, "GET https://kv.vault.azure.net/secrets/db-password/ 403", "GET https://kv.vault.azure.net/secrets/[redacted]/ 403"},
		{[]string{"a b"}, "path a%20b and query a+b and raw 'a b'", "path [redacted] and query [redacted] and raw '[redacted]'"},
		{[]string{"db"}, "db-password and mydb and db_x stay; 'db' and /db/ go", "db-password and mydb and db_x stay; '[redacted]' and /[redacted]/ go"},
		{[]string{"x", "y"}, "x then y", "[redacted] then [redacted]"},
		{[]string{""}, "nothing to do", "nothing to do"},
	} {
		got := Cache.LoggedError(errors.New(tc.message), tc.names...)
		if got.Error() != tc.want {
			t.Errorf("%v in %q:\n got %q\nwant %q", tc.names, tc.message, got.Error(), tc.want)
		}
	}
}

func TestLoggedError_DoesNotWrapTheOriginal(t *testing.T) {
	withSensitive(t, Cache, false)
	got := Cache.LoggedError(errors.New("secret 'name' failed"), "name")
	if errors.Unwrap(got) != nil || strings.Contains(got.Error(), "'name'") {
		t.Errorf("got %q wrapping %v", got, errors.Unwrap(got))
	}
	if Cache.LoggedError(nil, "name") != nil {
		t.Error("nil error became non-nil")
	}
}
