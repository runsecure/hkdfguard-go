package diagnostics

import (
	"net/url"
	"strings"
)

// RedactedName replaces a secret's name in a failure that is logged or traced while sensitive
// logging is off.
const RedactedName = "[redacted]"

// LoggedError is err as a failure log record or span may show it: err itself while c's sensitive
// logging is on; otherwise an error whose message is err's with every occurrence of each of names
// replaced by RedactedName, so a failure never names a secret unless sensitive logging is on.
// Pass every name the failure could quote: the name looked up, and any secret or member name it
// involved. nil for a nil err.
//
// A name is matched ignoring ASCII case, as written and as URL path- or query-escaped (an SDK's
// error may quote the request URL), and only as a whole token: where neither neighbouring byte is
// an ASCII letter, digit, '-' or '_', so "db" is not replaced inside "db-password". The result does
// not wrap err: a handler that walks the chain (errors.Unwrap, %+v of a wrapping type) would find
// the original message. Keep err for errors.Is and errors.As; log and trace what LoggedError
// returns.
func (c *Component) LoggedError(err error, names ...string) error {
	if err == nil || c.SensitiveLoggingEnabled() {
		return err
	}
	message := err.Error()
	for _, name := range names {
		message = redactName(message, name)
	}
	return &redactedError{message: message}
}

// redactedError is a failure's message with the names it quoted removed. It deliberately has no
// Unwrap: see LoggedError.
type redactedError struct{ message string }

func (e *redactedError) Error() string { return e.message }

// redactName replaces each whole occurrence of name in message, in every spelling an error may
// carry it, with RedactedName.
func redactName(message, name string) string {
	if name == "" {
		return message
	}
	message = redactToken(message, name)
	for _, escaped := range []string{url.PathEscape(name), url.QueryEscape(name)} {
		if escaped != name {
			message = redactToken(message, escaped)
		}
	}
	return message
}

// redactToken replaces each occurrence of token in message, ignoring ASCII case, that is a whole
// token (see LoggedError) with RedactedName.
func redactToken(message, token string) string {
	lowerMessage, lowerToken := asciiLower(message), asciiLower(token)
	var b strings.Builder
	from := 0
	for {
		at := strings.Index(lowerMessage[from:], lowerToken)
		if at < 0 {
			break
		}
		at += from
		end := at + len(token)
		if isTokenEdge(message, at-1) && isTokenEdge(message, end) {
			b.WriteString(message[from:at])
			b.WriteString(RedactedName)
			from = end
		} else {
			b.WriteString(message[from : at+1])
			from = at + 1
		}
	}
	if from == 0 {
		return message
	}
	b.WriteString(message[from:])
	return b.String()
}

// isTokenEdge reports whether message[i] - or the start or end of message - can border a whole
// name: anything but an ASCII letter, digit, '-' or '_'.
func isTokenEdge(message string, i int) bool {
	if i < 0 || i >= len(message) {
		return true
	}
	c := message[i]
	return !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-' || c == '_')
}

// asciiLower lower-cases only ASCII letters, so every byte keeps its offset.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}
