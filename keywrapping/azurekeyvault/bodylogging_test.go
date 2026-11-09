package azurekeyvault

import (
	"encoding/base64"
	"strings"
	"sync"
	"testing"

	azlog "github.com/Azure/azure-sdk-for-go/sdk/azcore/log"

	"github.com/runsecure/hkdfguard-go/diagnostics"
)

// TestBodyLogging_IsOnlyHonoured_WhileSensitiveLoggingIsOn runs the SDK's own logging policy, so it
// checks what actually reaches a log: with IncludeBody set, the DEK (base64url in Key Vault's
// wrap and unwrap bodies) is logged only while sensitive logging is on.
func TestBodyLogging_IsOnlyHonoured_WhileSensitiveLoggingIsOn(t *testing.T) {
	original := diagnostics.KeyWrapping.SensitiveLoggingEnabled()
	var mu sync.Mutex
	var logged strings.Builder
	azlog.SetListener(func(_ azlog.Event, message string) {
		mu.Lock()
		defer mu.Unlock()
		logged.WriteString(message + "\n")
	})
	t.Cleanup(func() {
		azlog.SetListener(nil)
		diagnostics.KeyWrapping.SetSensitiveLogging(original)
	})

	for _, sensitive := range []bool{false, true} {
		diagnostics.KeyWrapping.SetSensitiveLogging(sensitive)
		vault := newFakeVault(t)
		options := clientOptions(vault)
		options.Logging.IncludeBody = true
		wrapper, err := New(wrapKeyID, signKeyID, &fakeCredential{}, Options{ClientOptions: options})
		if err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		logged.Reset()
		mu.Unlock()

		dek := random(32)
		wrapped := wrapWith(t, wrapper, append([]byte(nil), dek...))
		if _, err := wrapper.Unwrap(t.Context(), wrapped, make([]byte, 32)); err != nil {
			t.Fatal(err)
		}

		mu.Lock()
		text := logged.String()
		mu.Unlock()
		if text == "" {
			t.Fatalf("sensitive=%v: the SDK logged nothing; the test can't see its logging", sensitive)
		}
		encoded := base64.RawURLEncoding.EncodeToString(dek)
		if strings.Contains(text, encoded) != sensitive {
			t.Errorf("sensitive=%v: the DEK logged = %v", sensitive, !sensitive)
		}
	}
}
