package systemdcredentials

import (
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrUnsupportedPlatform reports New anywhere but Linux: systemd-creds runs only there.
	ErrUnsupportedPlatform = errors.New("systemd-creds runs only on Linux")

	// ErrInvalidArgument reports options, a path or encrypted files that aren't valid.
	ErrInvalidArgument = errors.New("systemdcredentials: invalid argument")

	// ErrInvalidName reports a name that can't be a credential's (see IsValidName). It matches
	// ErrInvalidArgument too.
	ErrInvalidName = fmt.Errorf("%w: not a credential name", ErrInvalidArgument)

	// ErrTooLarge reports a credential longer than MaxLength, systemd's own limit.
	ErrTooLarge = errors.New("systemdcredentials: the credential is longer than systemd's limit")

	// ErrTimeout reports a systemd-creds run that didn't finish in time, and was killed.
	ErrTimeout = errors.New("systemdcredentials: systemd-creds timed out")

	// ErrClosed reports a Credential read after it was closed.
	ErrClosed = errors.New("systemdcredentials: the credential is closed")

	// ErrResultTooSmall reports a Source.Decrypt result buffer too small for the credential.
	ErrResultTooSmall = errors.New("systemdcredentials: the result buffer is too small")

	// ErrCommandFailed is what a *CommandError matches.
	ErrCommandFailed = errors.New("systemdcredentials: systemd-creds failed")
)

// CommandError is a systemd-creds run that exited with a failure: the wrong name, another
// machine's credential, no access to the host key or TPM. Its message is systemd-creds' own.
type CommandError struct {
	// Verb is what was run: "encrypt" or "decrypt".
	Verb string

	// ExitCode is systemd-creds' exit code.
	ExitCode int

	// Stderr is what systemd-creds wrote to its standard error.
	Stderr string
}

func (e *CommandError) Error() string {
	message := fmt.Sprintf("systemd-creds %s failed with exit code %d", e.Verb, e.ExitCode)
	if detail := strings.TrimSpace(e.Stderr); detail != "" {
		message += ": " + detail
	}
	return message
}

// Is reports whether target is ErrCommandFailed.
func (e *CommandError) Is(target error) bool { return target == ErrCommandFailed }
