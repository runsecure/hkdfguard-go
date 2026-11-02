package googlesecretmanager

import (
	"context"
	"errors"
	"fmt"
)

var (
	// ErrInvalidArgument reports an argument New refuses: no client, no key ring, or a project that
	// isn't a Google Cloud project ID or number.
	ErrInvalidArgument = errors.New("googlesecretmanager: invalid argument")

	// ErrInvalidResponse reports an AccessSecretVersion response the cache refuses rather than
	// cache: one naming a secret other than the one asked for, or whose payload doesn't match the
	// CRC32C Google returned with it - corrupted in transit. Nothing it held is cached, and its
	// payload is zeroed. The .NET cache throws a CryptographicException for the same.
	ErrInvalidResponse = errors.New("googlesecretmanager: invalid Secret Manager response")
)

// invalidArgument returns an error wrapping ErrInvalidArgument with a formatted reason.
func invalidArgument(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidArgument, fmt.Sprintf(format, args...))
}

// invalidResponse returns an error wrapping ErrInvalidResponse with a formatted reason.
func invalidResponse(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidResponse, fmt.Sprintf(format, args...))
}

// failed is a failed AccessSecretVersion call, the client's error wrapped so that errors.As still
// reaches its *apierror.APIError and status.Code its gRPC status (over REST too, mapped from the
// HTTP status). When ctx itself has ended it also matches ctx's error (context.Canceled or
// context.DeadlineExceeded), which gRPC reports only as a CANCELLED or DEADLINE_EXCEEDED status.
func failed(ctx context.Context, name string, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil && !errors.Is(err, ctxErr) {
		return fmt.Errorf("googlesecretmanager: AccessSecretVersion of secret '%s' failed: %w (%w)", name, err, ctxErr)
	}
	return fmt.Errorf("googlesecretmanager: AccessSecretVersion of secret '%s' failed: %w", name, err)
}
