package awssecretsmanager

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/cache"
)

// MaxSecretNameLength is the longest name Secrets Manager accepts for a secret.
const MaxSecretNameLength = 512

var (
	// ErrInvalidArgument reports an argument New refuses: a nil client or key ring.
	ErrInvalidArgument = errors.New("awssecretsmanager: invalid argument")

	// ErrNotCaptured reports a GetSecretValue that succeeded without running the capture middleware
	// the cache passed it - a Client that doesn't hand its optFns on to a *secretsmanager.Client -
	// so the SDK, not the cache, parsed the secret. Nothing is cached, and the binary value it
	// returned, if any, is zeroed; a SecretString it returned is a Go string, beyond reach.
	ErrNotCaptured = errors.New("awssecretsmanager: GetSecretValue answered without running the cache's capture middleware")
)

// Client is what the cache needs of a Secrets Manager client: the one call it makes, as the AWS SDK
// for Go v2 defines it. A *secretsmanager.Client is one. The cache passes every call an optFn that
// adds its capture middleware, so a Client wrapping a *secretsmanager.Client must hand optFns on to
// it unchanged; one that doesn't fails every fetch with ErrNotCaptured.
type Client interface {
	GetSecretValue(ctx context.Context, params *secretsmanager.GetSecretValueInput,
		optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

var _ Client = (*secretsmanager.Client)(nil)

// Options are the cache's optional settings; the zero value logs nothing.
type Options struct {
	// Logger receives a debug record per fetched name while sensitive logging is enabled
	// (diagnostics.Cache), and an error record per failed fetch; see cache.RemoteOptions.
	Logger *slog.Logger
}

// New returns a hkdfguard.ProtectedReadOnlyCache over the secrets client can read, encrypting each
// one it fetches under ring's current key. Nothing is fetched until a name is looked up: the first
// Decrypt or MaxDecryptedLength of a name that isn't cached yet calls GetSecretValue for that one
// secret (its AWSCURRENT version), and every later lookup is served from the cache. The ring is the
// caller's: the cache never closes keys.
//
// Names are matched exactly, as Secrets Manager matches them: "prod/Db" and "prod/db" are two
// secrets and two entries. A name Secrets Manager can't hold (see IsValidSecretName) - such as the
// configuration path "ConnectionStrings:Admin" - is reported missing without a call, so the cache
// can go last in a cache.Collection behind other sources. ARNs aren't accepted: look secrets up by
// name.
//
// A secret that doesn't exist (ResourceNotFoundException) or whose value is empty is reported
// missing, and looked up again next time. Any other failure (access denied, a secret scheduled for
// deletion, AWS unreachable, no credentials) is returned as the SDK's error, so errors.As reaches a
// *types.InvalidRequestException, a smithy.APIError, and so on; a response body that can't be read
// as a secret wraps cache.ErrInvalidSecretData. A SecretString is cached as its UTF-8 bytes; a
// SecretBinary as its bytes. A key/value secret - a SecretString holding a JSON object - is cached
// whole under its name and each member under "name#key" ("prod/app#password"), all from one
// GetSecretValue (see cache.RemoteCache); a SecretBinary is never split. A cached value isn't
// refreshed: a new secret version is picked up by a new cache.
//
// The secret never becomes a Go string. Every GetSecretValue the cache makes appends to that call's
// APIOptions a middleware at the innermost end of the Deserialize step - after every middleware the
// SDK or the application's own APIOptions added, so it is the first to see each attempt's raw HTTP
// response, before the SDK's response logger, interceptors and unmarshaller. On a 2xx answer it
// reads the body into a buffer of its own (cache.CaptureJSONBody), hands SecretString or
// SecretBinary to the cache, closes the original body and hands the SDK one with both values
// blanked, so the GetSecretValueOutput the SDK builds holds "" and an empty slice. Retries live in
// the Finalize step, so each attempt passes through it. The call also has response-body logging
// (aws.LogResponseWithBody) turned off. Every buffer that held the value is zeroed once it is
// encrypted. What can't be zeroed is below the middleware: the HTTP client's own buffers (TLS
// decryption, socket reads, and any the application's HTTPClient adds).
//
// The client is the application's: it creates and configures it (credentials, region, retries,
// timeouts, HTTP client). It fails with ErrInvalidArgument when client or ring is nil.
func New(client Client, ring hkdfguard.KeyRing, options Options) (*cache.RemoteCache, error) {
	if client == nil {
		return nil, fmt.Errorf("%w: a Secrets Manager client is required (a *secretsmanager.Client)", ErrInvalidArgument)
	}
	if ring == nil {
		return nil, fmt.Errorf("%w: a key ring is required", ErrInvalidArgument)
	}
	return cache.NewRemote(ring, &secretStore{client: client}, cache.RemoteOptions{Matching: cache.Exact, Logger: options.Logger})
}

// IsValidSecretName reports whether Secrets Manager accepts name as a secret name: 1-512 ASCII
// letters, digits and /_+=.@-
func IsValidSecretName(name string) bool {
	if name == "" || len(name) > MaxSecretNameLength {
		return false
	}
	for i := 0; i < len(name); i++ {
		switch c := name[i]; {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case c == '/', c == '_', c == '+', c == '=', c == '.', c == '@', c == '-':
		default:
			return false
		}
	}
	return true
}

// secretStore is the cache.SecretStore over Secrets Manager.
type secretStore struct {
	client Client
}

func (s *secretStore) IsValidName(name string) bool { return IsValidSecretName(name) }

func (s *secretStore) Fetch(ctx context.Context, name string, sink *cache.SecretSink) error {
	// The value reaches the sink through the capture middleware; the output holds it blanked, so it
	// isn't read here.
	capture := &captureMiddleware{sink: sink}
	out, err := s.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String(name)}, capture.apply)
	if err != nil {
		if notFound := (*types.ResourceNotFoundException)(nil); errors.As(err, &notFound) {
			return nil // missing: nothing handed over
		}
		return err
	}
	if !capture.ran {
		if out != nil {
			hkdfguard.Wipe(out.SecretBinary)
		}
		return ErrNotCaptured
	}
	return nil
}
