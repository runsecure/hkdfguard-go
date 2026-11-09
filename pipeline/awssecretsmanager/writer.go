package awssecretsmanager

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/pipeline"
)

// MaxSecretNameLength is the longest name Secrets Manager accepts for a secret.
const MaxSecretNameLength = 512

var (
	// ErrInvalidArgument reports an argument New refuses: a nil client - and, matching
	// pipeline.ErrInvalidArgument too, whatever pipeline.New refuses of the protector and the secret
	// names.
	ErrInvalidArgument = errors.New("awssecretsmanager: invalid argument")

	// ErrNotCaptured reports a GetSecretValue that succeeded without running the capture middleware
	// the writer passed it - a Client that doesn't hand its optFns on to a *secretsmanager.Client -
	// so the SDK, not the writer, parsed the secret. Nothing is kept, and the binary value it
	// returned, if any, is zeroed; a SecretString it returned is a Go string, beyond reach.
	ErrNotCaptured = errors.New("awssecretsmanager: GetSecretValue answered without running the writer's capture middleware")
)

// Client is what the writer needs of a Secrets Manager client: the one call it makes, as the AWS SDK
// for Go v2 defines it. A *secretsmanager.Client is one. The writer passes every call an optFn that
// adds its capture middleware, so a Client wrapping a *secretsmanager.Client must hand optFns on to
// it unchanged; one that doesn't fails every read with ErrNotCaptured.
type Client interface {
	GetSecretValue(ctx context.Context, params *secretsmanager.GetSecretValueInput,
		optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

var _ Client = (*secretsmanager.Client)(nil)

// New returns a *pipeline.Writer pulling secretNames from AWS Secrets Manager through client, every
// value encrypted by protector - the Go port of the .NET AwsSecretsManagerSecretPipelineWriter.
// Each secret's current version (AWSCURRENT) is read once with GetSecretValue, so the principal
// needs only secretsmanager:GetSecretValue on them (and kms:Decrypt on a customer managed key that
// encrypts them); naming, encrypting, keeping and writing are the pipeline.Writer's.
//
// A secret name is a Secrets Manager secret name, optionally with a key after '#': "prod/api-key"
// reads the secret's whole SecretString, and "prod/app#password" the password member of a key/value
// secret - a SecretString holding a JSON object, as the console stores one (written as
// prod__api-key and prod__app__password). A member's string is read as its text; a number, true or
// false as its JSON text. A name holding '+', '=' or '@', which no file name can, is refused, and so
// is an ARN: name secrets by name.
//
// A secret that doesn't exist (ResourceNotFoundException) or whose SecretString is empty is
// reported missing (pipeline.ErrSecretNotFound). A SecretBinary fails the pull with
// pipeline.ErrInvalidSecretData - the protector encrypts text - as does a response body that isn't
// Secrets Manager's JSON, or a key/value secret holding a key twice. Any other failure (access
// denied, a secret scheduled for deletion, AWS unreachable, no credentials) is returned as the
// SDK's error, so errors.As reaches a smithy.APIError, and so on.
//
// The secret never becomes a Go string. Every GetSecretValue the writer makes appends to that
// call's APIOptions a middleware at the innermost end of the Deserialize step - after every
// middleware the SDK or the application's own APIOptions added, so it is the first to see each
// attempt's raw HTTP response. On a 2xx answer it reads the body into a buffer of its own
// (pipeline.ReadBody), encrypts SecretString, whole and by key, closes the original body and hands
// the SDK an empty object in its place, so the GetSecretValueOutput the SDK builds holds nothing.
// Retries live in the Finalize step, so each attempt passes through it. The call also has
// response-body logging (aws.LogResponseWithBody) turned off. Every buffer that held the value is
// zeroed once it is encrypted. What can't be zeroed is below the middleware: the HTTP client's own
// buffers (TLS decryption, socket reads, and any the application's HTTPClient adds).
//
// The client is the application's: it creates and configures it (credentials - IRSA or EKS Pod
// Identity on EKS through the default chain - region, retries, timeouts, HTTP client). The
// protector is the caller's too: the writer never closes it. New makes no call.
//
// It fails with ErrInvalidArgument when client is nil; and, matching pipeline.ErrInvalidArgument
// too, when pipeline.New refuses the protector or secretNames: no protector, no names, a name
// Secrets Manager can't hold (see IsValidSecretName) with a key after '#' if any, one whose file
// name cache/filepersecret can't read, or two with the same file name in any case.
func New(client Client, protector hkdfguard.PipelineDataProtector, secretNames []string) (*pipeline.Writer, error) {
	if client == nil {
		return nil, fmt.Errorf("%w: a Secrets Manager client is required (a *secretsmanager.Client)", ErrInvalidArgument)
	}
	writer, err := pipeline.New(protector, secretNames, &secretStore{client: client}, pipeline.Options{})
	if err != nil {
		return nil, &argumentError{err: err}
	}
	return writer, nil
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

// secretStore is the pipeline.SecretStore over Secrets Manager.
type secretStore struct {
	client Client
}

func (s *secretStore) IsValidName(name string) bool { return IsValidSecretName(name) }

func (s *secretStore) ReadSecret(ctx context.Context, name string, secret *pipeline.Secret) error {
	// The value reaches secret through the capture middleware; the output holds nothing, so it isn't
	// read here.
	capture := &captureMiddleware{ctx: ctx, secret: secret}
	out, err := s.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String(name)}, capture.apply)
	if err != nil {
		secret.Reset()
		if notFound := (*types.ResourceNotFoundException)(nil); errors.As(err, &notFound) {
			return nil // missing: nothing handed over
		}
		return err
	}
	if !capture.ran {
		secret.Reset()
		if out != nil {
			hkdfguard.Wipe(out.SecretBinary)
		}
		return ErrNotCaptured
	}
	return nil
}

// argumentError is what pipeline.New refused, matching both ErrInvalidArgument and
// pipeline.ErrInvalidArgument, with pipeline.New's message.
type argumentError struct{ err error }

func (e *argumentError) Error() string   { return e.err.Error() }
func (e *argumentError) Unwrap() []error { return []error{ErrInvalidArgument, e.err} }
