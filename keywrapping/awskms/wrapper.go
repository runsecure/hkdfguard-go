package awskms

import (
	"context"
	"errors"
	"maps"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/securefile"
)

// GeneratedKeyLength is the length of the DEK GenerateAndWrap generates: 32 bytes (AES-256).
const GeneratedKeyLength = 32

// MaxPlaintextLength is the largest plaintext KMS's Encrypt accepts, in bytes.
const MaxPlaintextLength = 4096

// Client is what KeyWrapper needs of a KMS client: the three calls it makes, as the AWS SDK for Go
// v2 defines them. A *kms.Client is one, and so is a test double. Every response is checked
// before it is used.
type Client interface {
	Encrypt(ctx context.Context, params *kms.EncryptInput, optFns ...func(*kms.Options)) (*kms.EncryptOutput, error)
	Decrypt(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error)
	GenerateDataKeyWithoutPlaintext(ctx context.Context, params *kms.GenerateDataKeyWithoutPlaintextInput,
		optFns ...func(*kms.Options)) (*kms.GenerateDataKeyWithoutPlaintextOutput, error)
}

var _ Client = (*kms.Client)(nil)

// Options are a KeyWrapper's optional settings; the zero value binds no encryption context and
// trusts only administrators to have written key files.
type Options struct {
	// EncryptionContext is bound into every wrapped DEK and required again to reveal it. It is
	// copied by New; nil or empty binds none. CloudTrail logs it in plaintext, so it must not hold
	// secrets.
	EncryptionContext map[string]string

	// KeyFileTrust is who besides the operating system's administrators may have written a key
	// file ReadKeyFile reads; the zero value (securefile.AdministratorsOnly()) trusts no one else.
	KeyFileTrust securefile.KeyFileTrust
}

// KeyWrapper is a hkdfguard.KeyWrapper that protects (Encrypt) and reveals (Decrypt) a DEK under
// one symmetric AWS KMS key, and generates fresh DEKs with GenerateDataKeyWithoutPlaintext - so on
// that path the plaintext DEK never leaves KMS. The KEK never enters this process; every call is a
// network round trip, authorized by the caller's IAM credentials and recorded in CloudTrail. The
// ports send KMS the same requests, so a key file wrapped by any of them unwraps with the others
// under the same key and encryption context.
//
// The key is pinned on every Decrypt. A symmetric ciphertext blob names its own key and KMS would
// otherwise decrypt it under whichever key it names, so a substituted key file wrapped under any
// other key this principal may use would be revealed. With the key pinned KMS refuses it
// (IncorrectKeyException). Prefer a key ARN to an alias: Decrypt resolves an alias when it is
// called, so re-pointing the alias at a new key makes every DEK wrapped under the old one
// unreadable. KMS's own automatic key rotation keeps the key ARN and is transparent here.
//
// The encryption context, if any, is bound into every wrapped DEK as authenticated data: Decrypt
// fails unless it is presented again exactly, and key policies can require it
// (kms:EncryptionContext:*). It is logged in plaintext by CloudTrail, so it must not hold secrets.
//
// Key files are read only from where an untrusted account can't have written or replaced them (see
// ReadKeyFile and securefile.KeyFileTrust). Pinning the key stops a key file wrapped under another
// key; this stops one wrapped under this key by anyone who may call kms:Encrypt, which would
// otherwise choose the DEK new data is encrypted under.
//
// Plaintext key bytes this wrapper owns are zeroed once used: its copy of the key sent to Encrypt,
// once the call has returned, and the slice the SDK decodes Decrypt's plaintext into, once it is
// copied into result - as is result itself whenever an unwrap fails. Copies are beyond its reach:
// the SDK base64-encodes the key sent to Encrypt into a JSON request body, and reads Decrypt's
// plaintext from a JSON response body, in buffers it does not expose. Process hardening
// (nativev1.HardenProcess) is what keeps such copies out of reach of a debugger or a crash dump.
//
// The client is the application's: it creates and configures it (credentials, region, retries,
// timeouts). Every call takes ctx, which the SDK honours; when ctx has ended, the SDK's error is
// returned as it is. Argument errors wrap ErrInvalidArgument; a KMS refusal or an unreachable KMS
// is an *Error (matching ErrKMS), the SDK's error as its cause. A KeyWrapper is safe for
// concurrent use.
type KeyWrapper struct {
	client            Client
	keyID             string
	encryptionContext map[string]string
	keyFileTrust      securefile.KeyFileTrust
}

var _ hkdfguard.KeyWrapper = (*KeyWrapper)(nil)

// New returns a KeyWrapper over the symmetric KMS key keyID - a key ARN (preferred), key ID, alias
// name ("alias/...") or alias ARN - every call made through client (a *kms.Client):
//
//	cfg, err := config.LoadDefaultConfig(ctx) // the application's: credentials, region, retries
//	wrapper, err := awskms.New(kms.NewFromConfig(cfg),
//		"arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
//		awskms.Options{EncryptionContext: map[string]string{"purpose": "com.example.myapp"}})
//
// It fails with ErrInvalidArgument when client is nil, keyID is empty or whitespace, or the
// encryption context has an empty key.
func New(client Client, keyID string, options Options) (*KeyWrapper, error) {
	if client == nil {
		return nil, invalidArgument("a KMS client is required (a *kms.Client).")
	}
	if strings.TrimSpace(keyID) == "" {
		return nil, invalidArgument("the key ID must not be empty or whitespace.")
	}
	var encryptionContext map[string]string
	if len(options.EncryptionContext) > 0 {
		for key := range options.EncryptionContext {
			if key == "" {
				return nil, invalidArgument("encryption context keys must not be empty.")
			}
		}
		encryptionContext = maps.Clone(options.EncryptionContext)
	}
	return &KeyWrapper{client: client, keyID: keyID, encryptionContext: encryptionContext, keyFileTrust: options.KeyFileTrust}, nil
}

// KeyID is the symmetric KMS key that wraps every DEK, as given to New.
func (w *KeyWrapper) KeyID() string { return w.keyID }

// Wrap protects a key with KMS's Encrypt, writing the ciphertext blob into result and returning
// its length; hkdfguard.MaxWrappedKeyBytes is always enough room. plaintext is not modified - it is
// the caller's to zero.
//
// It fails with ErrInvalidArgument when plaintext is empty or over MaxPlaintextLength bytes, or
// result is too small for the wrapped DEK; with an *Error when KMS refused the request or could not
// be reached, or returned a wrapped DEK over hkdfguard.MaxWrappedKeyBytes.
func (w *KeyWrapper) Wrap(ctx context.Context, plaintext, result []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if len(plaintext) == 0 || len(plaintext) > MaxPlaintextLength {
		return 0, invalidArgument("KMS wraps 1-%d bytes; got %d.", MaxPlaintextLength, len(plaintext))
	}

	// A copy this wrapper owns, so it can be zeroed whatever the caller does with theirs meanwhile.
	// The SDK serializes the request inside the call, so it has been sent - or failed - once the
	// call returns.
	buffer := make([]byte, len(plaintext))
	copy(buffer, plaintext)
	defer hkdfguard.Wipe(buffer)

	output, err := w.client.Encrypt(ctx, &kms.EncryptInput{
		KeyId:               aws.String(w.keyID),
		Plaintext:           buffer,
		EncryptionContext:   w.requestContext(),
		EncryptionAlgorithm: types.EncryptionAlgorithmSpecSymmetricDefault,
	})
	if err != nil {
		return 0, w.classify(ctx, err, "wrap")
	}
	if output == nil {
		return 0, w.noResponse("wrap")
	}
	return w.copyWrapped(output.CiphertextBlob, result, "wrap")
}

// Unwrap reveals a key with KMS's Decrypt, the key and SYMMETRIC_DEFAULT pinned, writing it into
// result and returning its length. On any failure result is zeroed.
//
// It fails with an *Error when wrapped is empty or over hkdfguard.MaxWrappedKeyBytes (refused
// without calling KMS), or KMS refused it - tampered with, wrapped under another key, or under a
// different encryption context - or could not be reached, or returned no plaintext; with
// ErrInvalidArgument when result is too small for the revealed key.
func (w *KeyWrapper) Unwrap(ctx context.Context, wrapped, result []byte) (n int, err error) {
	defer func() {
		if err != nil {
			// Whatever a failed call left in the DEK buffer is erased.
			hkdfguard.Wipe(result)
		}
	}()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	// Refused locally: no ciphertext this wrapper produced is outside these bounds.
	if len(wrapped) == 0 || len(wrapped) > hkdfguard.MaxWrappedKeyBytes {
		return 0, w.kmsError("unwrap", nil, "A wrapped DEK is 1-%d bytes; got %d.", hkdfguard.MaxWrappedKeyBytes, len(wrapped))
	}

	ciphertext := make([]byte, len(wrapped))
	copy(ciphertext, wrapped)
	output, err := w.client.Decrypt(ctx, &kms.DecryptInput{
		KeyId:               aws.String(w.keyID),
		CiphertextBlob:      ciphertext,
		EncryptionContext:   w.requestContext(),
		EncryptionAlgorithm: types.EncryptionAlgorithmSpecSymmetricDefault,
	})
	if err != nil {
		return 0, w.classify(ctx, err, "unwrap")
	}
	if output == nil {
		return 0, w.noResponse("unwrap")
	}

	// The SDK decoded it into a slice of its own, which nothing else holds: zeroed once copied.
	revealed := output.Plaintext
	defer hkdfguard.Wipe(revealed)
	if len(revealed) == 0 {
		return 0, w.kmsError("unwrap", nil, "AWS KMS unwrap for key '%s' returned no plaintext.", w.keyID)
	}
	if len(revealed) > len(result) {
		return 0, invalidArgument("The revealed key is %d bytes; result holds %d.", len(revealed), len(result))
	}
	return copy(result, revealed), nil
}

// GenerateAndWrap has KMS generate a fresh GeneratedKeyLength-byte DEK and return it wrapped only
// (GenerateDataKeyWithoutPlaintext) - the plaintext DEK never leaves KMS on this call - writing it
// into result and returning its length.
//
// It fails with ErrInvalidArgument when result is too small for the wrapped DEK; with an *Error
// when KMS refused the request or could not be reached, or returned a wrapped DEK over
// hkdfguard.MaxWrappedKeyBytes.
func (w *KeyWrapper) GenerateAndWrap(ctx context.Context, result []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	output, err := w.client.GenerateDataKeyWithoutPlaintext(ctx, &kms.GenerateDataKeyWithoutPlaintextInput{
		KeyId:             aws.String(w.keyID),
		KeySpec:           types.DataKeySpecAes256,
		EncryptionContext: w.requestContext(),
	})
	if err != nil {
		return 0, w.classify(ctx, err, "generate-and-wrap")
	}
	if output == nil {
		return 0, w.noResponse("generate-and-wrap")
	}
	return w.copyWrapped(output.CiphertextBlob, result, "generate-and-wrap")
}

// ReadKeyFile reads a key file this wrapper wrote, still wrapped, refusing one that an account
// other than the operating system's administrators and the Options.KeyFileTrust given to New could
// have written or replaced - the Go equivalent of the native library's checks
// (securefile.ReadTrustedKeyFile). On Windows the file must be on a local fixed drive, reached
// through real folders (no symbolic link, junction or substituted drive), and it and every folder
// above it must be owned by, and modifiable only by, trusted principals. On Linux and macOS it and
// every directory above it must be owned by root or a trusted user and writable by nobody else (by
// its group only if that group is trusted), and only symbolic links a trusted user owns are
// followed. It is also refused if it is empty, over hkdfguard.MaxWrappedKeyBytes, or looks like an
// unwrapped key. No KMS call is made.
//
// A refusal is a *securefile.KeyFileError, matchable with errors.Is against fs.ErrNotExist,
// fs.ErrPermission (securefile.ErrUntrusted for a location that isn't trusted),
// hkdfguard.ErrInvalidKeyFile or securefile.ErrBusy; a KeyFileTrust naming a Windows principal that
// can't be trusted fails with securefile.ErrInvalidTrust.
func (w *KeyWrapper) ReadKeyFile(ctx context.Context, path string) ([]byte, error) {
	return securefile.ReadTrustedKeyFile(ctx, path, w.keyFileTrust)
}

// requestContext is a fresh copy of the encryption context per request, so nothing the SDK (or a
// middleware the application added to the client) does to one request's input can change what
// later requests bind; nil - left out of the request, as the other ports leave it out - when there
// is none.
func (w *KeyWrapper) requestContext() map[string]string {
	return maps.Clone(w.encryptionContext)
}

// classify turns the SDK's failures into the *Error every operation fails with: a service refusal
// (a smithy.APIError: KMS's error code and the HTTP status), or a failure on the way (no
// credentials, a refused connection, a timeout). When ctx itself has ended, the SDK's error is
// returned as it is.
func (w *KeyWrapper) classify(ctx context.Context, err error, op string) error {
	if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
		return err
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return w.kmsError(op, err, "AWS KMS %s failed for key '%s': %s (HTTP %s).", op, w.keyID, apiErr.ErrorCode(), httpStatus(err))
	}
	return w.kmsError(op, err, "AWS KMS %s failed for key '%s': %v", op, w.keyID, err)
}

// httpStatus is the HTTP status of the response an SDK error carries, or "unknown".
func httpStatus(err error) string {
	// The SDK's *awshttp.ResponseError matches through the *smithyhttp.ResponseError it embeds.
	var responseErr *smithyhttp.ResponseError
	if !errors.As(err, &responseErr) || responseErr.Response == nil || responseErr.Response.Response == nil {
		return "unknown"
	}
	return strconv.Itoa(responseErr.Response.StatusCode)
}

func (w *KeyWrapper) noResponse(op string) error {
	return w.kmsError(op, nil, "AWS KMS %s for key '%s' returned no response.", op, w.keyID)
}

func (w *KeyWrapper) copyWrapped(ciphertext, result []byte, op string) (int, error) {
	if len(ciphertext) == 0 {
		return 0, w.kmsError(op, nil, "AWS KMS %s for key '%s' returned no ciphertext.", op, w.keyID)
	}
	// A key file over the limit would be refused when read back, so refuse to produce one.
	if len(ciphertext) > hkdfguard.MaxWrappedKeyBytes {
		return 0, w.kmsError(op, nil, "AWS KMS %s for key '%s' returned %d bytes; a wrapped DEK is at most %d.",
			op, w.keyID, len(ciphertext), hkdfguard.MaxWrappedKeyBytes)
	}
	if len(ciphertext) > len(result) {
		return 0, invalidArgument("The wrapped DEK is %d bytes; result holds %d.", len(ciphertext), len(result))
	}
	return copy(result, ciphertext), nil
}
