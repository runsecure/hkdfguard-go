package googlekms

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"hash/crc32"
	"regexp"
	"strings"
	"unicode/utf8"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/securefile"
)

// GeneratedKeyLength is the length of the DEK GenerateAndWrap generates: 32 bytes (AES-256).
const GeneratedKeyLength = 32

// MaxPlaintextLength is the largest plaintext Cloud KMS's Encrypt accepts, in bytes.
const MaxPlaintextLength = 64 * 1024

// MaxContextLength is the longest context, in UTF-8 bytes: what Cloud KMS's additional authenticated
// data allows, less the HkdfGuard label.
const MaxContextLength = 64*1024 - 32

// Client is what KeyWrapper needs of a Cloud KMS client: the two calls it makes, as
// cloud.google.com/go/kms/apiv1 defines them. A *kms.KeyManagementClient is one - over gRPC or REST
// - and so is a test double. Every response is checked before it is used.
type Client interface {
	Encrypt(ctx context.Context, req *kmspb.EncryptRequest, opts ...gax.CallOption) (*kmspb.EncryptResponse, error)
	Decrypt(ctx context.Context, req *kmspb.DecryptRequest, opts ...gax.CallOption) (*kmspb.DecryptResponse, error)
}

var _ Client = (*kms.KeyManagementClient)(nil)

// Options are a KeyWrapper's optional settings; the zero value binds no context and trusts only
// administrators to have written key files.
type Options struct {
	// Context is bound into every wrapped DEK and required again to reveal it; "" binds none. Use one
	// value per application, so a key file made for one can't be used by another that shares the
	// key. It must be valid UTF-8, at most MaxContextLength bytes. Not secret.
	Context string

	// KeyFileTrust is who besides the operating system's administrators may have written a key
	// file ReadKeyFile reads; the zero value (securefile.AdministratorsOnly()) trusts no one else.
	KeyFileTrust securefile.KeyFileTrust
}

// A key's resource name, every part present and none a path of its own: a key version's name, which
// Decrypt doesn't take, doesn't match.
var keyName = regexp.MustCompile(`^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+$`)

// aadLabel is prefixed to every wrapped DEK's additional authenticated data. Changing it makes every
// existing key file unreadable.
const aadLabel = "HkdfGuard-GoogleKms-wrap-v1\x00"

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// statusNames are the gRPC status names, by code, as the other ports name them.
var statusNames = [...]string{
	"OK", "CANCELLED", "UNKNOWN", "INVALID_ARGUMENT", "DEADLINE_EXCEEDED", "NOT_FOUND", "ALREADY_EXISTS", "PERMISSION_DENIED",
	"RESOURCE_EXHAUSTED", "FAILED_PRECONDITION", "ABORTED", "OUT_OF_RANGE", "UNIMPLEMENTED", "INTERNAL", "UNAVAILABLE", "DATA_LOSS",
	"UNAUTHENTICATED",
}

// KeyWrapper is a hkdfguard.KeyWrapper that protects (Encrypt) and reveals (Decrypt) a DEK under one
// symmetric Google Cloud KMS key (purpose ENCRYPT_DECRYPT). The KEK never enters this process; every
// call is a network round trip, authorized by the caller's Google credential through IAM and
// recorded in Cloud Audit Logs. Wrapped DEKs are byte for byte those of the .NET, Java, Python and
// Node wrappers, so a key file made by any of them is read by the others, given the same key and
// context.
//
// The key is pinned: Decrypt is always called against the key given to New, and Cloud KMS refuses a
// ciphertext made under any other key, so a substituted key file wrapped under another key this
// principal may use is never revealed. A ciphertext names the key version that made it, so Cloud
// KMS's own key rotation is transparent here - each key file keeps decrypting under its version,
// which must stay enabled while the file is in use.
//
// Every wrapped DEK is bound, as additional authenticated data, to a fixed HkdfGuard label and the
// optional context: Decrypt fails unless both are presented again exactly. The label stops a
// ciphertext the same key made for some other purpose being accepted as a DEK; the context stops a
// key file made for one application being used by another that shares the key. Neither is secret.
//
// Symmetric encryption needs no secret beyond permission to use the key, so anyone allowed
// cloudkms.cryptoKeyVersions.useToEncrypt can make a key file this wrapper accepts. Give the
// application decrypt only (roles/cloudkms.cryptoKeyDecrypter) and the pipeline that creates key
// files encrypt only; and key files are read only from where an untrusted account can't have written
// or replaced them (see ReadKeyFile and securefile.KeyFileTrust).
//
// Every request and response carries a CRC32C checksum, as Google recommends, so data corrupted in
// transit is refused rather than stored or used. A response naming a version of any other key is
// refused too. Cloud KMS has no "generate data key", so GenerateAndWrap generates the DEK in this
// process and wraps it.
//
// Plaintext key bytes this wrapper owns are zeroed once used: its copy of a key it wraps, once the
// call has returned, and the slice the client decodes Decrypt's plaintext into, once it is copied
// into result - as is result itself whenever an unwrap fails. Copies the client makes are beyond its
// reach: the serialized request and response (protobuf over gRPC, base64 text in JSON over REST), in
// buffers it does not expose, and anything its debug logging writes - which, when
// GOOGLE_SDK_GO_LOGGING_LEVEL is debug or the client was given a logger, includes every request and
// response, keys and all. Process hardening (nativev1.HardenProcess) is what keeps such copies out of
// reach of a debugger or a crash dump; logging must stay off.
//
// The client is the application's: it creates it (credentials, transport, retries), keeps it for as
// long as anything uses this wrapper - a key ring's background refresh included - and closes it. This
// wrapper never creates or closes one. Every call takes ctx, which the client honours; when ctx has
// ended, the call fails with an error matching ctx's (context.Canceled or
// context.DeadlineExceeded). Argument errors wrap ErrInvalidArgument; a Cloud KMS refusal, an
// unreachable service or a credential that can't get a token is an *Error (matching ErrCloudKMS),
// the client's error as its cause. A KeyWrapper is safe for concurrent use.
type KeyWrapper struct {
	client       Client
	keyName      string
	aad          []byte
	aadCRC32C    int64
	keyFileTrust securefile.KeyFileTrust
}

var _ hkdfguard.KeyWrapper = (*KeyWrapper)(nil)

// New returns a KeyWrapper over the symmetric Cloud KMS key keyName, every call made through client
// (a *kms.KeyManagementClient):
//
//	client, err := kms.NewKeyManagementClient(ctx) // the application's: credentials, transport, retries
//	wrapper, err := googlekms.New(client,
//		"projects/my-project/locations/us-east1/keyRings/myapp/cryptoKeys/myapp-wrap",
//		googlekms.Options{Context: "com.example.myapp"})
//
// The key is given as its resource name,
// projects/{project}/locations/{location}/keyRings/{keyRing}/cryptoKeys/{key} - not a key version:
// Decrypt takes the key, and Encrypt uses its primary version. No call is made until the wrapper is
// used.
//
// It fails with ErrInvalidArgument when client is nil, keyName isn't a Cloud KMS key's resource
// name, or the context is too long or not UTF-8.
func New(client Client, keyName string, options Options) (*KeyWrapper, error) {
	if client == nil {
		return nil, invalidArgument("a Cloud KMS client is required (a *kms.KeyManagementClient).")
	}
	if !isKeyName(keyName) {
		return nil, invalidArgument("%q isn't a Cloud KMS key's resource name: "+
			"projects/{project}/locations/{location}/keyRings/{keyRing}/cryptoKeys/{key}, without a key version.", keyName)
	}
	if !utf8.ValidString(options.Context) {
		return nil, invalidArgument("The context isn't valid UTF-8.")
	}
	if len(options.Context) > MaxContextLength {
		return nil, invalidArgument("The context is %d bytes in UTF-8; at most %d are allowed.", len(options.Context), MaxContextLength)
	}
	aad := []byte(aadLabel + options.Context)
	return &KeyWrapper{client: client, keyName: keyName, aad: aad, aadCRC32C: crc32c(aad), keyFileTrust: options.KeyFileTrust}, nil
}

// isKeyName reports whether name is a Cloud KMS key's resource name.
func isKeyName(name string) bool { return keyName.MatchString(name) }

// KeyName is the symmetric key that wraps every DEK: its resource name, as given to New.
func (w *KeyWrapper) KeyName() string { return w.keyName }

// Wrap protects a key with Cloud KMS's Encrypt, writing the ciphertext into result and returning its
// length; hkdfguard.MaxWrappedKeyBytes is always enough room. plaintext is not modified - it is the
// caller's to zero.
//
// It fails with ErrInvalidArgument when plaintext is empty or over MaxPlaintextLength bytes, or
// result is too small for the wrapped DEK; with an *Error when Cloud KMS refused the request or could
// not be reached, the request or response was corrupted in transit, it answered for a key other than
// this one, or the wrapped DEK is over hkdfguard.MaxWrappedKeyBytes.
func (w *KeyWrapper) Wrap(ctx context.Context, plaintext, result []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if len(plaintext) == 0 || len(plaintext) > MaxPlaintextLength {
		return 0, invalidArgument("Cloud KMS wraps 1-%d bytes; got %d.", MaxPlaintextLength, len(plaintext))
	}

	// A copy this wrapper owns, so it can be zeroed whatever the caller does with theirs meanwhile.
	// The client serializes the request inside the call, so it has been sent - or failed - once the
	// call returns.
	buffer := bytes.Clone(plaintext)
	defer hkdfguard.Wipe(buffer)
	return w.wrapOwned(ctx, buffer, result)
}

// Unwrap reveals a key with Cloud KMS's Decrypt, the key pinned, writing it into result and returning
// its length. On any failure result is zeroed.
//
// It fails with an *Error when wrapped is empty or over hkdfguard.MaxWrappedKeyBytes (refused without
// calling Cloud KMS), or Cloud KMS refused it - tampered with, wrapped under another key, or under a
// different context - or could not be reached, or the response was corrupted in transit; with
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
		return 0, w.cloudKMSError("unwrap", nil, "A wrapped DEK is 1-%d bytes; got %d.", hkdfguard.MaxWrappedKeyBytes, len(wrapped))
	}

	ciphertext := bytes.Clone(wrapped)
	response, err := w.client.Decrypt(ctx, &kmspb.DecryptRequest{
		Name:                              w.keyName,
		Ciphertext:                        ciphertext,
		CiphertextCrc32C:                  wrapperspb.Int64(crc32c(ciphertext)),
		AdditionalAuthenticatedData:       bytes.Clone(w.aad),
		AdditionalAuthenticatedDataCrc32C: wrapperspb.Int64(w.aadCRC32C),
	})
	if err != nil {
		return 0, w.classify(ctx, err, "unwrap")
	}
	if response == nil {
		return 0, w.noResponse("unwrap")
	}

	// The client decoded it into a slice of its own, which nothing else holds: zeroed once copied.
	revealed := response.Plaintext
	defer hkdfguard.Wipe(revealed)
	if len(revealed) == 0 {
		return 0, w.cloudKMSError("unwrap", nil, "Cloud KMS unwrap for key '%s' returned no plaintext.", w.keyName)
	}
	if !matches(response.PlaintextCrc32C, revealed) {
		return 0, w.cloudKMSError("unwrap", nil,
			"Cloud KMS unwrap for key '%s' returned a plaintext that doesn't match its checksum: it was corrupted in transit.", w.keyName)
	}
	if len(revealed) > len(result) {
		return 0, invalidArgument("The revealed key is %d bytes; result holds %d.", len(revealed), len(result))
	}
	return copy(result, revealed), nil
}

// GenerateAndWrap generates a fresh GeneratedKeyLength-byte DEK in this process and wraps it as Wrap
// does, writing the wrapped DEK into result and returning its length - the DEK itself is never
// returned, and is zeroed once wrapped. Cloud KMS has no "generate data key".
//
// It fails as Wrap does.
func (w *KeyWrapper) GenerateAndWrap(ctx context.Context, result []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	dek := make([]byte, GeneratedKeyLength)
	defer hkdfguard.Wipe(dek)
	_, _ = rand.Read(dek) // never fails; it crashes the program first
	return w.wrapOwned(ctx, dek, result)
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
// unwrapped key. No Cloud KMS call is made.
//
// A refusal is a *securefile.KeyFileError, matchable with errors.Is against fs.ErrNotExist,
// fs.ErrPermission (securefile.ErrUntrusted for a location that isn't trusted),
// hkdfguard.ErrInvalidKeyFile or securefile.ErrBusy; a KeyFileTrust naming a Windows principal that
// can't be trusted fails with securefile.ErrInvalidTrust.
func (w *KeyWrapper) ReadKeyFile(ctx context.Context, path string) ([]byte, error) {
	return securefile.ReadTrustedKeyFile(ctx, path, w.keyFileTrust)
}

// wrapOwned encrypts key - the wrapper's own slice, which the caller zeroes - and checks the answer
// before using it.
func (w *KeyWrapper) wrapOwned(ctx context.Context, key, result []byte) (int, error) {
	response, err := w.client.Encrypt(ctx, &kmspb.EncryptRequest{
		Name:                              w.keyName,
		Plaintext:                         key,
		PlaintextCrc32C:                   wrapperspb.Int64(crc32c(key)),
		AdditionalAuthenticatedData:       bytes.Clone(w.aad),
		AdditionalAuthenticatedDataCrc32C: wrapperspb.Int64(w.aadCRC32C),
	})
	if err != nil {
		return 0, w.classify(ctx, err, "wrap")
	}
	if response == nil {
		return 0, w.noResponse("wrap")
	}

	// The version that made it must be one of this key's: a response for any other key would produce
	// a key file this wrapper can't read back.
	version, found := strings.CutPrefix(response.Name, w.keyName+"/cryptoKeyVersions/")
	if !found || version == "" || strings.Contains(version, "/") {
		return 0, w.cloudKMSError("wrap", nil, "Cloud KMS wrap for key '%s' reported key version '%s' instead.", w.keyName, response.Name)
	}
	if !response.VerifiedPlaintextCrc32C || !response.VerifiedAdditionalAuthenticatedDataCrc32C {
		return 0, w.cloudKMSError("wrap", nil, "Cloud KMS wrap for key '%s' didn't verify the request's checksums: it was corrupted in transit.", w.keyName)
	}

	ciphertext := response.Ciphertext
	if len(ciphertext) == 0 {
		return 0, w.cloudKMSError("wrap", nil, "Cloud KMS wrap for key '%s' returned no ciphertext.", w.keyName)
	}
	if !matches(response.CiphertextCrc32C, ciphertext) {
		return 0, w.cloudKMSError("wrap", nil,
			"Cloud KMS wrap for key '%s' returned a ciphertext that doesn't match its checksum: it was corrupted in transit.", w.keyName)
	}
	// A key file over the limit would be refused when read back, so refuse to produce one.
	if len(ciphertext) > hkdfguard.MaxWrappedKeyBytes {
		return 0, w.cloudKMSError("wrap", nil, "Cloud KMS wrap for key '%s' returned %d bytes; a wrapped DEK is at most %d.",
			w.keyName, len(ciphertext), hkdfguard.MaxWrappedKeyBytes)
	}
	if len(ciphertext) > len(result) {
		return 0, invalidArgument("The wrapped DEK is %d bytes; result holds %d.", len(ciphertext), len(result))
	}
	return copy(result, ciphertext), nil
}

// classify turns the client's failures into the *Error every operation fails with: a refusal - any
// error carrying a gRPC status, over gRPC or REST - names the status and Google's description;
// anything else (a credential that can't get a token, say) its message. When ctx itself has ended,
// the failure matches ctx's error, whatever status the client reported it with.
func (w *KeyWrapper) classify(ctx context.Context, err error, op string) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		if errors.Is(err, ctxErr) {
			return err
		}
		// gRPC reports an ended context as a CANCELLED or DEADLINE_EXCEEDED status, which doesn't
		// match context.Canceled or context.DeadlineExceeded itself.
		return &contextError{ctxErr: ctxErr, err: err}
	}
	if s, ok := status.FromError(err); ok && s != nil && int(s.Code()) > 0 && int(s.Code()) < len(statusNames) {
		return w.cloudKMSError(op, err, "Cloud KMS %s failed for key '%s': %s: %s", op, w.keyName, statusNames[s.Code()], s.Message())
	}
	return w.cloudKMSError(op, err, "Cloud KMS %s failed for key '%s': %v", op, w.keyName, err)
}

// contextError is a call that failed because its context ended: it matches the context's error, and
// unwraps to the client's too.
type contextError struct {
	ctxErr error
	err    error
}

func (e *contextError) Error() string   { return e.err.Error() }
func (e *contextError) Unwrap() []error { return []error{e.ctxErr, e.err} }

func (w *KeyWrapper) noResponse(op string) error {
	return w.cloudKMSError(op, nil, "Cloud KMS %s for key '%s' returned no response.", op, w.keyName)
}

// crc32c is the CRC32C checksum of data, as Cloud KMS's checksum fields hold it.
func crc32c(data []byte) int64 { return int64(crc32.Checksum(data, castagnoli)) }

// matches reports whether a checksum field is present and holds data's checksum.
func matches(checksum *wrapperspb.Int64Value, data []byte) bool {
	return checksum != nil && checksum.GetValue() == crc32c(data)
}
