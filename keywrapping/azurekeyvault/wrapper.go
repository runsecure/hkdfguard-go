package azurekeyvault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/internal/kmswrap"
	"github.com/runsecure/hkdfguard-go/securefile"
)

// GeneratedKeyLength is the length of the DEK GenerateAndWrap generates: 32 bytes (AES-256).
const GeneratedKeyLength = 32

// MaxPlaintextLength is the largest plaintext RSA-OAEP-256 wraps under a 2048-bit key, in bytes.
const MaxPlaintextLength = 190

// service is Key Vault's limits, for the steps every cloud key wrapper takes alike.
var service = kmswrap.Service{Name: "Azure Key Vault", MaxPlaintextLength: MaxPlaintextLength, InvalidArgument: invalidArgument}

// Options are a KeyWrapper's optional settings; the zero value binds no context, trusts only
// administrators to have written key files, and gives the Key Vault clients the SDK's defaults.
type Options struct {
	// Context is bound into every wrapped DEK's signature and required again to reveal it; "" binds
	// none. Use one value per application, so a key file made for one can't be used by another that
	// shares the keys. It must be valid UTF-8, at most 65535 bytes. Not secret.
	Context string

	// KeyFileTrust is who besides the operating system's administrators may have written a key
	// file ReadKeyFile reads; the zero value (securefile.AdministratorsOnly()) trusts no one else.
	KeyFileTrust securefile.KeyFileTrust

	// ClientOptions configure every Key Vault client the wrapper creates - retries, transport,
	// logging, the API version, challenge resource verification; nil is the SDK's defaults. They are
	// copied by New.
	ClientOptions *azkeys.ClientOptions
}

// KeyWrapper is a hkdfguard.KeyWrapper that protects (wraps) and reveals (unwraps) a DEK under an
// RSA key in Azure Key Vault, and signs every wrapped DEK with a second, EC P-256 key in the vault.
// The private keys never enter this process; every call is a round trip to Key Vault, authorized by
// the caller's Azure credential.
//
// Why two keys: RSA-OAEP wrapping needs only the public key, which isn't secret, so without the
// signature anyone could produce a wrapped DEK this wrapper would accept - holding a DEK they chose,
// which the application would then encrypt new data under. Signing needs the signing key's private
// half, held in Key Vault and usable only by principals granted sign. Unwrap checks the signature
// before it unwraps anything, so a wrapped DEK proves it was made by a principal allowed to sign:
// give that permission to the pipeline that creates key files, never to the application. Each key
// does one job; New refuses the same key for both.
//
// Both keys are pinned: a wrapped DEK records only the key versions it was made with, and the vault
// and key names always come from New. Rotating either key in Key Vault therefore needs nothing here
// - existing key files keep naming the version that made them, which must stay enabled while
// they're in use. Wrapped DEKs are byte for byte those of the .NET, Java, Python and Node wrappers,
// so a key file made by any of them is read by the others, given the same keys and context.
//
// A key identifier given without a version wraps and signs under the key's current version, and the
// version Key Vault reports having used is the one recorded; unwrapping and verifying go to the
// versions a key file records. No call reads a key, so no identity needs get. The Azure SDK for Go
// does no cryptography in the process, so wrapping and verifying are Key Vault calls too, as
// unwrapping and signing always are.
//
// The optional context is bound into the signature, and must be given again, exactly, to reveal the
// DEK. Key Vault has no "generate data key", so GenerateAndWrap generates the DEK in this process and
// wraps it.
//
// Plaintext key bytes this wrapper owns are zeroed once used: its copy of a key it wraps, once the
// call has returned, and the slice the SDK decodes an unwrapped key into, once it is copied into
// result - as is result itself whenever an unwrap fails. Copies are beyond its reach: the SDK
// base64-encodes the key sent to wrapKey into a JSON request body, and reads unwrapKey's answer from
// a JSON response body, in buffers it does not expose. Process hardening (nativev1.HardenProcess) is
// what keeps such copies out of reach of a debugger or a crash dump.
//
// Every call takes ctx, which the SDK honours; when ctx has ended, the SDK's error is returned as it
// is. Argument errors wrap ErrInvalidArgument; a Key Vault refusal, an unreachable vault or a
// credential that can't get a token is an *Error (matching ErrKeyVault), the SDK's error as its
// cause. A KeyWrapper is safe for concurrent use.
type KeyWrapper struct {
	wrappingKeyID string
	signingKeyID  string
	wrappingKey   keyID
	signingKey    keyID
	wrapClient    *azkeys.Client
	signClient    *azkeys.Client
	context       []byte
	keyFileTrust  securefile.KeyFileTrust
}

var _ hkdfguard.KeyWrapper = (*KeyWrapper)(nil)

// New returns a KeyWrapper over an RSA wrapping key and an EC P-256 signing key, every call
// authorized by credential - a managed identity, say, or azidentity.DefaultAzureCredential, which
// finds it:
//
//	wrapper, err := azurekeyvault.New(
//		"https://myvault.vault.azure.net/keys/myapp-wrap",
//		"https://myvault.vault.azure.net/keys/myapp-sign",
//		credential, azurekeyvault.Options{Context: "com.example.myapp"})
//
// Each key is given as its key identifier, https://{vault}.vault.azure.net/keys/{name}, optionally
// with /{version} to wrap or sign under that version rather than the current one. The wrapping key
// must be RSA, 2048 or 3072 bits. No call is made until the wrapper is used.
//
// It fails with ErrInvalidArgument when a key identifier isn't a Key Vault key's, both name the same
// key, credential is nil, or the context is too long or not UTF-8; or with the SDK's error when it
// refuses the client options.
func New(wrappingKeyID, signingKeyID string, credential azcore.TokenCredential, options Options) (*KeyWrapper, error) {
	wrappingKey, err := parseKeyID(wrappingKeyID)
	if err != nil {
		return nil, err
	}
	signingKey, err := parseKeyID(signingKeyID)
	if err != nil {
		return nil, err
	}
	if wrappingKey.sameKey(signingKey) {
		return nil, invalidArgument("The wrapping and signing keys are both '%s'; use an RSA key to wrap and a separate EC P-256 key to sign.",
			wrappingKey.name)
	}
	if credential == nil {
		return nil, invalidArgument("a credential is required (an azcore.TokenCredential, from azidentity for example).")
	}
	encodedContext, err := encodeContext(options.Context)
	if err != nil {
		return nil, err
	}

	wrapClient, err := newClient(wrappingKey.vault, credential, options.ClientOptions)
	if err != nil {
		return nil, err
	}
	// One client per vault: each learns its vault's authentication challenge once.
	signClient := wrapClient
	if signingKey.vault != wrappingKey.vault {
		if signClient, err = newClient(signingKey.vault, credential, options.ClientOptions); err != nil {
			return nil, err
		}
	}
	return &KeyWrapper{
		wrappingKeyID: wrappingKeyID,
		signingKeyID:  signingKeyID,
		wrappingKey:   wrappingKey,
		signingKey:    signingKey,
		wrapClient:    wrapClient,
		signClient:    signClient,
		context:       encodedContext,
		keyFileTrust:  options.KeyFileTrust,
	}, nil
}

// newClient is a Key Vault client for vault, given its own copy of the options.
func newClient(vault string, credential azcore.TokenCredential, options *azkeys.ClientOptions) (*azkeys.Client, error) {
	var copied azkeys.ClientOptions
	if options != nil {
		copied = *options
	}
	return azkeys.NewClient(vault, credential, &copied)
}

// WrappingKeyID is the RSA key that wraps every DEK, as given to New.
func (w *KeyWrapper) WrappingKeyID() string { return w.wrappingKeyID }

// SigningKeyID is the EC P-256 key that signs every wrapped DEK, as given to New.
func (w *KeyWrapper) SigningKeyID() string { return w.signingKeyID }

// Wrap wraps a key under the wrapping key (RSA-OAEP-256), then has the signing key sign the result
// (ES256), writing the wrapped DEK into result and returning its length; hkdfguard.MaxWrappedKeyBytes
// is always enough room. plaintext is not modified - it is the caller's to zero.
//
// It fails with ErrInvalidArgument when plaintext is empty or over MaxPlaintextLength bytes, or
// result is too small for the wrapped DEK; with an *Error when Key Vault refused a request or could
// not be reached, answered for a key other than the one asked, or the wrapped DEK would be over
// hkdfguard.MaxWrappedKeyBytes (an RSA key over 3072 bits) or its signature isn't ES256's.
func (w *KeyWrapper) Wrap(ctx context.Context, plaintext, result []byte) (int, error) {
	return service.Wrap(ctx, plaintext, result, w.wrapOwned)
}

// Unwrap verifies the wrapped DEK's signature under the signing key version it records, and only
// then unwraps it under the recorded wrapping key version, writing the key into result and
// returning its length. On any failure result is zeroed.
//
// It fails with an *Error when wrapped isn't a wrapped DEK this wrapper wrote, its signature doesn't
// verify (forged, tampered with, or under a different context), Key Vault refused it, could not be
// reached or returned no key; with ErrInvalidArgument when result is too small for the revealed key.
func (w *KeyWrapper) Unwrap(ctx context.Context, wrapped, result []byte) (int, error) {
	return kmswrap.Unwrap(ctx, wrapped, result, w.unwrap)
}

func (w *KeyWrapper) unwrap(ctx context.Context, wrapped, result []byte) (int, error) {
	// A copy, so what is verified is what is unwrapped, whatever the caller does with theirs meanwhile.
	envelope := bytes.Clone(wrapped)
	p, err := parse(envelope, w.fail("unwrap", w.wrappingKey))
	if err != nil {
		return 0, err
	}

	// The signature first: nothing reaches unwrapKey that a principal allowed to sign didn't make.
	digest := sha256.Sum256(signedData(envelope[:p.unsignedLength], w.context))
	signedBy := w.signingKey.withVersion(p.signingKeyVersion)
	verified, err := w.signClient.Verify(ctx, signedBy.name, signedBy.version, azkeys.VerifyParameters{
		Algorithm: to.Ptr(azkeys.SignatureAlgorithmES256),
		Digest:    digest[:],
		Signature: p.signature,
	}, nil)
	if err != nil {
		return 0, w.classify(ctx, err, "verify", signedBy)
	}
	if verified.Value == nil || !*verified.Value {
		return 0, keyVaultError("verify", signedBy, nil, "The wrapped DEK's signature doesn't verify under '%s' version %s: it was tampered with, "+
			"wrapped under a different context, or not made by a principal allowed to sign.", w.signingKey.name, p.signingKeyVersion)
	}

	wrappedBy := w.wrappingKey.withVersion(p.wrappingKeyVersion)
	unwrapped, err := w.wrapClient.UnwrapKey(ctx, wrappedBy.name, wrappedBy.version, azkeys.KeyOperationParameters{
		Algorithm: to.Ptr(azkeys.EncryptionAlgorithmRSAOAEP256),
		Value:     p.wrappedDEK,
	}, nil)
	if err != nil {
		return 0, w.classify(ctx, err, "unwrap", wrappedBy)
	}

	// The SDK decoded it into a slice of its own, which nothing else holds: zeroed once copied.
	revealed := unwrapped.Result
	defer hkdfguard.Wipe(revealed)
	if len(revealed) == 0 {
		return 0, keyVaultError("unwrap", wrappedBy, nil, "Azure Key Vault unwrap for key '%s' returned no key.", w.wrappingKey.name)
	}
	return service.Reveal(revealed, result)
}

// GenerateAndWrap generates a fresh GeneratedKeyLength-byte DEK in this process, and wraps and signs
// it as Wrap does, writing the wrapped DEK into result and returning its length - the DEK itself is
// never returned, and is zeroed once wrapped.
//
// It fails as Wrap does.
func (w *KeyWrapper) GenerateAndWrap(ctx context.Context, result []byte) (int, error) {
	return kmswrap.GenerateAndWrap(ctx, GeneratedKeyLength, result, w.wrapOwned)
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
// unwrapped key. No Key Vault call is made.
//
// A refusal is a *securefile.KeyFileError, matchable with errors.Is against fs.ErrNotExist,
// fs.ErrPermission (securefile.ErrUntrusted for a location that isn't trusted),
// hkdfguard.ErrInvalidKeyFile or securefile.ErrBusy; a KeyFileTrust naming a Windows principal that
// can't be trusted fails with securefile.ErrInvalidTrust.
func (w *KeyWrapper) ReadKeyFile(ctx context.Context, path string) ([]byte, error) {
	return securefile.ReadTrustedKeyFile(ctx, path, w.keyFileTrust)
}

func (w *KeyWrapper) wrapOwned(ctx context.Context, key, result []byte) (int, error) {
	wrapped, err := w.wrapClient.WrapKey(ctx, w.wrappingKey.name, w.wrappingKey.version, azkeys.KeyOperationParameters{
		Algorithm: to.Ptr(azkeys.EncryptionAlgorithmRSAOAEP256),
		Value:     key,
	}, nil)
	if err != nil {
		return 0, w.classify(ctx, err, "wrap", w.wrappingKey)
	}
	wrappingKey, err := w.versionUsed(wrapped.KID, w.wrappingKey, "wrap")
	if err != nil {
		return 0, err
	}
	unsigned, err := buildUnsigned(wrappingKey.version, wrapped.Result, w.fail("wrap", wrappingKey))
	if err != nil {
		return 0, err
	}
	if length := len(unsigned) + keyVersionLength + signatureLength; length > hkdfguard.MaxWrappedKeyBytes {
		return 0, keyVaultError("wrap", wrappingKey, nil, "The wrapped DEK would be %d bytes; a wrapped DEK is at most %d. "+
			"Use a 2048- or 3072-bit RSA key for '%s'.", length, hkdfguard.MaxWrappedKeyBytes, w.wrappingKey.name)
	}

	// ES256 signs the SHA-256 digest of the data, which Key Vault takes already computed.
	digest := sha256.Sum256(signedData(unsigned, w.context))
	signed, err := w.signClient.Sign(ctx, w.signingKey.name, w.signingKey.version, azkeys.SignParameters{
		Algorithm: to.Ptr(azkeys.SignatureAlgorithmES256),
		Value:     digest[:],
	}, nil)
	if err != nil {
		return 0, w.classify(ctx, err, "sign", w.signingKey)
	}
	signingKey, err := w.versionUsed(signed.KID, w.signingKey, "sign")
	if err != nil {
		return 0, err
	}
	return write(unsigned, signingKey.version, signed.Result, result, w.fail("sign", signingKey))
}

// versionUsed is the version of key Key Vault reports an operation used, refusing an answer from any
// other key, or from another version than the one asked for.
func (w *KeyWrapper) versionUsed(reported *azkeys.ID, key keyID, op string) (keyID, error) {
	var id string
	if reported != nil {
		id = string(*reported)
	}
	used, err := parseKeyID(id)
	if err != nil {
		return keyID{}, keyVaultError(op, key, nil, "Azure Key Vault %s for key '%s' reported key %q, which isn't a key identifier.", op, key.name, id)
	}
	if !used.sameKey(key) || (key.version != "" && !strings.EqualFold(used.version, key.version)) {
		return keyID{}, keyVaultError(op, key, nil, "Azure Key Vault %s for key '%s' reported key '%s' instead.", op, key.name, id)
	}
	if used.version == "" {
		return keyID{}, keyVaultError(op, key, nil, "Azure Key Vault %s for key '%s' didn't report which version it used.", op, key.name)
	}
	return key.withVersion(used.version), nil
}

// classify turns the SDK's failures into the *Error every operation fails with: a service refusal
// (an *azcore.ResponseError: Key Vault's error code and the HTTP status), or a failure on the way (a
// credential that can't get a token, a refused connection, a timeout). When ctx itself has ended,
// the SDK's error is returned as it is.
func (w *KeyWrapper) classify(ctx context.Context, err error, op string, key keyID) error {
	if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
		return err
	}
	var responseErr *azcore.ResponseError
	if errors.As(err, &responseErr) {
		code := responseErr.ErrorCode
		if code == "" {
			code = "error"
		}
		return keyVaultError(op, key, err, "Azure Key Vault %s failed for key '%s': %s (HTTP %d).", op, key.name, code, responseErr.StatusCode)
	}
	return keyVaultError(op, key, err, "Azure Key Vault %s failed for key '%s': %v", op, key.name, err)
}

// fail is how a malformed envelope or Key Vault answer fails: an *Error for op on key.
func (w *KeyWrapper) fail(op string, key keyID) fail {
	return func(format string, args ...any) error {
		return keyVaultError(op, key, nil, format, args...)
	}
}
