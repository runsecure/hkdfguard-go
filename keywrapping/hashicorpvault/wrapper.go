package hashicorpvault

import (
	"bytes"
	"context"
	"encoding/base64"
	"strings"
	"unicode/utf8"

	"github.com/hashicorp/vault/api"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/internal/kmswrap"
	"github.com/runsecure/hkdfguard-go/internal/secretjson"
	"github.com/runsecure/hkdfguard-go/securefile"
)

// GeneratedKeyLength is the length of the DEK GenerateAndWrap generates: 32 bytes (AES-256).
const GeneratedKeyLength = 32

// MaxPlaintextLength is the largest plaintext Wrap accepts, in bytes: its ciphertext still fits
// hkdfguard.MaxWrappedKeyBytes.
const MaxPlaintextLength = 256

// MaxContextLength is the longest context, in UTF-8 bytes.
const MaxContextLength = 1024

// MaxKeyNameLength is the longest key name.
const MaxKeyNameLength = 128

// DefaultMountPath is where Options.MountPath leaves the transit secrets engine when it is "":
// Vault's own default mount for it.
const DefaultMountPath = "transit"

// maxResponseLength is the largest answer read from Vault, in bytes; a transit answer is well under
// 1 KB.
const maxResponseLength = 16 * 1024

// service is Vault transit's limits, for the steps every cloud key wrapper takes alike.
var service = kmswrap.Service{Name: "Vault transit", MaxPlaintextLength: MaxPlaintextLength, InvalidArgument: invalidArgument}

// The fixed parts of each request body. Vault doesn't escape base64 or its own ciphertexts, and
// neither is escaped here: neither holds a character JSON would.
const (
	plaintextPrefix  = `{"plaintext":"`
	ciphertextPrefix = `{"ciphertext":"`
	// Asks for a 256-bit key: GeneratedKeyLength bytes.
	dataKeyBody = `{"bits":256}`
)

// Options are a KeyWrapper's optional settings; the zero value calls the engine at "transit", binds
// no context, trusts only administrators to have written key files, and refuses a client that would
// follow redirects.
type Options struct {
	// MountPath is where the transit secrets engine is mounted, e.g. "transit/team-a"; "" for
	// DefaultMountPath. '/'-separated segments of ASCII letters, digits, '-', '_' and '.', none
	// empty, "." or "..". The Vault Enterprise namespace isn't part of it: it is the client's
	// (api.Client.SetNamespace, or VAULT_NAMESPACE).
	MountPath string

	// Context is bound into every wrapped DEK as Vault's associated_data and required again to reveal
	// it; "" binds none. Use one value per application, so a key file made for one can't be used by
	// another that shares the key. It must be valid UTF-8, at most MaxContextLength bytes. Not
	// secret: it must not hold one.
	Context string

	// KeyFileTrust is who besides the operating system's administrators may have written a key
	// file ReadKeyFile reads; the zero value (securefile.AdministratorsOnly()) trusts no one else.
	KeyFileTrust securefile.KeyFileTrust

	// AllowRedirects accepts a client whose HTTP client follows redirects, and has the wrapper
	// follow the one redirect *api.Client itself follows (301, 302 or 307), resending the request
	// body - sending the Vault token, and on wrap and unwrap the request's DEK or ciphertext, to
	// wherever the redirect points. Set it only when every address a redirect could lead to may see
	// the token, such as an HA cluster whose standbys redirect to the active node rather than
	// forward. Default false: no redirect is ever followed, and one is reported as an *Error.
	AllowRedirects bool
}

// KeyWrapper is a hkdfguard.KeyWrapper that protects (encrypt) and reveals (decrypt) a DEK under one
// key in a HashiCorp Vault transit secrets engine, and generates fresh DEKs with datakey/wrapped -
// so on that path the plaintext DEK never leaves Vault. The KEK never enters this process; every call
// is a request to Vault's HTTP API through the application's *api.Client, authorized by its token's
// policy and recorded in Vault's audit log. A wrapped DEK is Vault's ciphertext as it returns it,
// "vault:v{version}:{base64}", in ASCII - byte for byte what the .NET wrapper writes.
//
// The key is pinned by its path: every request names it, and a ciphertext carries only its key
// version, never its key, so a key file wrapped under another transit key fails to authenticate
// rather than being revealed. Vault's key rotation (transit/keys/{name}/rotate) keeps the name and
// is transparent here: new DEKs are wrapped under the latest version, and older ones still reveal
// while their version is at or above the key's min_decryption_version. The key must be an AEAD key
// that isn't derived - aes256-gcm96 (Vault's default), aes128-gcm96 or chacha20-poly1305.
//
// The context, if any, is bound into every wrapped DEK as Vault's associated_data (AAD): decrypt
// fails unless it is presented again exactly. datakey/wrapped ignores associated_data, so with a
// context GenerateAndWrap generates the DEK here and wraps it with encrypt instead - the plaintext
// DEK then does cross the network to Vault, as on Wrap. An answer whose warnings say Vault ignored a
// parameter (a Vault too old for associated_data) is refused, so a context is never silently
// dropped. Vault's audit log HMACs request fields by default, but the context isn't a secret and
// must not hold one.
//
// Key files are read only from where an untrusted account can't have written or replaced them (see
// ReadKeyFile and securefile.KeyFileTrust). Pinning the key stops a key file wrapped under another
// key; this stops one wrapped under this key by anyone whose policy allows encrypt, which would
// otherwise choose the DEK new data is encrypted under.
//
// Plaintext key bytes this wrapper owns are zeroed once used: the encrypt request body (the DEK,
// base64-encoded), which the client sends from the wrapper's own buffer without copying it, and
// Vault's answer, read off the network into a buffer of the wrapper's, with the value read out of it
// and the DEK decoded from that. What it can't zero: the token, which the client holds as a Go string
// for as long as it is set; and copies below the client - the HTTP stack's own buffers (TLS records,
// the connection's read buffer) and anything the client's request or response callbacks, or a
// RoundTripper the application installed, keep. Process hardening (nativev1.HardenProcess) is what
// keeps such copies out of reach of a debugger or a crash dump.
//
// The client is the application's: it sets Vault's address, TLS, the namespace, the token (and
// renews or replaces it - a LifetimeWatcher, or a Vault Agent), the timeout and retries; it keeps the
// client for as long as anything uses this wrapper, a key ring's background refresh included. New
// refuses a client whose address would send the token in the clear - http anywhere but loopback - or
// whose HTTP client follows redirects, unless Options.AllowRedirects; each call checks the address
// again, since the client can be pointed elsewhere. No redirect is followed: *api.Client follows one
// itself, and the wrapper stops it before it is sent. Every call takes ctx, which the client honours;
// when ctx has ended, the call fails with an error matching ctx's (context.Canceled or
// context.DeadlineExceeded). Argument errors wrap ErrInvalidArgument; a Vault refusal, an unreachable
// Vault or the client's own timeout is an *Error (matching ErrVault), the client's error as its
// cause. A KeyWrapper is safe for concurrent use, as *api.Client is.
type KeyWrapper struct {
	client         *api.Client
	keyName        string
	encryptPath    string
	decryptPath    string
	dataKeyPath    string
	hasContext     bool
	bodySuffix     string // closes every encrypt and decrypt body: the value's closing quote, the context if any, the closing brace
	allowRedirects bool
	keyFileTrust   securefile.KeyFileTrust
}

var _ hkdfguard.KeyWrapper = (*KeyWrapper)(nil)

// New returns a KeyWrapper over the transit key keyName, every call made through client:
//
//	config := api.DefaultConfig() // VAULT_ADDR, VAULT_CACERT, VAULT_CLIENT_TIMEOUT, VAULT_MAX_RETRIES...
//	client, err := api.NewClient(config) // VAULT_TOKEN, VAULT_NAMESPACE
//	wrapper, err := hashicorpvault.New(client, "myapp-kek",
//		hashicorpvault.Options{Context: "com.example.myapp"})
//
// No call is made until the wrapper is used.
//
// It fails with ErrInvalidArgument when client is nil; its address isn't https (or http on a
// loopback address or a Unix socket), or holds credentials, a query or a fragment; its HTTP client
// follows redirects and Options.AllowRedirects isn't set; keyName isn't 1-MaxKeyNameLength ASCII
// letters, digits, '-', '_' and '.' (and not "." or ".."); the mount path isn't one; or the
// context is too long or not UTF-8.
func New(client *api.Client, keyName string, options Options) (*KeyWrapper, error) {
	if client == nil {
		return nil, invalidArgument("a Vault client is required (a *api.Client from api.NewClient).")
	}
	if len(keyName) > MaxKeyNameLength || !isSegment(keyName) {
		return nil, invalidArgument("The key name %q isn't one: 1-%d ASCII letters, digits, '-', '_' and '.', and not \".\" or \"..\".",
			keyName, MaxKeyNameLength)
	}
	mountPath := options.MountPath
	if mountPath == "" {
		mountPath = DefaultMountPath
	}
	if !isPath(mountPath) {
		return nil, invalidArgument("The mount path %q isn't a Vault path.", mountPath)
	}
	if !utf8.ValidString(options.Context) {
		return nil, invalidArgument("The context isn't valid UTF-8.")
	}
	if len(options.Context) > MaxContextLength {
		return nil, invalidArgument("The context is %d bytes in UTF-8; at most %d are allowed.", len(options.Context), MaxContextLength)
	}
	if err := checkAddress(client.Address()); err != nil {
		return nil, err
	}
	if !options.AllowRedirects && followsRedirects(client) {
		return nil, invalidArgument("The Vault client's HTTP client follows redirects, which would send the Vault token wherever they point. " +
			"Use the HTTP client api.DefaultConfig makes, set its CheckRedirect to return http.ErrUseLastResponse, " +
			"or set Options.AllowRedirects if every redirect target may see the token.")
	}

	// Vault treats an empty associated_data as none, so an empty context is none too.
	suffix := `"}`
	if options.Context != "" {
		suffix = `","associated_data":"` + base64.StdEncoding.EncodeToString([]byte(options.Context)) + `"}`
	}
	return &KeyWrapper{
		client:         client,
		keyName:        keyName,
		encryptPath:    "/v1/" + mountPath + "/encrypt/" + keyName,
		decryptPath:    "/v1/" + mountPath + "/decrypt/" + keyName,
		dataKeyPath:    "/v1/" + mountPath + "/datakey/wrapped/" + keyName,
		hasContext:     options.Context != "",
		bodySuffix:     suffix,
		allowRedirects: options.AllowRedirects,
		keyFileTrust:   options.KeyFileTrust,
	}, nil
}

// KeyName is the transit key that wraps every DEK, as given to New.
func (w *KeyWrapper) KeyName() string { return w.keyName }

// Wrap protects a key with Vault's encrypt, writing the ciphertext - "vault:v{version}:{base64}" -
// into result and returning its length; hkdfguard.MaxWrappedKeyBytes is always enough room.
// plaintext is not modified - it is the caller's to zero.
//
// It fails with ErrInvalidArgument when plaintext is empty or over MaxPlaintextLength bytes, or
// result is too small for the wrapped DEK, leaving result as it was; with an *Error when Vault
// refused the request or could not be reached, or answered with something that isn't a ciphertext,
// over hkdfguard.MaxWrappedKeyBytes, or with a warning that it ignored the context.
func (w *KeyWrapper) Wrap(ctx context.Context, plaintext, result []byte) (int, error) {
	return service.Wrap(ctx, plaintext, result, w.wrapOwned)
}

// Unwrap reveals a key with Vault's decrypt, the key pinned, writing it into result and returning
// its length. On any failure result is zeroed.
//
// It fails with an *Error when wrapped is empty, over hkdfguard.MaxWrappedKeyBytes or isn't a Vault
// ciphertext (refused without calling Vault), or Vault refused it - tampered with, wrapped under
// another key or under a different context, or its key version is below min_decryption_version - or
// could not be reached, or answered with something that isn't a plaintext; with ErrInvalidArgument
// when result is too small for the revealed key.
func (w *KeyWrapper) Unwrap(ctx context.Context, wrapped, result []byte) (int, error) {
	return kmswrap.Unwrap(ctx, wrapped, result, w.unwrap)
}

func (w *KeyWrapper) unwrap(ctx context.Context, wrapped, result []byte) (int, error) {
	// Refused locally: no ciphertext Vault produces is outside these bounds, and one that is Vault's
	// ciphertext needs no escaping to go in the request body.
	if len(wrapped) == 0 || len(wrapped) > hkdfguard.MaxWrappedKeyBytes {
		return 0, w.vaultError("unwrap", nil, "A wrapped DEK is 1-%d bytes; got %d.", hkdfguard.MaxWrappedKeyBytes, len(wrapped))
	}
	if !isVaultCiphertext(wrapped) {
		return 0, w.vaultError("unwrap", nil, "A wrapped DEK is a Vault transit ciphertext, vault:v{version}:{base64}; this isn't one.")
	}

	body := make([]byte, 0, len(ciphertextPrefix)+len(wrapped)+len(w.bodySuffix))
	body = append(append(append(body, ciphertextPrefix...), wrapped...), w.bodySuffix...)
	answer, err := w.post(ctx, "unwrap", w.decryptPath, body)
	if err != nil {
		return 0, err
	}
	defer hkdfguard.Wipe(answer)
	return w.readAnswer(answer, "unwrap", "plaintext", result)
}

// GenerateAndWrap generates a fresh GeneratedKeyLength-byte DEK wrapped under the key, writing the
// wrapped DEK into result and returning its length. Without a context Vault generates it and returns
// it wrapped only (datakey/wrapped, 256 bits), so the plaintext DEK never leaves Vault on this call.
// With a context - which datakey/wrapped would ignore - it is generated in this process and wrapped
// as Wrap does, then zeroed.
//
// It fails as Wrap does.
func (w *KeyWrapper) GenerateAndWrap(ctx context.Context, result []byte) (int, error) {
	if w.hasContext {
		return kmswrap.GenerateAndWrap(ctx, GeneratedKeyLength, result, w.wrapOwned)
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	answer, err := w.post(ctx, "generate-and-wrap", w.dataKeyPath, []byte(dataKeyBody))
	if err != nil {
		return 0, err
	}
	defer hkdfguard.Wipe(answer)
	return w.readAnswer(answer, "generate-and-wrap", "ciphertext", result)
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
// unwrapped key. No Vault call is made.
//
// A refusal is a *securefile.KeyFileError, matchable with errors.Is against fs.ErrNotExist,
// fs.ErrPermission (securefile.ErrUntrusted for a location that isn't trusted),
// hkdfguard.ErrInvalidKeyFile or securefile.ErrBusy; a KeyFileTrust naming a Windows principal that
// can't be trusted fails with securefile.ErrInvalidTrust.
func (w *KeyWrapper) ReadKeyFile(ctx context.Context, path string) ([]byte, error) {
	return securefile.ReadTrustedKeyFile(ctx, path, w.keyFileTrust)
}

// wrapOwned encrypts key - the wrapper's own slice, which the caller zeroes - from a request body
// holding it base64-encoded, zeroed once the call returns.
func (w *KeyWrapper) wrapOwned(ctx context.Context, key, result []byte) (int, error) {
	body := make([]byte, len(plaintextPrefix)+base64.StdEncoding.EncodedLen(len(key))+len(w.bodySuffix))
	defer hkdfguard.Wipe(body)
	n := copy(body, plaintextPrefix)
	base64.StdEncoding.Encode(body[n:], key)
	copy(body[n+base64.StdEncoding.EncodedLen(len(key)):], w.bodySuffix)

	answer, err := w.post(ctx, "wrap", w.encryptPath, body)
	if err != nil {
		return 0, err
	}
	defer hkdfguard.Wipe(answer)
	return w.readAnswer(answer, "wrap", "ciphertext", result)
}

// readAnswer takes data.{name} - "ciphertext", copied, or "plaintext", decoded - out of a successful
// answer into result, through a buffer of its own that it zeroes. Zeroing the answer is the caller's.
func (w *KeyWrapper) readAnswer(answer []byte, op, name string, result []byte) (int, error) {
	// Never longer than the answer it is read out of: unescaped, a string is never longer.
	value := make([]byte, len(answer))
	defer hkdfguard.Wipe(value)
	n, err := w.readData(answer, op, name, value)
	if err != nil {
		return 0, err
	}
	if name == "plaintext" {
		return w.decodePlaintext(value[:n], result)
	}
	return w.copyCiphertext(value[:n], op, result)
}

// readData copies the string at data.{name} in a successful answer into value, unescaped, and
// returns its length. Refused if it is missing, empty or repeated, isn't a string, or the answer's
// warnings say Vault ignored a parameter - as a Vault too old for associated_data does, leaving a DEK
// bound to no context. The answer is walked in place (package secretjson): no part of it becomes a
// Go string the wrapper couldn't zero.
func (w *KeyWrapper) readData(answer []byte, op, name string, value []byte) (int, error) {
	if !secretjson.IsObject(answer) {
		return 0, w.malformed(op)
	}
	n, found, repeated, ignoredParameter := 0, false, false, false
	secretjson.Members(answer, secretjson.SkipSpace(answer, 0), func(member secretjson.Member) bool {
		switch {
		case member.NameIs("data") && secretjson.KindAt(answer, member.Start) == secretjson.Object:
			secretjson.Members(answer, member.Start, func(field secretjson.Member) bool {
				if !field.NameIs(name) {
					return true
				}
				if found || secretjson.KindAt(answer, field.Start) != secretjson.String {
					repeated = true
					return false
				}
				// Vault doesn't escape base64 or its ciphertext, but a proxy re-encoding the
				// answer might.
				n = secretjson.Unescape(value, secretjson.StringContent(answer, field.Start, field.End))
				found = true
				return true
			})
			return !repeated
		case member.NameIs("warnings") && secretjson.KindAt(answer, member.Start) == secretjson.Array:
			secretjson.Elements(answer, member.Start, func(start, end int) {
				if secretjson.KindAt(answer, start) == secretjson.String && mentionsIgnoredParameter(secretjson.StringContent(answer, start, end)) {
					ignoredParameter = true
				}
			})
		}
		return true
	})
	if repeated {
		return 0, w.malformed(op)
	}
	if ignoredParameter {
		return 0, w.vaultError(op, nil, "Vault transit %s for key '%s' ignored a parameter it was sent, so its answer can't be used: "+
			"a context needs a Vault that supports associated_data.", op, w.keyName)
	}
	if !found || n == 0 {
		return 0, w.vaultError(op, nil, "Vault transit %s for key '%s' returned no %s.", op, w.keyName, name)
	}
	return n, nil
}

// mentionsIgnoredParameter reports whether a warning - raw, as the answer holds it - says Vault
// ignored a parameter it was sent. Warnings hold no key material.
func mentionsIgnoredParameter(raw []byte) bool {
	warning := make([]byte, len(raw))
	warning = warning[:secretjson.Unescape(warning, raw)]
	return strings.Contains(strings.ToLower(string(warning)), "unrecognized parameters")
}

func (w *KeyWrapper) malformed(op string) error {
	return w.vaultError(op, nil, "Vault transit %s for key '%s' returned a response that isn't Vault's.", op, w.keyName)
}

func (w *KeyWrapper) copyCiphertext(ciphertext []byte, op string, result []byte) (int, error) {
	if !isVaultCiphertext(ciphertext) {
		return 0, w.vaultError(op, nil, "Vault transit %s for key '%s' returned something that isn't a ciphertext.", op, w.keyName)
	}
	// A key file over the limit would be refused when read back, so refuse to produce one.
	if len(ciphertext) > hkdfguard.MaxWrappedKeyBytes {
		return 0, w.vaultError(op, nil, "Vault transit %s for key '%s' returned %d bytes; a wrapped DEK is at most %d.",
			op, w.keyName, len(ciphertext), hkdfguard.MaxWrappedKeyBytes)
	}
	if len(ciphertext) > len(result) {
		return 0, invalidArgument("The wrapped DEK is %d bytes; result holds %d.", len(ciphertext), len(result))
	}
	return copy(result, ciphertext), nil
}

// decodePlaintext decodes the revealed key into result, through a buffer of its own that it zeroes:
// decoded straight into result, a key too long for it would be partly written before that was known.
func (w *KeyWrapper) decodePlaintext(encoded, result []byte) (int, error) {
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(encoded)))
	defer hkdfguard.Wipe(decoded)
	n, err := base64.StdEncoding.Decode(decoded, encoded)
	if err != nil || n == 0 || bytes.ContainsAny(encoded, "\r\n") {
		return 0, w.vaultError("unwrap", nil, "Vault transit unwrap for key '%s' returned a plaintext that isn't base64.", w.keyName)
	}
	return service.Reveal(decoded[:n], result)
}

// isVaultCiphertext reports whether value is a transit ciphertext as Vault writes it:
// vault:v{version}:{base64}, the version 1-10 digits.
func isVaultCiphertext(value []byte) bool {
	rest, ok := bytes.CutPrefix(value, []byte("vault:v"))
	if !ok {
		return false
	}
	digits := 0
	for digits < len(rest) && rest[digits] >= '0' && rest[digits] <= '9' {
		digits++
	}
	if digits == 0 || digits > 10 || digits == len(rest) || rest[digits] != ':' || digits+1 == len(rest) {
		return false
	}
	for _, c := range rest[digits+1:] {
		if !isBase64Byte(c) {
			return false
		}
	}
	return true
}

func isBase64Byte(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '='
}

// isPath reports whether path is '/'-separated segments, none empty, "." or "..": a path that stays
// where it's put.
func isPath(path string) bool {
	for segment := range strings.SplitSeq(path, "/") {
		if !isSegment(segment) {
			return false
		}
	}
	return true
}

func isSegment(segment string) bool {
	if segment == "" || segment == "." || segment == ".." {
		return false
	}
	for i := range len(segment) {
		c := segment[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}
