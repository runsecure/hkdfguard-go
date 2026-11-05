package jsonsecretsfile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/cache/filepersecret"
	"github.com/runsecure/hkdfguard-go/diagnostics"
	"github.com/runsecure/hkdfguard-go/securefile"
	"go.opentelemetry.io/otel/metric"
)

// DefaultMaxFileLength is the longest file read by default, in bytes: room for hundreds of
// formatted secrets.
const DefaultMaxFileLength = 1024 * 1024

var (
	// ErrInvalidArgument reports something New refuses before anything is read: an empty file path,
	// no key ring or format provider, or a negative maximum file length.
	ErrInvalidArgument = errors.New("jsonsecretsfile: invalid argument")

	// ErrInvalidData reports a file that isn't the secrets object: not valid JSON, not one object,
	// a member whose name isn't a secret's name or that is named twice ignoring case, or one whose
	// value isn't a non-empty string - the .NET InvalidDataException.
	ErrInvalidData = errors.New("jsonsecretsfile: invalid secrets file")
)

// Options are a Cache's settings; the zero value logs nothing and reads up to DefaultMaxFileLength
// bytes.
type Options struct {
	// Logger receives a debug record per load and per looked-up name while sensitive logging is
	// enabled (diagnostics.Cache), and an error record per failed load; nil logs nothing.
	Logger *slog.Logger

	// MaxFileLength is the longest file read, in bytes; 0 means DefaultMaxFileLength. securefile
	// reads into a buffer this large, so keep it close to the largest file expected.
	MaxFileLength int
}

// Cache is the hkdfguard.ProtectedReadOnlyCache over one JSON file of encrypted secrets: see the
// package documentation. Safe for concurrent use.
type Cache struct {
	filePath       string
	trust          securefile.KeyFileTrust
	ring           hkdfguard.KeyRing
	formatProvider hkdfguard.EncryptedFormatProvider
	logger         *slog.Logger
	maxFileLength  int

	// One load at a time: a token taken to load. Once a load succeeds its values are kept, and the
	// token is never needed again.
	loading chan struct{}

	// The file's values - encrypted, each bound to its name - by name in upper case; nil until a
	// load succeeds.
	values atomic.Pointer[map[string]*hkdfguard.KeyTrackingValue]
}

var _ hkdfguard.ProtectedReadOnlyCache = (*Cache)(nil)

// New returns a Cache over the JSON file at filePath - absolute or relative to the working
// directory - which trust says who besides administrators may have written
// (securefile.AdministratorsOnly() for no one). ring supplies the key each value names, and is the
// caller's: the cache never closes keys. formatProvider parses each formatted value - the format
// the values were written in, normally dek.NewDefaultFormatProvider().
//
// It fails with ErrInvalidArgument for an empty filePath, a nil ring or formatProvider, or a
// negative options.MaxFileLength, and with an error matching fs.ErrNotExist when filePath doesn't
// name an existing file.
func New(filePath string, trust securefile.KeyFileTrust, ring hkdfguard.KeyRing, formatProvider hkdfguard.EncryptedFormatProvider,
	options Options) (*Cache, error) {
	switch {
	case filePath == "":
		return nil, fmt.Errorf("%w: a secrets file path is required", ErrInvalidArgument)
	case ring == nil:
		return nil, fmt.Errorf("%w: a key ring is required", ErrInvalidArgument)
	case formatProvider == nil:
		return nil, fmt.Errorf("%w: a format provider is required", ErrInvalidArgument)
	case options.MaxFileLength < 0:
		return nil, fmt.Errorf("%w: the maximum file length %d isn't positive", ErrInvalidArgument, options.MaxFileLength)
	}
	maxFileLength := options.MaxFileLength
	if maxFileLength == 0 {
		maxFileLength = DefaultMaxFileLength
	}

	full, err := filepath.Abs(filePath)
	if err != nil {
		return nil, fmt.Errorf("jsonsecretsfile: the secrets file '%s' can't be resolved: %w", filePath, err)
	}
	info, err := os.Stat(full)
	if errors.Is(err, fs.ErrNotExist) || (err == nil && info.IsDir()) {
		return nil, fmt.Errorf("jsonsecretsfile: the secrets file '%s' doesn't exist: %w", full, fs.ErrNotExist)
	}
	if err != nil {
		return nil, fmt.Errorf("jsonsecretsfile: the secrets file '%s' can't be examined: %w", full, err)
	}

	return &Cache{filePath: full, trust: trust, ring: ring, formatProvider: formatProvider, logger: options.Logger,
		maxFileLength: maxFileLength, loading: make(chan struct{}, 1)}, nil
}

// FilePath is the full path of the JSON file the secrets are read from.
func (c *Cache) FilePath() string { return c.filePath }

// Decrypt decrypts the value for name into result - loading the file first if it isn't loaded yet
// - and returns the number of bytes written, or 0 if there is none. Size result with
// MaxDecryptedLength.
//
// It fails, when the file is loaded, with hkdfguard.ErrAuthenticationFailed when a value in the
// file wasn't encrypted for its name, or was altered; with ErrInvalidData when the file isn't the
// secrets object; with a *securefile.KeyFileError when the file's location isn't trusted
// (securefile.ErrUntrusted), this account may not read it (fs.ErrPermission) or it is over the
// maximum length (securefile.ErrTooLarge); with hkdfguard.ErrKeyNotFound when a value's key version
// isn't in the ring; and with ctx's error when ctx ends first.
func (c *Cache) Decrypt(ctx context.Context, name string, result []byte) (int, error) {
	telemetry := diagnostics.Cache
	ctx, span := telemetry.Start(ctx, diagnostics.SpanCacheDecrypt)
	defer span.End()
	if telemetry.SensitiveLoggingEnabled() {
		telemetry.LogSensitiveOperation(span, diagnostics.SpanCacheDecrypt, diagnostics.AttrName.String(name))
		diagnostics.SensitiveOperationLogged(ctx, c.logger, diagnostics.SpanCacheDecrypt, name)
	}

	n, err := c.decrypt(ctx, name, result)
	if err != nil {
		diagnostics.RecordError(span, err)
	}
	return n, err
}

func (c *Cache) decrypt(ctx context.Context, name string, result []byte) (int, error) {
	value, found, err := c.value(ctx, name)
	if err != nil || !found {
		return 0, err
	}
	return c.decryptValue(ctx, name, value, result)
}

// MaxDecryptedLength is an upper bound on how many bytes Decrypt will write for name, loading the
// file first if needed; ok is false if there is no such value. It fails as Decrypt does when the
// file is loaded.
func (c *Cache) MaxDecryptedLength(ctx context.Context, name string) (int, bool, error) {
	value, found, err := c.value(ctx, name)
	if err != nil || !found {
		return 0, false, err
	}
	return len(value.Value), true, nil
}

func (c *Cache) decryptValue(ctx context.Context, name string, value *hkdfguard.KeyTrackingValue, result []byte) (int, error) {
	aad, err := hkdfguard.ConfigurationAAD(name)
	if err != nil {
		return 0, err
	}
	key, err := c.ring.Get(ctx, value.KeyVersion)
	if err != nil {
		return 0, err
	}
	return key.Decrypt(ctx, value.Value, aad, result)
}

// value is name's value, loading the file on the first lookup; found is false if name couldn't be
// a secret's name, the file is missing, or it holds no value for name.
func (c *Cache) value(ctx context.Context, name string) (*hkdfguard.KeyTrackingValue, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	// Checked first, so a name that couldn't be one never loads the file - and every name kept or
	// looked up is ASCII, so folding its case is upper-casing its ASCII letters.
	if !filepersecret.IsValidName(name) {
		return nil, false, nil
	}

	values := c.values.Load()
	if values == nil {
		loaded, err := c.load(ctx)
		if err != nil || loaded == nil {
			return nil, false, err
		}
		values = loaded
	}
	value, found := (*values)[strings.ToUpper(name)]
	return value, found, nil
}

// load reads, parses and authenticates the whole file, keeping its values once every one passes;
// nil if the file is missing.
func (c *Cache) load(ctx context.Context) (*map[string]*hkdfguard.KeyTrackingValue, error) {
	select {
	case c.loading <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-c.loading }()

	// Another lookup may have loaded it while this one waited.
	if loaded := c.values.Load(); loaded != nil {
		return loaded, nil
	}

	telemetry := diagnostics.Cache
	ctx, span := telemetry.Start(ctx, diagnostics.SpanCachePopulate)
	defer span.End()
	if telemetry.SensitiveLoggingEnabled() {
		telemetry.LogSensitiveOperation(span, diagnostics.SpanCachePopulate, diagnostics.AttrName.String(c.filePath))
		diagnostics.SensitiveOperationLogged(ctx, c.logger, diagnostics.SpanCachePopulate, c.filePath)
	}

	values, err := c.readValues(ctx)
	if err != nil {
		diagnostics.RecordError(span, err)
		diagnostics.OperationFailed(ctx, c.logger, diagnostics.SpanCachePopulate, err)
		recordPopulate(ctx, diagnostics.ResultError)
		return nil, err
	}
	if values == nil {
		recordPopulate(ctx, diagnostics.ResultNotFound)
		return nil, nil
	}
	recordPopulate(ctx, diagnostics.ResultSuccess)
	c.values.Store(values)
	return values, nil
}

// readValues is the file's values, parsed and every one authenticated; nil if the file, or a folder
// above it, doesn't exist.
func (c *Cache) readValues(ctx context.Context) (*map[string]*hkdfguard.KeyTrackingValue, error) {
	contents, err := securefile.ReadTrustedFile(ctx, c.filePath, c.trust, c.maxFileLength)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	members, err := c.parse(ctx, contents)
	if err != nil {
		return nil, err
	}
	values := make(map[string]*hkdfguard.KeyTrackingValue, len(members))
	for _, m := range members {
		if err := c.authenticate(ctx, m.name, m.value); err != nil {
			return nil, err
		}
		values[strings.ToUpper(m.name)] = m.value
	}
	return &values, nil
}

// member is one of the secrets object's members, its value parsed but not yet authenticated.
type member struct {
	name  string
	value *hkdfguard.KeyTrackingValue
}

// parse reads the secrets object's members, in the file's order.
func (c *Cache) parse(ctx context.Context, contents []byte) ([]member, error) {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.UseNumber()

	token, err := decoder.Token()
	if err != nil {
		return nil, c.invalidJSON(err)
	}
	if token != json.Delim('{') {
		return nil, c.invalid("holds %s, not an object of secrets", describe(token))
	}

	var members []member
	seen := map[string]struct{}{}
	// The decoder fails on anything malformed or incomplete, so inside the object each token read
	// is a member's name or the object's end, and after a name, its value.
	for {
		token, err := decoder.Token()
		if err != nil {
			return nil, c.invalidJSON(err)
		}
		if token == json.Delim('}') {
			break
		}
		name := token.(string)
		if !filepersecret.IsValidName(name) {
			return nil, c.invalid("names a secret '%s', which isn't a secret's name", name)
		}

		token, err = decoder.Token()
		if err != nil {
			return nil, c.invalidJSON(err)
		}
		encrypted, _ := token.(string)
		encrypted = strings.TrimSpace(encrypted)
		if encrypted == "" {
			return nil, c.invalid("holds no value for '%s': each must be a non-empty string", name)
		}
		value, err := c.formatProvider.Parse(ctx, encrypted)
		if err != nil {
			return nil, err
		}
		folded := strings.ToUpper(name)
		if _, twice := seen[folded]; twice {
			return nil, c.invalid("names '%s' more than once", name)
		}
		seen[folded] = struct{}{}
		members = append(members, member{name: name, value: &value})
	}

	// Anything after the object - a second value, stray text - fails here.
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			err = errors.New("more than one value")
		}
		return nil, c.invalidJSON(err)
	}
	return members, nil
}

func (c *Cache) invalid(format string, args ...any) error {
	return fmt.Errorf("%w: the secrets file '%s' %s", ErrInvalidData, c.filePath, fmt.Sprintf(format, args...))
}

func (c *Cache) invalidJSON(err error) error {
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return c.invalid("isn't valid JSON: %v", err)
}

// describe names a top-level JSON token that isn't an object's start.
func describe(token json.Token) string {
	switch token.(type) {
	case json.Delim:
		return "an array"
	case string:
		return "a string"
	case json.Number:
		return "a number"
	case bool:
		return "a boolean"
	default:
		return "null"
	}
}

// authenticate decrypts value once into a buffer that is zeroed at once, so only values that
// authenticate under their names - and key versions the ring holds - are ever kept. AEAD ciphertext
// is always at least as long as its plaintext, so the ciphertext's length is room enough.
func (c *Cache) authenticate(ctx context.Context, name string, value *hkdfguard.KeyTrackingValue) error {
	plaintext := make([]byte, len(value.Value))
	defer hkdfguard.Wipe(plaintext)
	_, err := c.decryptValue(ctx, name, value, plaintext)
	return err
}

func recordPopulate(ctx context.Context, result string) {
	diagnostics.CacheOperations().Add(ctx, 1, metric.WithAttributes(
		diagnostics.AttrOperationName.String(diagnostics.SpanCachePopulate), diagnostics.AttrResult.String(result)))
}
