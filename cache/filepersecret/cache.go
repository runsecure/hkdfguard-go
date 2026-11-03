package filepersecret

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/diagnostics"
	"github.com/runsecure/hkdfguard-go/securefile"
	"go.opentelemetry.io/otel/metric"
)

// MaxNameLength is the longest name a secret's file can have.
const MaxNameLength = 255

// MaxFileLength is the longest file, in bytes, that is read: room for a formatted secret of about
// 48 KB.
const MaxFileLength = 64 * 1024

// ErrInvalidArgument reports something New refuses before anything is read: an empty folder path,
// or no key ring or format provider.
var ErrInvalidArgument = errors.New("filepersecret: invalid argument")

// Options are a Cache's settings; the zero value logs nothing.
type Options struct {
	// Logger receives a debug record per loaded name while sensitive logging is enabled
	// (diagnostics.Cache), and an error record per failed load; nil logs nothing.
	Logger *slog.Logger
}

// Cache is the hkdfguard.ProtectedReadOnlyCache over a folder of one encrypted file per secret:
// see the package documentation. Safe for concurrent use.
type Cache struct {
	folderPath     string
	trust          securefile.KeyFileTrust
	ring           hkdfguard.KeyRing
	formatProvider hkdfguard.EncryptedFormatProvider
	logger         *slog.Logger

	// Each loaded secret's value as its file held it - encrypted, bound to its name - by exact name,
	// since each spelling is bound, and authenticated, separately. Each a *hkdfguard.KeyTrackingValue.
	values sync.Map
}

var _ hkdfguard.ProtectedReadOnlyCache = (*Cache)(nil)

// New returns a Cache over the folder at folderPath - absolute or relative to the working directory
// - whose files trust says who besides administrators may have written (securefile.AdministratorsOnly()
// for no one). ring supplies the key each file's value names, and is the caller's: the cache never
// closes keys. formatProvider parses each file's formatted value - the format the values were
// written in, normally dek.NewDefaultFormatProvider().
//
// It fails with ErrInvalidArgument for an empty folderPath or a nil ring or formatProvider, and with
// an error matching fs.ErrNotExist when folderPath doesn't name an existing folder.
func New(folderPath string, trust securefile.KeyFileTrust, ring hkdfguard.KeyRing, formatProvider hkdfguard.EncryptedFormatProvider,
	options Options) (*Cache, error) {
	switch {
	case folderPath == "":
		return nil, fmt.Errorf("%w: a secrets folder path is required", ErrInvalidArgument)
	case ring == nil:
		return nil, fmt.Errorf("%w: a key ring is required", ErrInvalidArgument)
	case formatProvider == nil:
		return nil, fmt.Errorf("%w: a format provider is required", ErrInvalidArgument)
	}

	full, err := filepath.Abs(folderPath)
	if err != nil {
		return nil, fmt.Errorf("filepersecret: the secrets folder '%s' can't be resolved: %w", folderPath, err)
	}
	info, err := os.Stat(full)
	if errors.Is(err, fs.ErrNotExist) || (err == nil && !info.IsDir()) {
		return nil, fmt.Errorf("filepersecret: the secrets folder '%s' doesn't exist: %w", full, fs.ErrNotExist)
	}
	if err != nil {
		return nil, fmt.Errorf("filepersecret: the secrets folder '%s' can't be examined: %w", full, err)
	}

	return &Cache{folderPath: full, trust: trust, ring: ring, formatProvider: formatProvider, logger: options.Logger}, nil
}

// FolderPath is the full path of the folder the secrets' files are read from.
func (c *Cache) FolderPath() string { return c.folderPath }

// IsValidName reports whether name can be a secret's file name: 1-MaxNameLength ASCII letters,
// digits, '-', '_' and '.', not starting with '.'.
func IsValidName(name string) bool {
	if name == "" || len(name) > MaxNameLength || name[0] == '.' {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

// Decrypt decrypts the value for name into result - loading it from its file first if it isn't
// cached yet - and returns the number of bytes written, or 0 if there is none. Size result with
// MaxDecryptedLength.
//
// It fails with hkdfguard.ErrAuthenticationFailed when the file's value wasn't encrypted for this
// name, or was altered; with a *securefile.KeyFileError when the file's location isn't trusted
// (securefile.ErrUntrusted), this account may not read it (fs.ErrPermission) or it is over
// MaxFileLength (securefile.ErrTooLarge); and with hkdfguard.ErrKeyNotFound when the value's key
// version isn't in the ring.
func (c *Cache) Decrypt(ctx context.Context, name string, result []byte) (int, error) {
	telemetry := diagnostics.Cache
	ctx, span := telemetry.Start(ctx, diagnostics.SpanCacheDecrypt)
	defer span.End()
	telemetry.LogSensitiveOperation(span, diagnostics.SpanCacheDecrypt, diagnostics.AttrName.String(name))

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

// MaxDecryptedLength is an upper bound on how many bytes Decrypt will write for name, loading its
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

// value is the cached value for name, loading it from its file on a miss; found is false if name
// can't be a file name or there is no value. Concurrent misses may each load the file; the first
// stored is kept.
func (c *Cache) value(ctx context.Context, name string) (*hkdfguard.KeyTrackingValue, bool, error) {
	if cached, ok := c.values.Load(name); ok {
		return cached.(*hkdfguard.KeyTrackingValue), true, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	if !IsValidName(name) {
		return nil, false, nil
	}
	return c.load(ctx, name)
}

// load reads, parses and authenticates name's file, caching its value; found is false when there is
// none.
func (c *Cache) load(ctx context.Context, name string) (*hkdfguard.KeyTrackingValue, bool, error) {
	telemetry := diagnostics.Cache
	ctx, span := telemetry.Start(ctx, diagnostics.SpanCachePopulate)
	defer span.End()
	if telemetry.SensitiveLoggingEnabled() {
		telemetry.LogSensitiveOperation(span, diagnostics.SpanCachePopulate, diagnostics.AttrName.String(name))
		diagnostics.SensitiveOperationLogged(ctx, c.logger, diagnostics.SpanCachePopulate, name)
	}

	value, found, err := c.readValue(ctx, name)
	if err != nil {
		diagnostics.RecordError(span, err)
		diagnostics.OperationFailed(ctx, c.logger, diagnostics.SpanCachePopulate, err)
		recordPopulate(ctx, diagnostics.ResultError)
		return nil, false, err
	}
	if !found {
		recordPopulate(ctx, diagnostics.ResultNotFound)
		return nil, false, nil
	}
	recordPopulate(ctx, diagnostics.ResultSuccess)
	stored, _ := c.values.LoadOrStore(name, value)
	return stored.(*hkdfguard.KeyTrackingValue), true, nil
}

// readValue is name's value from its trusted file, parsed and authenticated; found is false if the
// file or folder doesn't exist, or the file is empty.
func (c *Cache) readValue(ctx context.Context, name string) (*hkdfguard.KeyTrackingValue, bool, error) {
	contents, err := securefile.ReadTrustedFile(ctx, filepath.Join(c.folderPath, name), c.trust, MaxFileLength)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	encrypted := string(bytes.TrimSpace(contents))
	if encrypted == "" {
		return nil, false, nil
	}

	value, err := c.formatProvider.Parse(ctx, encrypted)
	if err != nil {
		return nil, false, err
	}
	if err := c.authenticate(ctx, name, &value); err != nil {
		return nil, false, err
	}
	return &value, true, nil
}

// authenticate decrypts value once into a buffer that is zeroed at once, so only a value that
// authenticates under name - and under a key version the ring holds - is ever cached. AEAD
// ciphertext is always at least as long as its plaintext, so the ciphertext's length is room enough.
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
