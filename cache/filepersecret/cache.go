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
	"strings"
	"sync"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/diagnostics"
	"github.com/runsecure/hkdfguard-go/internal/cachevalue"
	"github.com/runsecure/hkdfguard-go/securefile"
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
// digits, '-', '_' and '.', neither starting nor ending with '.', and not a name Windows reserves for a
// device (see isReservedDeviceName).
//
// The rule is the same on every platform, since files written on one are often read on another
// (a pipeline's tar unpacked on a Windows host, say), and Windows doesn't open the file it is asked
// for under either kind of name: it drops a trailing '.', so "item." is the file "item" - two names
// that would share one file - and it opens a device for a reserved name, so a secret named "nul"
// would be written nowhere and never found.
func IsValidName(name string) bool {
	if name == "" || len(name) > MaxNameLength || name[0] == '.' || name[len(name)-1] == '.' {
		return false
	}
	if isReservedDeviceName(name) {
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
		diagnostics.RecordError(span, telemetry.LoggedError(err, name))
	}
	return n, err
}

func (c *Cache) decrypt(ctx context.Context, name string, result []byte) (int, error) {
	value, found, err := c.value(ctx, name)
	if err != nil || !found {
		return 0, err
	}
	return cachevalue.Decrypt(ctx, c.ring, name, value, result)
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
		// A securefile error quotes the file's path, which ends in the name.
		logged := telemetry.LoggedError(err, name)
		diagnostics.RecordError(span, logged)
		diagnostics.OperationFailed(ctx, c.logger, diagnostics.SpanCachePopulate, logged)
		cachevalue.RecordPopulate(ctx, diagnostics.ResultError)
		return nil, false, err
	}
	if !found {
		cachevalue.RecordPopulate(ctx, diagnostics.ResultNotFound)
		return nil, false, nil
	}
	cachevalue.RecordPopulate(ctx, diagnostics.ResultSuccess)
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
	// Only a value that authenticates under name - and under a key version the ring holds - is
	// ever cached.
	if err := cachevalue.Authenticate(ctx, c.ring, name, &value); err != nil {
		return nil, false, err
	}
	return &value, true, nil
}

// isReservedDeviceName reports whether Windows reserves name for a device: its stem - what comes
// before its first '.' - is CON, PRN, AUX or NUL, or COM or LPT followed by one digit, in any case.
// Windows 10 and Windows Server open the device even with an extension ("nul.txt"); later Windows 11
// builds open a file for some of these, but not for every one, so every one is refused. Names
// holding '$' (CONIN$, CONOUT$, CLOCK$) and the superscript-digit forms (COM¹) are already refused
// by the character rule.
func isReservedDeviceName(name string) bool {
	stem, _, _ := strings.Cut(name, ".")
	switch strings.ToUpper(stem) {
	case "CON", "PRN", "AUX", "NUL":
		return true
	}
	if len(stem) == 4 && '0' <= stem[3] && stem[3] <= '9' {
		switch strings.ToUpper(stem[:3]) {
		case "COM", "LPT":
			return true
		}
	}
	return false
}
