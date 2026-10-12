package dek

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime"
	"slices"
	"time"

	"github.com/runsecure/hkdfguard-go"
)

const (
	// DefaultEphemeralKeyRotation is how often a ring with ephemeral keys adds a fresh one as its
	// current version, unless configured otherwise.
	DefaultEphemeralKeyRotation = 24 * time.Hour

	// MinEphemeralKeyRotation is the shortest rotation interval accepted. Every rotation generates
	// a key through the KEK and starts another background refresh, so rotating faster buys no
	// security and only loads the KMS.
	MinEphemeralKeyRotation = time.Hour

	// DefaultEphemeralKeyRetention is how long a superseded ephemeral key stays registered for
	// decryption, unless configured otherwise.
	DefaultEphemeralKeyRetention = 24 * time.Hour

	// MinEphemeralKeyRetention is the shortest retention accepted.
	MinEphemeralKeyRetention = time.Minute

	// MinKeyRefreshInterval and MaxKeyRefreshInterval bound Config.KeyRefreshInterval.
	MinKeyRefreshInterval = time.Second
	MaxKeyRefreshInterval = 300 * time.Second
)

// keyFileForbiddenPerm is the group- and other-write bits a key file must not have.
const keyFileForbiddenPerm = 0o022

var (
	// ErrInvalidConfig reports a Config that is missing something Build needs, or has a value out
	// of range.
	ErrInvalidConfig = errors.New("dek: invalid key ring configuration")

	// ErrInvalidKeyFile reports a key file that is not a regular file, is writable by its group
	// or by others, or is empty or larger than hkdfguard.MaxWrappedKeyBytes.
	ErrInvalidKeyFile = errors.New("dek: invalid key file")
)

// Config describes the KeyRing Build assembles. One KeyWrapper is shared by every key - it is bound
// to a KEK, not to any one wrapped payload. For each key file, Build asks the CryptoProviderFactory
// to Create a provider for that file's wrapped bytes; for each ephemeral version, to
// CreateEphemeral one around a DEK generated and wrapped at Build time. Every provider is wrapped
// in a Key the ring owns.
//
// Key files are rotated by deployment: each release brings freshly generated files. Ephemeral keys
// are rotated by the ring itself: one with any ephemeral key adds a fresh one as its current
// version every EphemeralKeyRotation.
type Config struct {
	// KeyWrapper reveals every key's DEK. Required.
	KeyWrapper hkdfguard.KeyWrapper

	// CryptoProviderFactory creates each key's provider - the cipher. Required.
	CryptoProviderFactory hkdfguard.CryptoProviderFactory

	// KeyRefreshInterval is how often each key is re-revealed through the KEK to confirm it is
	// still available, MinKeyRefreshInterval to MaxKeyRefreshInterval. Required. Together with
	// RefreshFailurePolicy it sets how quickly a revoked KEK stops a running process: about
	// MaxFailures × KeyRefreshInterval.
	KeyRefreshInterval time.Duration

	// RefreshFailurePolicy is handed to every provider. The zero value fails closed after
	// hkdfguard.DefaultMaxRefreshFailures consecutive failures; choose hkdfguard.FailOpen only when
	// availability matters more than revocation taking effect, and give the crypto provider
	// factory a logger - each failed refresh is then the only sign the KEK is gone.
	RefreshFailurePolicy hkdfguard.RefreshFailurePolicy

	// KeyFiles maps a version to the path of its wrapped DEK file. Each must be a regular file
	// that only its owner can write (on Unix, no group or other write bit): a principal who could
	// rewrite it, and reach the KEK, could substitute a DEK they know.
	KeyFiles map[int]string

	// EphemeralKeys are versions whose DEK is generated at Build time and never written to disk.
	// The highest version across KeyFiles and EphemeralKeys becomes current. At least one key file
	// or ephemeral key is required.
	EphemeralKeys []int

	// FormatProvider formats protected values; a DefaultFormatProvider when nil.
	FormatProvider hkdfguard.EncryptedFormatProvider

	// ServiceName describes this ring's KEK identity, for callers to read back; Build doesn't use
	// it (the KeyWrapper already knows its KEK) but validates it when set.
	ServiceName string

	// EphemeralKeyRotation is how often a ring with ephemeral keys rotates them: at least
	// MinEphemeralKeyRotation, or DefaultEphemeralKeyRotation when zero. A ring of key files alone
	// never rotates.
	EphemeralKeyRotation time.Duration

	// DisableEphemeralKeyRotation keeps the ephemeral key built at startup current until the
	// process restarts.
	DisableEphemeralKeyRotation bool

	// EphemeralKeyRetention is how long a superseded ephemeral key stays registered for
	// decryption before the ring closes and removes it: at least MinEphemeralKeyRetention, or
	// DefaultEphemeralKeyRetention when zero.
	EphemeralKeyRetention time.Duration

	// Logger receives an entry for every ephemeral key rotation, failed rotation and retirement.
	Logger *slog.Logger

	// Test hooks: rotation ticks the test sends, and a callback after each rotation attempt.
	rotationTicks <-chan time.Time
	afterRotate   func()
}

func (c *Config) validate() error {
	switch {
	case c.KeyWrapper == nil:
		return fmt.Errorf("%w: a KeyWrapper is required", ErrInvalidConfig)
	case c.CryptoProviderFactory == nil:
		return fmt.Errorf("%w: a CryptoProviderFactory is required", ErrInvalidConfig)
	case len(c.KeyFiles) == 0 && len(c.EphemeralKeys) == 0:
		return fmt.Errorf("%w: at least one key file or ephemeral key is required", ErrInvalidConfig)
	case c.KeyRefreshInterval < MinKeyRefreshInterval || c.KeyRefreshInterval > MaxKeyRefreshInterval:
		return fmt.Errorf("%w: KeyRefreshInterval must be between %v and %v, got %v", ErrInvalidConfig, MinKeyRefreshInterval, MaxKeyRefreshInterval, c.KeyRefreshInterval)
	case c.EphemeralKeyRotation != 0 && c.EphemeralKeyRotation < MinEphemeralKeyRotation:
		return fmt.Errorf("%w: EphemeralKeyRotation must be at least %v, got %v", ErrInvalidConfig, MinEphemeralKeyRotation, c.EphemeralKeyRotation)
	case c.EphemeralKeyRetention != 0 && c.EphemeralKeyRetention < MinEphemeralKeyRetention:
		return fmt.Errorf("%w: EphemeralKeyRetention must be at least %v, got %v", ErrInvalidConfig, MinEphemeralKeyRetention, c.EphemeralKeyRetention)
	}
	if c.ServiceName != "" {
		if err := hkdfguard.ValidateServiceName(c.ServiceName); err != nil {
			return err
		}
	}
	return c.RefreshFailurePolicy.Validate()
}

// Build reads each key file, creates each ephemeral key, and returns the populated KeyRing. If
// anything fails partway - an unreadable file, an unwrap failure, a version registered twice,
// ctx cancelled - every key created so far is closed and the error returned.
func Build(ctx context.Context, config Config) (*KeyRing, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}

	ring := NewKeyRing(config.FormatProvider)
	if err := populate(ctx, ring, &config); err != nil {
		_ = ring.Close()
		return nil, err
	}

	if len(config.EphemeralKeys) > 0 && !config.DisableEphemeralKeyRotation {
		interval := config.EphemeralKeyRotation
		if interval == 0 {
			interval = DefaultEphemeralKeyRotation
		}
		retention := config.EphemeralKeyRetention
		if retention == 0 {
			retention = DefaultEphemeralKeyRetention
		}

		// Each rotation creates its key exactly as an ephemeral version was created at Build.
		factory, wrapper, refresh, policy := config.CryptoProviderFactory, config.KeyWrapper, config.KeyRefreshInterval, config.RefreshFailurePolicy
		createKey := func(ctx context.Context) (hkdfguard.DataEncryptionKey, error) {
			provider, err := factory.CreateEphemeral(ctx, wrapper, refresh, policy)
			if err != nil {
				return nil, err
			}
			return NewKey(provider), nil
		}
		ring.startRotation(interval, retention, config.EphemeralKeys, createKey, config.Logger, config.rotationTicks, config.afterRotate)
	}
	return ring, nil
}

func populate(ctx context.Context, ring *KeyRing, config *Config) error {
	// In version order, so a failure is reported for the same file every time.
	versions := make([]int, 0, len(config.KeyFiles))
	for version := range config.KeyFiles {
		versions = append(versions, version)
	}
	slices.Sort(versions)

	for _, version := range versions {
		if err := ctx.Err(); err != nil {
			return err
		}
		wrapped, err := readKeyFile(config.KeyFiles[version])
		if err != nil {
			return err
		}
		provider, err := config.CryptoProviderFactory.Create(ctx, config.KeyWrapper, wrapped, config.KeyRefreshInterval, config.RefreshFailurePolicy)
		if err != nil {
			return err
		}
		if err := addOwned(ctx, ring, version, provider); err != nil {
			return err
		}
	}

	for _, version := range config.EphemeralKeys {
		if err := ctx.Err(); err != nil {
			return err
		}
		provider, err := config.CryptoProviderFactory.CreateEphemeral(ctx, config.KeyWrapper, config.KeyRefreshInterval, config.RefreshFailurePolicy)
		if err != nil {
			return err
		}
		if err := addOwned(ctx, ring, version, provider); err != nil {
			return err
		}
	}
	return nil
}

func addOwned(ctx context.Context, ring *KeyRing, version int, provider hkdfguard.CryptoProvider) error {
	key := NewKey(provider)
	if err := ring.Add(ctx, version, key); err != nil {
		_ = key.Close()
		return err
	}
	return nil
}

// readKeyFile reads a wrapped DEK, refusing anything but a regular file only its owner can
// write, an empty file, or one over hkdfguard.MaxWrappedKeyBytes. It never reads more than one
// byte past the limit, so a wrong path (a log, a device) can't make startup allocate an unbounded
// buffer. The checks are made on the opened file, so they describe what is read, not a path that
// may have changed in between.
func readKeyFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: key file '%s' is not a regular file", ErrInvalidKeyFile, path)
	}
	// Windows reports no meaningful Unix permission bits; its ACLs are the file owner's to set.
	if runtime.GOOS != "windows" && info.Mode().Perm()&keyFileForbiddenPerm != 0 {
		return nil, fmt.Errorf("%w: key file '%s' is writable by its group or by others (mode %04o); only its owner may write it", ErrInvalidKeyFile, path, info.Mode().Perm())
	}

	buffer := make([]byte, hkdfguard.MaxWrappedKeyBytes+1)
	n, err := io.ReadFull(file, buffer)
	switch {
	case err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF):
		return nil, err
	case n == 0:
		return nil, fmt.Errorf("%w: key file '%s' is empty", ErrInvalidKeyFile, path)
	case n > hkdfguard.MaxWrappedKeyBytes:
		return nil, fmt.Errorf("%w: key file '%s' is larger than %d bytes (hkdfguard.MaxWrappedKeyBytes); a wrapped key never is", ErrInvalidKeyFile, path, hkdfguard.MaxWrappedKeyBytes)
	}
	return buffer[:n:n], nil
}
