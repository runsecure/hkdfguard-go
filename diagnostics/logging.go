package diagnostics

import (
	"context"
	"fmt"
	"log/slog"
)

// LevelCritical is the slog level for unrecoverable conditions (the .NET port's LogLevel.Critical).
const LevelCritical = slog.LevelError + 4

// Log record attribute keys. Event IDs and names match the .NET port's LoggerMessage EventIds and
// method names, so log-based alerts translate across ports.
const (
	LogKeyEventID              = "event.id"
	LogKeyEventName            = "event.name"
	LogKeyError                = "error"
	LogKeyRefreshFailurePolicy = "hkdfguard.refresh_failure_policy"
)

// Structured-log helpers shared by every component that accepts an optional *slog.Logger. A nil
// logger is a no-op, and nothing is formatted when the logger has the level disabled.
// SensitiveOperationLogged is only worth calling when Component.SensitiveLoggingEnabled is set,
// while OperationFailed is unconditional - failures are always worth logging.

// SensitiveOperationLogged logs, at debug level, that operationName completed for name.
func SensitiveOperationLogged(ctx context.Context, logger *slog.Logger, operationName, name string) {
	logEvent(ctx, logger, slog.LevelDebug, 1, "SensitiveOperationLogged", nil,
		func() string { return fmt.Sprintf("%s completed for %s.", operationName, name) },
		slog.String(string(AttrOperationName), operationName),
		slog.String(string(AttrName), name))
}

// OperationFailed logs, at error level, that operationName failed with err.
func OperationFailed(ctx context.Context, logger *slog.Logger, operationName string, err error) {
	logEvent(ctx, logger, slog.LevelError, 2, "OperationFailed", err,
		func() string { return fmt.Sprintf("%s failed.", operationName) },
		slog.String(string(AttrOperationName), operationName))
}

// KeyRefreshFailed logs that a background attempt to re-reveal a key through its key wrapper
// failed - the KEK may have been revoked or become unreachable. Log it on every failure, whatever
// the refresh-failure policy, since under fail-open this is the only sign that the KEK is gone.
func KeyRefreshFailed(ctx context.Context, logger *slog.Logger, consecutiveFailures int, refreshFailurePolicy string, err error) {
	logEvent(ctx, logger, slog.LevelError, 3, "KeyRefreshFailed", err,
		func() string {
			return fmt.Sprintf("Background key refresh failed (%d consecutive). Policy: %s.", consecutiveFailures, refreshFailurePolicy)
		},
		slog.Int(string(AttrConsecutiveFailures), consecutiveFailures),
		slog.String(LogKeyRefreshFailurePolicy, refreshFailurePolicy))
}

// KeyAccessSuspended logs that the refresh-failure limit was reached: the key has been zeroed and
// every Encrypt/Decrypt under it fails until a refresh succeeds.
func KeyAccessSuspended(ctx context.Context, logger *slog.Logger, consecutiveFailures int) {
	logEvent(ctx, logger, LevelCritical, 4, "KeyAccessSuspended", nil,
		func() string {
			return fmt.Sprintf("Key access suspended after %d consecutive failed refreshes; the key has been zeroed and every operation under it fails until a refresh succeeds.", consecutiveFailures)
		},
		slog.Int(string(AttrConsecutiveFailures), consecutiveFailures))
}

// KeyAccessResumed logs that a refresh succeeded after key access had been suspended; operations
// resume.
func KeyAccessResumed(ctx context.Context, logger *slog.Logger, consecutiveFailures int) {
	logEvent(ctx, logger, slog.LevelInfo, 5, "KeyAccessResumed", nil,
		func() string {
			return fmt.Sprintf("Key access resumed: a background refresh succeeded after %d consecutive failures.", consecutiveFailures)
		},
		slog.Int(string(AttrConsecutiveFailures), consecutiveFailures))
}

// EphemeralKeyRotated logs that a scheduled rotation added a fresh ephemeral key, which is now
// the current version.
func EphemeralKeyRotated(ctx context.Context, logger *slog.Logger, keyVersion int) {
	logEvent(ctx, logger, slog.LevelInfo, 6, "EphemeralKeyRotated", nil,
		func() string { return fmt.Sprintf("Ephemeral key rotated: version %d is now current.", keyVersion) },
		slog.Int(string(AttrKeyVersion), keyVersion))
}

// EphemeralKeyRotationFailed logs that a scheduled rotation could not add a new key; the current
// version stays in use and the next interval tries again.
func EphemeralKeyRotationFailed(ctx context.Context, logger *slog.Logger, keyVersion int, err error) {
	logEvent(ctx, logger, slog.LevelError, 7, "EphemeralKeyRotationFailed", err,
		func() string {
			return fmt.Sprintf("Ephemeral key rotation failed; version %d stays current until the next attempt.", keyVersion)
		},
		slog.Int(string(AttrKeyVersion), keyVersion))
}

// EphemeralKeyRetired logs that a superseded ephemeral key's retention ran out: it has been
// removed from the ring and disposed, so values encrypted under it can no longer be decrypted.
func EphemeralKeyRetired(ctx context.Context, logger *slog.Logger, keyVersion int) {
	logEvent(ctx, logger, slog.LevelInfo, 8, "EphemeralKeyRetired", nil,
		func() string {
			return fmt.Sprintf("Ephemeral key retired: version %d has been removed and its key zeroed; values encrypted under it no longer decrypt.", keyVersion)
		},
		slog.Int(string(AttrKeyVersion), keyVersion))
}

// EphemeralKeyRetirementFailed logs that a retired ephemeral key was removed from the ring but
// disposing it failed.
func EphemeralKeyRetirementFailed(ctx context.Context, logger *slog.Logger, keyVersion int, err error) {
	logEvent(ctx, logger, slog.LevelError, 9, "EphemeralKeyRetirementFailed", err,
		func() string {
			return fmt.Sprintf("Ephemeral key version %d was removed from the ring, but disposing it failed.", keyVersion)
		},
		slog.Int(string(AttrKeyVersion), keyVersion))
}

// EncryptionBudgetWarning logs that a key has performed enough encryptions to cross the warning
// threshold of its AES-GCM budget; once it reaches the limit it refuses to encrypt, so rotate it
// before then.
func EncryptionBudgetWarning(ctx context.Context, logger *slog.Logger, encryptionCount, encryptionLimit int64) {
	logEvent(ctx, logger, slog.LevelWarn, 10, "EncryptionBudgetWarning", nil,
		func() string {
			return fmt.Sprintf("This key has performed %d encryptions of its %d AES-GCM limit; rotate it before the limit, when it stops encrypting.", encryptionCount, encryptionLimit)
		},
		slog.Int64(string(AttrEncryptionCount), encryptionCount),
		slog.Int64(string(AttrEncryptionLimit), encryptionLimit))
}

// logEvent writes one record when logger is non-nil and has level enabled, building the message
// only then. err, when non-nil, is attached under LogKeyError.
func logEvent(ctx context.Context, logger *slog.Logger, level slog.Level, eventID int, eventName string, err error, message func() string, attrs ...slog.Attr) {
	if logger == nil || !logger.Enabled(ctx, level) {
		return
	}

	all := make([]slog.Attr, 0, len(attrs)+3)
	all = append(all, slog.Int(LogKeyEventID, eventID), slog.String(LogKeyEventName, eventName))
	all = append(all, attrs...)
	if err != nil {
		all = append(all, slog.Any(LogKeyError, err))
	}
	logger.LogAttrs(ctx, level, message(), all...)
}
