package aesgcm256

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/runsecure/hkdfguard-go"
)

const (
	// MaxEncryptionsPerKey is the number of encryptions after which a key refuses to encrypt
	// (decryption keeps working): half of NIST SP 800-38D's 2^32 random-nonce limit, since a
	// per-process counter can't see the other processes sharing the same key file. The count is
	// per DEK and shared by every provider in this process that reveals it; a background refresh
	// re-reveals the same key, so it does not reset the count.
	MaxEncryptionsPerKey int64 = 1 << 31

	// EncryptionWarningThreshold is the number of encryptions after which an
	// EventEncryptionBudgetWarning span event and a log warning are raised, once - one eighth of
	// the limit.
	EncryptionWarningThreshold int64 = 1 << 28
)

// encryptionBudget counts how many times one AES-256-GCM key has encrypted. With random 96-bit
// nonces, past 2^32 encryptions the chance of a repeated nonce - which breaks both
// confidentiality and integrity for everything under the key - is no longer negligible. One budget
// is shared by every session built on the same key, and, through budgetFor, by every provider in
// this process that reveals that key. Safe for concurrent use.
type encryptionBudget struct {
	warningThreshold int64
	limit            int64
	count            atomic.Int64
}

func newEncryptionBudget(warningThreshold, limit int64) (*encryptionBudget, error) {
	if limit < 1 {
		return nil, fmt.Errorf("aesgcm256: encryption limit must be positive, got %d", limit)
	}
	if warningThreshold < 1 || warningThreshold > limit {
		return nil, fmt.Errorf("aesgcm256: warning threshold must be between 1 and the limit, got %d", warningThreshold)
	}
	return &encryptionBudget{warningThreshold: warningThreshold, limit: limit}, nil
}

func defaultBudget() *encryptionBudget {
	return &encryptionBudget{warningThreshold: EncryptionWarningThreshold, limit: MaxEncryptionsPerKey}
}

// consume reserves one encryption. It reports true exactly once, for the reservation that reaches
// the warning threshold, so the caller can raise a single warning; past the limit it fails with
// hkdfguard.ErrEncryptionLimitReached.
func (b *encryptionBudget) consume() (warn bool, err error) {
	count := b.count.Add(1)
	if count > b.limit {
		b.count.Add(-1)
		return false, fmt.Errorf("%w: this key has reached its AES-GCM encryption limit of %d and must be rotated; decryption still works", hkdfguard.ErrEncryptionLimitReached, b.limit)
	}
	return count == b.warningThreshold, nil
}

// Budgets by key, for the life of the process: one small entry per distinct DEK revealed. Indexed
// by an HMAC under a key generated for this process, never by the DEK or a plain hash of it - a
// plain hash would be the same in every process and on every machine, a stable fingerprint of the
// key sitting in memory.
var (
	registryKey  = newRegistryKey()
	budgetsByKey sync.Map // string -> *encryptionBudget
)

func newRegistryKey() []byte {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic("aesgcm256: no randomness for the encryption budget registry: " + err.Error())
	}
	return key
}

// budgetFor returns the budget for key, shared by every provider in this process that reveals the
// same DEK - two KeyRings built from one key file draw on one count, not two.
func budgetFor(key []byte) *encryptionBudget {
	mac := hmac.New(sha256.New, registryKey)
	mac.Write(key)
	id := string(mac.Sum(nil))

	budget, _ := budgetsByKey.LoadOrStore(id, defaultBudget())
	return budget.(*encryptionBudget)
}
