package diagnostics

import "go.opentelemetry.io/otel/attribute"

// Span (operation) names, grouped per component - lowercase, dot-separated (OpenTelemetry
// semantic-convention style: hkdfguard.<component>.<operation>). The values are identical to the
// .NET port's ActivityNames, so every language port reports the same span names.
const (
	SpanCacheAdd         = "hkdfguard.cache.add"
	SpanCacheAddOrUpdate = "hkdfguard.cache.add_or_update"
	SpanCacheDecrypt     = "hkdfguard.cache.decrypt"

	SpanDataProtectionProtectorEncrypt                    = "hkdfguard.data_protection.protector.encrypt"
	SpanDataProtectionProtectorDecrypt                    = "hkdfguard.data_protection.protector.decrypt"
	SpanDataProtectionKeyWrappedKeyEncrypt                = "hkdfguard.data_protection.key_wrapped_key.encrypt"
	SpanDataProtectionKeyWrappedKeyDecrypt                = "hkdfguard.data_protection.key_wrapped_key.decrypt"
	SpanDataProtectionEphemeralKeyInitialize              = "hkdfguard.data_protection.ephemeral_key.initialize"
	SpanDataProtectionKeyRingAdd                          = "hkdfguard.data_protection.key_ring.add"
	SpanDataProtectionKeyRingGet                          = "hkdfguard.data_protection.key_ring.get"
	SpanDataProtectionKeyRingGetCurrent                   = "hkdfguard.data_protection.key_ring.get_current"
	SpanDataProtectionKeyRingRotateEphemeral              = "hkdfguard.data_protection.key_ring.rotate_ephemeral"
	SpanDataProtectionFormatProviderFormat                = "hkdfguard.data_protection.format.format"
	SpanDataProtectionFormatProviderParse                 = "hkdfguard.data_protection.format.parse"
	SpanDataProtectionFormatProviderGetMaxDecryptedLength = "hkdfguard.data_protection.format.get_max_decrypted_length"

	SpanCryptoProviderAESGCM256Encrypt           = "hkdfguard.crypto_provider_aes_gcm256.encrypt"
	SpanCryptoProviderAESGCM256Decrypt           = "hkdfguard.crypto_provider_aes_gcm256.decrypt"
	SpanCryptoProviderAESGCM256BackgroundRefresh = "hkdfguard.crypto_provider_aes_gcm256.background_refresh"

	SpanEncryptedConfigurationDecrypt = "hkdfguard.encrypted_configuration.decrypt"
)

// Attribute keys shared across every component's spans, events, metrics, and log records -
// lowercase, dot-separated, identical to the .NET port's AttributeNames.
const (
	AttrName                 = attribute.Key("hkdfguard.name")
	AttrPlaintextLength      = attribute.Key("hkdfguard.plaintext_length")
	AttrCiphertextLength     = attribute.Key("hkdfguard.ciphertext_length")
	AttrEncryptedLength      = attribute.Key("hkdfguard.encrypted_length")
	AttrAADLength            = attribute.Key("hkdfguard.aad_length")
	AttrValueLength          = attribute.Key("hkdfguard.value_length")
	AttrKeyVersion           = attribute.Key("hkdfguard.key_version")
	AttrKeyRingBecameCurrent = attribute.Key("hkdfguard.key_ring.became_current")
	AttrOperationName        = attribute.Key("hkdfguard.operation.name")
	AttrResult               = attribute.Key("hkdfguard.result")
	AttrEncryptionCount      = attribute.Key("hkdfguard.encryption_count")
	AttrEncryptionLimit      = attribute.Key("hkdfguard.encryption_limit")
	AttrConsecutiveFailures  = attribute.Key("hkdfguard.consecutive_failures")
)

// Values for AttrResult.
const (
	ResultSuccess = "success"
	ResultError   = "error"
)

// Fixed span event names. Unlike the operation-specific Span* names, an event's own name stays
// constant regardless of which operation raised it - the operation itself is carried as the
// AttrOperationName attribute instead - so event names stay low-cardinality and stable for
// dashboards/queries.
const (
	EventSensitiveOperation = "hkdfguard.sensitive_operation"

	// EventEncryptionBudgetWarning is raised once, on the encrypt span that crosses a key's
	// encryption-count warning threshold - carries AttrEncryptionCount and AttrEncryptionLimit.
	EventEncryptionBudgetWarning = "hkdfguard.encryption_budget_warning"

	// EventKeyAccessSuspended is raised on the background-refresh span whose failure reached the
	// configured consecutive-failure limit: the provider has disposed its sessions (zeroing the
	// DEK) and suspended Encrypt/Decrypt until a refresh succeeds. Carries AttrConsecutiveFailures.
	EventKeyAccessSuspended = "hkdfguard.key_access_suspended"
)

// Metric instrument names, following the same hkdfguard.<component>.<noun> convention as the
// Span* names.
const (
	MetricCacheOperations = "hkdfguard.cache.operations"
)
