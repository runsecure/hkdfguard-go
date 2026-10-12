// Package diagnostics is the single place every HkdfGuard component's OpenTelemetry tracing,
// metrics, sensitive-logging toggle, and structured-log helpers live. It is the Go port of the
// .NET HkdfGuard.Diagnostics library; span, event, metric, and attribute names are identical
// across ports.
//
// Tracers and meters are resolved from the global OpenTelemetry providers (otel.SetTracerProvider
// and otel.SetMeterProvider) each time they are requested, so an application may install its
// providers at any point - before or after this package is first used.
package diagnostics

import (
	"context"
	"sync/atomic"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

// One Component per component in the library. Root, Cache, DataProtection, and
// EncryptedConfiguration all share one sensitive-logging flag (set any of them, all four read the
// new value); CryptoProviderAESGCM256 and KeyWrapping each keep their own, independent flag.
var (
	Root                    = newComponent("HkdfGuard", nil)
	Cache                   = newComponent("HkdfGuard.Cache", Root)
	DataProtection          = newComponent("HkdfGuard.DataEncryptionKey", Root)
	EncryptedConfiguration  = newComponent("HkdfGuard.EncryptedConfiguration", Root)
	CryptoProviderAESGCM256 = newComponent("HkdfGuard.CryptoProvider.AesGcm256", nil)
	KeyWrapping             = newComponent("HkdfGuard.KeyWrapping.V1", nil)
)

// Component is one component's telemetry surface: a Tracer and Meter sharing that component's
// instrumentation scope name, a sensitive-logging toggle, and the RecordError/LogSensitiveOperation
// helpers every operation across the library calls through.
type Component struct {
	sourceName string

	// sensitiveLogging points at this component's own flag, or at its shared flag owner's.
	sensitiveLogging *atomic.Bool
}

// newComponent creates a Component. When sharedFlagOwner is non-nil, the sensitive-logging flag
// is that owner's rather than an independent one.
func newComponent(sourceName string, sharedFlagOwner *Component) *Component {
	c := &Component{sourceName: sourceName}
	if sharedFlagOwner != nil {
		c.sensitiveLogging = sharedFlagOwner.sensitiveLogging
	} else {
		c.sensitiveLogging = new(atomic.Bool)
	}
	return c
}

// SourceName is this component's Tracer/Meter instrumentation scope name - e.g. "HkdfGuard.Cache".
func (c *Component) SourceName() string { return c.sourceName }

// Tracer returns this component's tracer from the global TracerProvider.
func (c *Component) Tracer() trace.Tracer { return otel.GetTracerProvider().Tracer(c.sourceName) }

// Meter returns this component's meter from the global MeterProvider.
func (c *Component) Meter() metric.Meter { return otel.GetMeterProvider().Meter(c.sourceName) }

// Start starts a span named spanName (one of the Span* constants) on this component's tracer.
func (c *Component) Start(ctx context.Context, spanName string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	return c.Tracer().Start(ctx, spanName, opts...)
}

// SensitiveLoggingEnabled reports whether sensitive operations emit additional debug telemetry
// (operation metadata such as buffer lengths and identifiers). Raw key, plaintext, and ciphertext
// bytes are never logged, regardless of this setting.
func (c *Component) SensitiveLoggingEnabled() bool { return c.sensitiveLogging.Load() }

// SetSensitiveLogging enables or disables sensitive-operation telemetry. Components that share a
// flag owner (Cache, DataProtection, EncryptedConfiguration share Root's) change the shared flag.
func (c *Component) SetSensitiveLogging(enabled bool) { c.sensitiveLogging.Store(enabled) }

// RecordError records err on span as an exception event and marks the span as errored. A nil
// span or nil err is a no-op.
func RecordError(span trace.Span, err error) {
	if span == nil || err == nil {
		return
	}
	span.RecordError(err)
	span.SetStatus(codes.Error, err.Error())
}

// LogSensitiveOperation adds a fixed-name (EventSensitiveOperation) event to span when sensitive
// logging is enabled, carrying operationName as AttrOperationName plus every detail. Only pass
// non-sensitive metadata (lengths, identifiers, timings) as details - never raw key, plaintext,
// or ciphertext bytes.
func (c *Component) LogSensitiveOperation(span trace.Span, operationName string, details ...attribute.KeyValue) {
	if !c.SensitiveLoggingEnabled() || span == nil || !span.IsRecording() {
		return
	}

	attrs := make([]attribute.KeyValue, 0, len(details)+1)
	attrs = append(attrs, AttrOperationName.String(operationName))
	attrs = append(attrs, details...)
	span.AddEvent(EventSensitiveOperation, trace.WithAttributes(attrs...))
}
