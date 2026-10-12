package diagnostics

import (
	"context"
	"errors"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

// These tests set components' shared, package-level sensitive-logging flags and the global
// OpenTelemetry providers, so none of them run in parallel.

var allComponents = []*Component{Root, Cache, DataProtection, EncryptedConfiguration, CryptoProviderAESGCM256, KeyWrapping}

// useSpanRecorder installs a global TracerProvider that records every span, restoring the
// previous provider when the test ends.
func useSpanRecorder(t *testing.T) *tracetest.SpanRecorder {
	t.Helper()
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	previous := otel.GetTracerProvider()
	otel.SetTracerProvider(provider)
	t.Cleanup(func() {
		otel.SetTracerProvider(previous)
		_ = provider.Shutdown(context.Background())
	})
	return recorder
}

// withSensitiveLogging sets c's flag for the duration of the test.
func withSensitiveLogging(t *testing.T, c *Component, enabled bool) {
	t.Helper()
	original := c.SensitiveLoggingEnabled()
	c.SetSensitiveLogging(enabled)
	t.Cleanup(func() { c.SetSensitiveLogging(original) })
}

// endAndGet ends span and returns its recorded form.
func endAndGet(t *testing.T, recorder *tracetest.SpanRecorder, span trace.Span) sdktrace.ReadOnlySpan {
	t.Helper()
	span.End()
	ended := recorder.Ended()
	if len(ended) != 1 {
		t.Fatalf("recorded %d spans, want 1", len(ended))
	}
	return ended[0]
}

func attrValue(attrs []attribute.KeyValue, key attribute.Key) (attribute.Value, bool) {
	for _, kv := range attrs {
		if kv.Key == key {
			return kv.Value, true
		}
	}
	return attribute.Value{}, false
}

func TestTracerScopeNameMatchesSourceName(t *testing.T) {
	for _, c := range allComponents {
		t.Run(c.SourceName(), func(t *testing.T) {
			recorder := useSpanRecorder(t)

			_, span := c.Start(context.Background(), "test-span")
			got := endAndGet(t, recorder, span)

			if got.InstrumentationScope().Name != c.SourceName() {
				t.Errorf("scope name = %q, want %q", got.InstrumentationScope().Name, c.SourceName())
			}
		})
	}
}

func TestRecordError_WithNilSpanOrError_DoesNotPanic(t *testing.T) {
	RecordError(nil, errors.New("boom"))
	RecordError(trace.SpanFromContext(context.Background()), nil)
}

func TestRecordError_WithRecordingSpan_RecordsExceptionAndErrorStatus(t *testing.T) {
	for _, c := range allComponents {
		t.Run(c.SourceName(), func(t *testing.T) {
			recorder := useSpanRecorder(t)

			_, span := c.Start(context.Background(), "test-span")
			RecordError(span, errors.New("boom"))
			got := endAndGet(t, recorder, span)

			if got.Status().Code != codes.Error || got.Status().Description != "boom" {
				t.Errorf("status = %+v, want Error/boom", got.Status())
			}
			found := false
			for _, e := range got.Events() {
				found = found || e.Name == "exception"
			}
			if !found {
				t.Error("no exception event recorded")
			}
		})
	}
}

func TestLogSensitiveOperation_WithNilSpan_DoesNotPanic(t *testing.T) {
	for _, c := range allComponents {
		withSensitiveLogging(t, c, true)
		c.LogSensitiveOperation(nil, "test-op")
	}
}

func TestLogSensitiveOperation_WhenDisabled_DoesNotAddEvent(t *testing.T) {
	for _, c := range allComponents {
		t.Run(c.SourceName(), func(t *testing.T) {
			withSensitiveLogging(t, c, false)
			recorder := useSpanRecorder(t)

			_, span := c.Start(context.Background(), "test-span")
			c.LogSensitiveOperation(span, "test-op", attribute.String("key", "value"))
			got := endAndGet(t, recorder, span)

			if len(got.Events()) != 0 {
				t.Errorf("recorded %d events, want 0", len(got.Events()))
			}
		})
	}
}

func TestLogSensitiveOperation_WhenEnabled_AddsFixedNameEventWithOperationAndDetailAttributes(t *testing.T) {
	for _, c := range allComponents {
		t.Run(c.SourceName(), func(t *testing.T) {
			withSensitiveLogging(t, c, true)
			recorder := useSpanRecorder(t)

			_, span := c.Start(context.Background(), "test-span")
			c.LogSensitiveOperation(span, "test-op", AttrName.String("item"))
			got := endAndGet(t, recorder, span)

			if len(got.Events()) != 1 {
				t.Fatalf("recorded %d events, want 1", len(got.Events()))
			}
			event := got.Events()[0]
			if event.Name != EventSensitiveOperation {
				t.Errorf("event name = %q, want %q", event.Name, EventSensitiveOperation)
			}
			if v, _ := attrValue(event.Attributes, AttrOperationName); v.AsString() != "test-op" {
				t.Errorf("%s = %q, want test-op", AttrOperationName, v.AsString())
			}
			if v, _ := attrValue(event.Attributes, AttrName); v.AsString() != "item" {
				t.Errorf("%s = %q, want item", AttrName, v.AsString())
			}
		})
	}
}

func TestSensitiveLogging_RootSharesFlagWithCacheDataProtectionAndEncryptedConfiguration(t *testing.T) {
	withSensitiveLogging(t, Root, false)

	Root.SetSensitiveLogging(true)
	for _, c := range []*Component{Cache, DataProtection, EncryptedConfiguration} {
		if !c.SensitiveLoggingEnabled() {
			t.Errorf("%s did not see Root's flag set", c.SourceName())
		}
	}

	Cache.SetSensitiveLogging(false)
	for _, c := range []*Component{Root, DataProtection, EncryptedConfiguration} {
		if c.SensitiveLoggingEnabled() {
			t.Errorf("%s did not see Cache's flag cleared", c.SourceName())
		}
	}
}

func TestSensitiveLogging_CryptoProviderAndKeyWrapping_AreIndependentFromRootAndEachOther(t *testing.T) {
	withSensitiveLogging(t, Root, false)
	withSensitiveLogging(t, CryptoProviderAESGCM256, false)
	withSensitiveLogging(t, KeyWrapping, false)

	Root.SetSensitiveLogging(true)
	if CryptoProviderAESGCM256.SensitiveLoggingEnabled() || KeyWrapping.SensitiveLoggingEnabled() {
		t.Error("setting Root's flag changed an independent component's flag")
	}

	CryptoProviderAESGCM256.SetSensitiveLogging(true)
	if KeyWrapping.SensitiveLoggingEnabled() {
		t.Error("setting CryptoProviderAESGCM256's flag changed KeyWrapping's flag")
	}
}
