package diagnostics

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func TestCacheOperations_ReportsMeasurementsWithTheirAttributesOnTheCacheMeter(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	previous := otel.GetMeterProvider()
	otel.SetMeterProvider(provider)
	t.Cleanup(func() {
		otel.SetMeterProvider(previous)
		_ = provider.Shutdown(context.Background())
	})

	CacheOperations().Add(context.Background(), 1, metric.WithAttributes(AttrResult.String(ResultSuccess)))

	var collected metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &collected); err != nil {
		t.Fatal(err)
	}
	if len(collected.ScopeMetrics) != 1 {
		t.Fatalf("collected %d scopes, want 1", len(collected.ScopeMetrics))
	}
	scope := collected.ScopeMetrics[0]
	if scope.Scope.Name != Cache.SourceName() {
		t.Errorf("scope name = %q, want %q", scope.Scope.Name, Cache.SourceName())
	}
	if len(scope.Metrics) != 1 {
		t.Fatalf("collected %d metrics, want 1", len(scope.Metrics))
	}
	m := scope.Metrics[0]
	if m.Name != MetricCacheOperations || m.Unit != "{operation}" {
		t.Errorf("metric = %q (%q), want %q ({operation})", m.Name, m.Unit, MetricCacheOperations)
	}

	sum, ok := m.Data.(metricdata.Sum[int64])
	if !ok || len(sum.DataPoints) != 1 {
		t.Fatalf("data = %#v, want one int64 sum data point", m.Data)
	}
	point := sum.DataPoints[0]
	if result, _ := point.Attributes.Value(AttrResult); point.Value != 1 || result.AsString() != ResultSuccess {
		t.Errorf("data point = %d with %s=%q, want 1 with %q", point.Value, AttrResult, result.AsString(), ResultSuccess)
	}
}
