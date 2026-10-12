package diagnostics

import (
	"go.opentelemetry.io/otel/metric"
)

const (
	cacheOperationsUnit        = "{operation}"
	cacheOperationsDescription = "Number of ProtectedCache operations, tagged by operation and result."
)

// CacheOperations returns the Cache component's operations counter, on Cache.Meter(). It counts
// every ProtectedCache Add/AddOrUpdate call, tagged with AttrOperationName (which SpanCache*
// operation ran) and AttrResult (ResultSuccess or ResultError).
//
// The counter is resolved from the current global MeterProvider on each call; providers cache
// instruments by name, so repeated calls return the same instrument.
func CacheOperations() metric.Int64Counter {
	// The name, unit, and description are fixed and valid, so creation cannot fail; on the
	// off chance a provider reports an error, it still returns a usable (possibly no-op) counter.
	counter, _ := Cache.Meter().Int64Counter(
		MetricCacheOperations,
		metric.WithUnit(cacheOperationsUnit),
		metric.WithDescription(cacheOperationsDescription),
	)
	return counter
}
