package configurationresolver

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// The port of .NET's ValueProviderBaseScenarioTests, and of ProviderScenarioTests' sizing test
// over a map-backed ValueProviderBase in place of DictionaryValueProvider.

// scriptedRemoved, as a scripted read, reports the key not found.
const scriptedRemoved = "\x00removed"

// scriptedByteSource is a ByteValueProvider whose reported sizes and actual contents are scripted
// per call: the port of ScriptedBytesProvider. A count below zero is a key not found.
type scriptedByteSource struct {
	counts     []int
	reads      []string
	countCalls int
	readCalls  int
}

var _ ByteValueProvider = (*scriptedByteSource)(nil)

func newFixedScriptedSource(value string) *scriptedByteSource {
	n := len(value)
	return &scriptedByteSource{counts: []int{n, n, n, n}, reads: []string{value, value, value, value}}
}

func (s *scriptedByteSource) TryGetBytes(_ context.Context, _ string, destination []byte) (int, ValueStatus, error) {
	value := s.reads[s.readCalls]
	s.readCalls++
	if value == scriptedRemoved {
		return 0, NotFound, nil
	}
	if len(value) > len(destination) {
		return 0, DestinationTooSmall, nil
	}
	return copy(destination, value), Found, nil
}

func (s *scriptedByteSource) TryGetByteCount(context.Context, string) (int, bool, error) {
	count := s.counts[s.countCalls%len(s.counts)]
	s.countCalls++
	if count < 0 {
		return 0, false, nil
	}
	return count, true, nil
}

func TestBytesSource_IsReadAsString(t *testing.T) {
	for _, value := range []string{"café", "", strings.Repeat("x", 600)} {
		provider := ValueProviderBase{ByteValueProvider: newFixedScriptedSource(value)}

		got, status, err := provider.TryGetValue(context.Background(), "Key")

		if got != value || status != Found || err != nil {
			t.Errorf("TryGetValue = %q, %v, %v; want %q, Found", got, status, err, value)
		}
	}
}

func TestBytesSource_MissingKey_IsNotFound(t *testing.T) {
	source := &scriptedByteSource{counts: []int{-1, -1, -1}}
	provider := ValueProviderBase{ByteValueProvider: source}

	value, status, err := provider.TryGetValue(context.Background(), "Key")

	if value != "" || status != NotFound || err != nil {
		t.Errorf("TryGetValue = %q, %v, %v; want \"\", NotFound", value, status, err)
	}
	if source.readCalls != 0 {
		t.Errorf("read %d times, want 0", source.readCalls)
	}
}

func TestBytesSource_RemovedBetweenSizingAndReading_IsNotFound(t *testing.T) {
	provider := ValueProviderBase{ByteValueProvider: &scriptedByteSource{counts: []int{4}, reads: []string{scriptedRemoved}}}

	value, status, err := provider.TryGetValue(context.Background(), "Key")

	if value != "" || status != NotFound || err != nil {
		t.Errorf("TryGetValue = %q, %v, %v; want \"\", NotFound", value, status, err)
	}
}

func TestBytesSource_ThatChangesSize_IsReadAgain(t *testing.T) {
	tests := []struct {
		firstCount int
		second     string
	}{
		{3, "abcdef"},
		{3, strings.Repeat("y", 600)},
		{600, strings.Repeat("y", 700)},
		{600, "abcdef"},
	}
	for _, tc := range tests {
		tooLarge := strings.Repeat("z", tc.firstCount+1)
		source := &scriptedByteSource{counts: []int{tc.firstCount, len(tc.second)}, reads: []string{tooLarge, tc.second}}
		provider := ValueProviderBase{ByteValueProvider: source}

		value, status, err := provider.TryGetValue(context.Background(), "Key")

		if value != tc.second || status != Found || err != nil {
			t.Errorf("first count %d: TryGetValue = %d bytes, %v, %v; want %d bytes, Found", tc.firstCount, len(value), status, err, len(tc.second))
		}
		if source.readCalls != 2 {
			t.Errorf("first count %d: read %d times, want 2", tc.firstCount, source.readCalls)
		}
	}
}

func TestBytesSource_ThatKeepsGrowing_Fails(t *testing.T) {
	source := &scriptedByteSource{counts: []int{1, 1, 1}, reads: []string{"ab", "ab", "ab"}}
	provider := ValueProviderBase{ByteValueProvider: source}

	value, _, err := provider.TryGetValue(context.Background(), "Key")

	var keyErr *ConfigurationKeyError
	if !errors.As(err, &keyErr) {
		t.Fatalf("err = %v, want a *ConfigurationKeyError", err)
	}
	if value != "" {
		t.Errorf("value = %q, want \"\"", value)
	}
	if keyErr.Key != "Key" || keyErr.Code != KeyValueUnstable || keyErr.HasSourceIndex {
		t.Errorf("err = %+v, want Key, ValueUnstable, no source index", keyErr)
	}
	if want := "configurationresolver: the value for a configuration key could not be resolved (ValueUnstable)"; keyErr.Error() != want {
		t.Errorf("Error() = %q, want %q", keyErr.Error(), want)
	}
	if source.readCalls != 3 {
		t.Errorf("read %d times, want 3", source.readCalls)
	}
}

// requireReportedAt is the port of AssertReportedAt.
func requireReportedAt(t testing.TB, err error, provider *fakeThrowingProvider, sourceIndex int) {
	t.Helper()
	var keyErr *ConfigurationKeyError
	if !errors.As(err, &keyErr) {
		t.Fatalf("err = %v, want a *ConfigurationKeyError", err)
	}
	if keyErr.Key != "Key" || keyErr.Code != KeyValueUnstable {
		t.Errorf("err = %+v, want Key, ValueUnstable", keyErr)
	}
	if !keyErr.HasSourceIndex || keyErr.SourceIndex != sourceIndex {
		t.Errorf("SourceIndex = %d (HasSourceIndex %v), want %d", keyErr.SourceIndex, keyErr.HasSourceIndex, sourceIndex)
	}
	if strings.Contains(keyErr.Error(), "Key") {
		t.Errorf("Error() = %q holds the key", keyErr.Error())
	}
	var inner *ConfigurationKeyError
	if !errors.As(keyErr.Err, &inner) || inner.HasSourceIndex {
		t.Errorf("Err = %v, want the provider's error, without a source index", keyErr.Err)
	}
	if keyErr.Err != error(provider.err) {
		t.Errorf("Err = %v, want the provider's own error", keyErr.Err)
	}
}

func TestProviderKeyError_IsReportedAtItsPositionInTheTemplate(t *testing.T) {
	provider := &fakeThrowingProvider{err: &ConfigurationKeyError{Key: "Key", Code: KeyValueUnstable}}
	resolver := newTemplateResolver(t, NewDefaultToken(), provider, "${Key}")

	// "é " is 3 bytes.
	_, err := resolver.Resolve(context.Background(), []byte("é ${Key}"), make([]byte, 16))

	requireReportedAt(t, err, provider, 3)
}

func TestProviderKeyErrorWithAPosition_IsNotWrapped(t *testing.T) {
	provider := &fakeThrowingProvider{err: &ConfigurationKeyError{Key: "Key", Code: KeyValueUnstable, SourceIndex: 7, HasSourceIndex: true}}
	resolver := newTemplateResolver(t, NewDefaultToken(), provider, "${Key}")

	_, err := resolver.Resolve(context.Background(), []byte("${Key}"), make([]byte, 16))

	if err != error(provider.err) {
		t.Errorf("err = %v, want the provider's own error", err)
	}
}

func TestBase_SizingMethods_ReportTheRequiredBufferSize(t *testing.T) {
	provider := ValueProviderBase{ByteValueProvider: mapProvider{"Key": "café"}}
	ctx := context.Background()

	byteCount, found, err := provider.TryGetByteCount(ctx, "Key")
	if byteCount != 5 || !found || err != nil {
		t.Errorf("TryGetByteCount(Key) = %d, %v, %v; want 5, true", byteCount, found, err)
	}
	missingCount, missingFound, err := provider.TryGetByteCount(ctx, "Missing")
	if missingCount != 0 || missingFound || err != nil {
		t.Errorf("TryGetByteCount(Missing) = %d, %v, %v; want 0, false", missingCount, missingFound, err)
	}
	if value, status, err := provider.TryGetValue(ctx, "Key"); value != "café" || status != Found || err != nil {
		t.Errorf("TryGetValue(Key) = %q, %v, %v; want café, Found", value, status, err)
	}
}
