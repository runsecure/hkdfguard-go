package cache

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/runsecure/hkdfguard-go"
)

// newSink returns a sink for the secret "s", and a function reading back what it was handed, by
// key ("" for the whole value).
func newSink(t *testing.T) (*SecretSink, func(key string) (string, bool)) {
	t.Helper()
	ring, _ := newRing(t, 1)
	s := &store{ring: ring}
	sink := &SecretSink{ctx: bg, store: s, secretEntry: "s", values: map[string]*hkdfguard.KeyTrackingValue{}}
	read := func(key string) (string, bool) {
		entry := "s"
		if key != "" {
			entry += "#" + escapeCase(key)
		}
		value, ok := sink.values[entry]
		if !ok {
			return "", false
		}
		s.entries.Store(matchKey(entry), value)
		result := make([]byte, len(value.Value))
		n, err := s.decrypt(bg, entry, result)
		if err != nil {
			t.Fatal(err)
		}
		return string(result[:n]), true
	}
	return sink, read
}

func TestCaptureJSONBody_TheTextValue_IsHandedOver_AndBlankedInTheBody(t *testing.T) {
	sink, read := newSink(t)
	redacted, err := CaptureJSONBody(strings.NewReader(`{"name":"s","value":"s3cret","version":"1"}`), sink, nil, "value", "")
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := read(""); got != "s3cret" {
		t.Errorf("handed over %q", got)
	}
	if string(redacted) != `{"name":"s","value":"","version":"1"}` {
		t.Errorf("redacted %s", redacted)
	}
}

func TestCaptureJSONBody_TheBase64Value_IsHandedOverDecoded_AndWhole(t *testing.T) {
	sink, read := newSink(t)
	encoded := base64.StdEncoding.EncodeToString([]byte(`{"k":"not split"}`))
	redacted, err := CaptureJSONBody(strings.NewReader(`{"SecretBinary":"`+encoded+`"}`), sink, nil, "SecretString", "SecretBinary")
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := read(""); got != `{"k":"not split"}` {
		t.Errorf("handed over %q", got)
	}
	if _, ok := read("k"); ok {
		t.Error("a binary value was split into keys")
	}
	if string(redacted) != `{"SecretBinary":""}` {
		t.Errorf("redacted %s", redacted)
	}
}

func TestCaptureJSONBody_EscapesAreUnescaped(t *testing.T) {
	sink, read := newSink(t)
	if _, err := CaptureJSONBody(strings.NewReader(`{"value":"a\"b\\c\/d\né😀\ud800x"}`), sink, nil, "value", ""); err != nil {
		t.Fatal(err)
	}
	if got, _ := read(""); got != "a\"b\\c/d\né😀�x" {
		t.Errorf("handed over %q", got)
	}
}

func TestCaptureJSONBody_AnEscapedPropertyName_StillMatches(t *testing.T) {
	sink, read := newSink(t)
	if _, err := CaptureJSONBody(strings.NewReader(`{"value":"x"}`), sink, nil, "value", ""); err != nil {
		t.Fatal(err)
	}
	if got, _ := read(""); got != "x" {
		t.Errorf("handed over %q", got)
	}
}

func TestCaptureJSONBody_ANestedPropertyOfTheSameName_IsLeftAlone(t *testing.T) {
	sink, read := newSink(t)
	redacted, err := CaptureJSONBody(strings.NewReader(`{"other":{"value":"nested"},"value":"top"}`), sink, nil, "value", "")
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := read(""); got != "top" {
		t.Errorf("handed over %q", got)
	}
	if string(redacted) != `{"other":{"value":"nested"},"value":""}` {
		t.Errorf("redacted %s", redacted)
	}
}

func TestCaptureJSONBody_NoNonEmptyStringValue_HandsNothingOver(t *testing.T) {
	for _, body := range []string{`{"other":"x"}`, `{"value":null}`, `{"value":42}`, `{"value":""}`} {
		sink, _ := newSink(t)
		redacted, err := CaptureJSONBody(strings.NewReader(body), sink, nil, "value", "")
		if err != nil || len(sink.values) != 0 || string(redacted) != body {
			t.Errorf("%s: %v, %d values, redacted %s", body, err, len(sink.values), redacted)
		}
	}
}

func TestCaptureJSONBody_EmptyDuplicates_AreBlankedAlongsideTheValue(t *testing.T) {
	sink, read := newSink(t)
	redacted, err := CaptureJSONBody(strings.NewReader(`{"value":"","value":"x","value":""}`), sink, nil, "value", "")
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := read(""); got != "x" {
		t.Errorf("handed over %q", got)
	}
	if string(redacted) != `{"value":"","value":"","value":""}` {
		t.Errorf("redacted %s", redacted)
	}
}

func TestCaptureJSONBody_ABodyThatCantBeTrusted_IsRefused_AndNothingIsHandedOver(t *testing.T) {
	for _, c := range []struct{ body, text, base64 string }{
		{`{"value":"a","value":"b"}`, "value", ""},
		{`{"SecretString":"a","SecretBinary":"Yg=="}`, "SecretString", "SecretBinary"},
		{`{"SecretBinary":"not base64!"}`, "SecretString", "SecretBinary"},
		{`["value"]`, "value", ""},
		{`{"value":"unterminated`, "value", ""},
		{``, "value", ""},
		{`{"value":"s3cr\qt"}`, "value", ""},
		{"{\"value\":\"s3cr\x01t\"}", "value", ""},
		{"{\"value\":\"s3cr\xd3t\"}", "value", ""},
		{`{"data":{"value":"a"},"data":{"value":"b"}}`, "", ""},
	} {
		sink, _ := newSink(t)
		var err error
		if c.text == "" {
			_, err = CaptureJSONBody(strings.NewReader(c.body), sink, []string{"data"}, "value", "")
		} else {
			_, err = CaptureJSONBody(strings.NewReader(c.body), sink, nil, c.text, c.base64)
		}
		if !errors.Is(err, ErrInvalidSecretData) {
			t.Errorf("%s: got %v", c.body, err)
		}
		if err != nil && (strings.Contains(err.Error(), "s3cr") || strings.Contains(err.Error(), "qt")) {
			t.Errorf("%s: the error quotes the body: %v", c.body, err)
		}
	}
}

func TestCaptureJSONBody_ABodyLargerThanTheFirstBuffer_IsReadWhole(t *testing.T) {
	sink, read := newSink(t)
	padding := strings.Repeat("x", 3*initialBodyBuffer)
	redacted, err := CaptureJSONBody(iotestOneByteAtATime(`{"pad":"`+padding+`","value":"v"}`), sink, nil, "value", "")
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := read(""); got != "v" {
		t.Errorf("handed over %q", got)
	}
	if !strings.HasSuffix(string(redacted), `"value":""}`) {
		t.Error("not redacted")
	}
}

func TestCaptureJSONBody_ABodyAtTheLimit_IsRefused(t *testing.T) {
	sink, _ := newSink(t)
	body := `{"pad":"` + strings.Repeat("x", MaxJSONBodyLength) + `"}`
	if _, err := CaptureJSONBody(strings.NewReader(body), sink, nil, "value", ""); !errors.Is(err, ErrInvalidSecretData) {
		t.Errorf("got %v", err)
	}
}

func TestCaptureJSONBody_AReadError_IsReturned(t *testing.T) {
	sink, _ := newSink(t)
	boom := errors.New("connection reset")
	if _, err := CaptureJSONBody(io.MultiReader(strings.NewReader(`{"value":"`), errReader{boom}), sink, nil, "value", ""); !errors.Is(err, boom) {
		t.Errorf("got %v", err)
	}
}

func TestCaptureJSONBody_ANestedValue_IsHandedOver_AndOnlyItIsBlanked(t *testing.T) {
	sink, read := newSink(t)
	body := `{"value":"top","data":{"value":"other"," data":{"value":"x"},"data":{"value":"nested","k":1}}}`
	redacted, err := CaptureJSONBody(strings.NewReader(body), sink, []string{"data", "data"}, "value", "")
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := read(""); got != "nested" {
		t.Errorf("handed over %q", got)
	}
	if want := strings.Replace(body, `"nested"`, `""`, 1); string(redacted) != want {
		t.Errorf("redacted %s", redacted)
	}
}

func TestCaptureJSONBody_APathLeadingToNoObject_HandsNothingOver(t *testing.T) {
	for _, body := range []string{`{"data":null}`, `{"data":"value"}`, `{"data":[{"value":"x"}]}`, `{"other":{"value":"x"}}`} {
		sink, _ := newSink(t)
		if _, err := CaptureJSONBody(strings.NewReader(body), sink, []string{"data"}, "value", ""); err != nil || len(sink.values) != 0 {
			t.Errorf("%s: %v, %d values", body, err, len(sink.values))
		}
	}
}

func TestCaptureJSONBody_ATextValueHoldingAJSONObject_IsHandedOverWholeAndByKey(t *testing.T) {
	sink, read := newSink(t)
	if _, err := CaptureJSONBody(strings.NewReader(`{"value":"{\"user\":\"app\",\"password\":\"p\\\"w\"}"}`), sink, nil, "value", ""); err != nil {
		t.Fatal(err)
	}
	if got, _ := read(""); got != `{"user":"app","password":"p\"w"}` {
		t.Errorf("whole: %q", got)
	}
	if got, _ := read("password"); got != `p"w` {
		t.Errorf("password: %q", got)
	}
}

func TestCaptureJSONKeys_HandsOverEveryMemberOfTheObjectAtThePath(t *testing.T) {
	sink, read := newSink(t)
	body := `{"request_id":"r","data":{"data":{"username":"app","password":"pw","port":5432,"on":false,"n":null,"o":{},"bad key":"x"},"metadata":{"version":3}}}`
	if err := CaptureJSONKeys(strings.NewReader(body), sink, []string{"data", "data"}); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{"username": "app", "password": "pw", "port": "5432", "on": "false"} {
		if got, ok := read(key); !ok || got != want {
			t.Errorf("%s: %q, %v", key, got, ok)
		}
	}
	if len(sink.values) != 4 {
		t.Errorf("%d values handed over", len(sink.values))
	}
	if _, ok := read(""); ok {
		t.Error("the whole object was handed over")
	}
}

func TestCaptureJSONKeys_WithNoKeysAtThePath_HandsNothingOver(t *testing.T) {
	for _, body := range []string{`{"data":{"data":null}}`, `{"data":{"other":{"k":"v"}}}`, `{"data":{"data":{}}}`} {
		sink, _ := newSink(t)
		if err := CaptureJSONKeys(strings.NewReader(body), sink, []string{"data", "data"}); err != nil || len(sink.values) != 0 {
			t.Errorf("%s: %v, %d values", body, err, len(sink.values))
		}
	}
}

func TestCaptureJSONKeys_RefusesABodyThatCantBeTrusted(t *testing.T) {
	for _, body := range []string{`{"data":{"k":"a"},"data":{"k":"b"}}`, `{"data":{"k":"a","k":"b"}}`, `{"data":{"k":"a",}}`, `["data"]`} {
		sink, _ := newSink(t)
		if err := CaptureJSONKeys(strings.NewReader(body), sink, []string{"data"}); !errors.Is(err, ErrInvalidSecretData) {
			t.Errorf("%s: got %v", body, err)
		}
	}
}

func TestCapture_ChecksItsArguments(t *testing.T) {
	sink, _ := newSink(t)
	if _, err := CaptureJSONBody(strings.NewReader(`{}`), sink, nil, "", ""); err == nil {
		t.Error("no text property was accepted")
	}
	if err := CaptureJSONKeys(strings.NewReader(`{}`), sink, []string{"data", ""}); err == nil {
		t.Error("an empty path name was accepted")
	}
	if err := CaptureJSONKeys(nil, sink, nil); err == nil {
		t.Error("no body was accepted")
	}
	if err := CaptureJSONKeys(strings.NewReader(`{}`), nil, nil); err == nil {
		t.Error("no sink was accepted")
	}
}

func TestSetBytesWithJSONKeys_AValueThatIsntOneJSONObject_IsCachedWholeOnly(t *testing.T) {
	for _, value := range []string{"plain text", `["a","b"]`, `"a json string"`, "42", `{"k":"unterminated`,
		`{"k":"v"} trailing`, `{"k":"v"}{"k":"w"}`, "{\"k\":\"v\", // a comment\n\"j\":\"w\"}"} {
		sink, read := newSink(t)
		if err := sink.SetBytesWithJSONKeys([]byte(value)); err != nil {
			t.Fatalf("%s: %v", value, err)
		}
		if got, _ := read(""); got != value || len(sink.values) != 1 {
			t.Errorf("%s: got %q and %d values", value, got, len(sink.values))
		}
	}
}

func TestSetBytesWithJSONKeys_AJSONObjectWithWhitespaceAround_IsSplit(t *testing.T) {
	sink, read := newSink(t)
	if err := sink.SetBytesWithJSONKeys([]byte(" \n{ \"k\" : \"v\" }\t")); err != nil {
		t.Fatal(err)
	}
	if got, _ := read("k"); got != "v" {
		t.Errorf("got %q", got)
	}
}

func TestSetBytesWithJSONKeys_ADuplicatedKey_IsRefused_AndZeroed(t *testing.T) {
	sink, _ := newSink(t)
	value := []byte(`{"k":"a","k":"b"}`)
	if err := sink.SetBytesWithJSONKeys(value); !errors.Is(err, ErrInvalidSecretData) {
		t.Errorf("got %v", err)
	}
	if !hkdfguard.IsZero(value) {
		t.Error("the value was not zeroed")
	}
}

func TestSetBytesWithJSONKeys_AnEmptyValue_IsMissing(t *testing.T) {
	sink, _ := newSink(t)
	if err := sink.SetBytesWithJSONKeys(nil); err != nil || len(sink.values) != 0 {
		t.Errorf("%v, %d values", err, len(sink.values))
	}
}

// iotestOneByteAtATime reads s back one byte per Read, as a slow network would deliver it.
func iotestOneByteAtATime(s string) io.Reader { return &oneByte{r: bytes.NewReader([]byte(s))} }

type oneByte struct{ r *bytes.Reader }

func (o *oneByte) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return o.r.Read(p[:1])
}

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }
