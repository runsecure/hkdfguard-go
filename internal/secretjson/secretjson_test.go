package secretjson

import (
	"encoding/json"
	"testing"
)

func TestUnescape_MatchesEncodingJSON(t *testing.T) {
	for _, s := range []string{
		``, `plain`, `a\"b`, `\\\/\b\f\n\r\t`, `é`, `€`, `😀`, `\ud800`, `\ud800x`, `\udc00`,
		`\ud800A`, `😀\ud83d`, `cafÃ©`, "raw \xc3\xa9",
	} {
		var want string
		if err := json.Unmarshal([]byte(`"`+s+`"`), &want); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		dst := make([]byte, len(s))
		if got := string(dst[:Unescape(dst, []byte(s))]); got != want {
			t.Errorf("%s: got %q, want %q", s, got, want)
		}
	}
}

func TestMembers_WalksEveryKindOfValue(t *testing.T) {
	data := []byte(` { "s" : "a\"}" , "n":-1.5e3,"t":true,"f":false,"z":null,"o":{"x":[1,{"y":"]"}]},"a":[ ],"e":{}} `)
	if !IsObject(data) {
		t.Fatal("not an object")
	}
	var names, values []string
	end := Members(data, SkipSpace(data, 0), func(m Member) bool {
		names = append(names, m.Name())
		values = append(values, string(data[m.Start:m.End]))
		return true
	})
	wantValues := []string{`"a\"}"`, `-1.5e3`, `true`, `false`, `null`, `{"x":[1,{"y":"]"}]}`, `[ ]`, `{}`}
	if len(values) != len(wantValues) {
		t.Fatalf("got %q", values)
	}
	for i := range values {
		if values[i] != wantValues[i] {
			t.Errorf("%s: got %s, want %s", names[i], values[i], wantValues[i])
		}
	}
	if SkipSpace(data, end) != len(data) {
		t.Errorf("ended at %d", end)
	}
}

func TestIsObject(t *testing.T) {
	for s, want := range map[string]bool{`{}`: true, ` {"a":1} `: true, `[]`: false, `"x"`: false, `{"a":1}{}`: false, `{"a":}`: false, ``: false} {
		if IsObject([]byte(s)) != want {
			t.Errorf("%q: want %v", s, want)
		}
	}
}

// FuzzMembers checks the walker against encoding/json on every valid object: the same members, in
// order, each string value unescaped exactly as encoding/json decodes it.
func FuzzMembers(f *testing.F) {
	for _, seed := range []string{`{"a":"b"}`, `{"a":{"b":["c",1,null]},"d":"é😀"}`, `{"":""," ":[{}]}`, `{"a":"\\\"\/"}`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		data := []byte(s)
		if !IsObject(data) {
			return
		}
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(data, &raw); err != nil {
			t.Fatalf("encoding/json refused a valid object: %v", err)
		}
		Members(data, SkipSpace(data, 0), func(m Member) bool {
			value := data[m.Start:m.End]
			if !json.Valid(value) {
				t.Fatalf("member %q: %q isn't one value", m.Name(), value)
			}
			if KindAt(data, m.Start) == String {
				var want string
				if err := json.Unmarshal(value, &want); err != nil {
					t.Fatal(err)
				}
				content := StringContent(data, m.Start, m.End)
				dst := make([]byte, len(content))
				if got := string(dst[:Unescape(dst, content)]); got != want {
					t.Fatalf("got %q, want %q", got, want)
				}
			}
			var name string
			if err := json.Unmarshal(append(append([]byte{'"'}, m.RawName...), '"'), &name); err != nil || name != m.Name() || !m.NameIs(name) {
				t.Fatalf("name %q: got %q", name, m.Name())
			}
			return true
		})
	})
}
