package pipeline_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/pipeline"
	"github.com/runsecure/hkdfguard-go/pipeline/internal/pipelinetest"
)

// fakeStore is a store of secret values by name, as UTF-8 bytes; names are ASCII letters, digits,
// hyphens and '/'.
type fakeStore struct {
	secrets  map[string][]byte
	reads    []string
	failWith error
	closed   int
}

func newFakeStore() *fakeStore { return &fakeStore{secrets: map[string][]byte{}} }

func (f *fakeStore) IsValidName(name string) bool {
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-' || c == '/') {
			return false
		}
	}
	return true
}

func (f *fakeStore) ReadSecret(ctx context.Context, name string, secret *pipeline.Secret) error {
	f.reads = append(f.reads, name)
	if f.failWith != nil {
		return f.failWith
	}
	if value, ok := f.secrets[name]; ok {
		return secret.ProtectSecret(ctx, value)
	}
	return nil
}

func (f *fakeStore) Close() error {
	f.closed++
	return nil
}

func (f *fakeStore) set(name, value string) { f.secrets[name] = []byte(value) }

// errDown is the fake's read failure.
var errDown = errors.New("the store is down")

// contractStore is the contract's view of the fake.
type contractStore struct{ *fakeStore }

func (c contractStore) NewWriter(protector hkdfguard.PipelineDataProtector, secretNames []string) (hkdfguard.SecretPipelineWriter, error) {
	return pipeline.New(protector, secretNames, c.fakeStore, pipeline.Options{})
}
func (c contractStore) SetText(name, text string)    { c.set(name, text) }
func (c contractStore) SetKeys(name, json string)    { c.set(name, json) }
func (c contractStore) FailReads()                   { c.failWith = errDown }
func (c contractStore) IsReadFailure(err error) bool { return errors.Is(err, errDown) }
func (c contractStore) Reads() []string              { return slices.Clone(c.reads) }

// The shared writer's contract over an in-memory store.
func TestContract(t *testing.T) {
	pipelinetest.Contract(t, func(*testing.T) pipelinetest.Store { return contractStore{newFakeStore()} })
}

func newWriter(t *testing.T, store *fakeStore, protector hkdfguard.PipelineDataProtector, options pipeline.Options, names ...string) *pipeline.Writer {
	t.Helper()
	w, err := pipeline.New(protector, names, store, options)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func TestANameWithoutAKey_ReadsTheWholeValue_OrTheDefaultKeyWhenThereIsOne(t *testing.T) {
	store, protector := newFakeStore(), pipelinetest.NewProtector(t)
	store.set("app", `{"value":"s3cret"}`)
	whole := newWriter(t, store, protector, pipeline.Options{}, "app")
	byDefault := newWriter(t, store, protector, pipeline.Options{DefaultKey: "value"}, "app")

	if err := whole.PullSecrets(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := byDefault.PullSecrets(t.Context()); err != nil {
		t.Fatal(err)
	}

	if got := pipelinetest.Decrypt(t, protector, whole.ProtectedSecrets()["app"], "app"); got != `{"value":"s3cret"}` {
		t.Errorf("the whole value is %q", got)
	}
	if got := pipelinetest.Decrypt(t, protector, byDefault.ProtectedSecrets()["app"], "app"); got != "s3cret" {
		t.Errorf("the default key is %q", got)
	}
}

func TestASecretIsReadOnce_ForItsWholeValueAndItsKeys(t *testing.T) {
	store, protector := newFakeStore(), pipelinetest.NewProtector(t)
	store.set("prod/app", `{"user":"app"}`)
	w := newWriter(t, store, protector, pipeline.Options{}, "prod/app", "prod/app#user")

	if err := w.PullSecrets(t.Context()); err != nil {
		t.Fatal(err)
	}

	if !slices.Equal(store.reads, []string{"prod/app"}) {
		t.Fatalf("read %q; want prod/app once", store.reads)
	}
	secrets := w.ProtectedSecrets()
	if got := pipelinetest.Decrypt(t, protector, secrets["prod__app"], "prod__app"); got != `{"user":"app"}` {
		t.Errorf("prod__app is %q", got)
	}
	if got := pipelinetest.Decrypt(t, protector, secrets["prod__app__user"], "prod__app__user"); got != "app" {
		t.Errorf("prod__app__user is %q", got)
	}
}

func TestAValueThatIsntUTF8Text_IsRefused(t *testing.T) {
	store := newFakeStore()
	store.secrets["binary"] = []byte{0xFF, 0xFE, 0x00, 0x80}
	w := newWriter(t, store, pipelinetest.NewProtector(t), pipeline.Options{}, "binary")

	if err := w.PullSecrets(t.Context()); !errors.Is(err, pipeline.ErrInvalidSecretData) {
		t.Fatalf("PullSecrets: %v; want pipeline.ErrInvalidSecretData", err)
	}
	if len(w.ProtectedSecrets()) != 0 {
		t.Fatal("something was kept")
	}
}

func TestAWhitespaceValue_HoldsNoKeys(t *testing.T) {
	store := newFakeStore()
	store.set("blank", "   ")
	w := newWriter(t, store, pipelinetest.NewProtector(t), pipeline.Options{}, "blank#key")

	if err := w.PullSecrets(t.Context()); !errors.Is(err, pipeline.ErrSecretNotFound) {
		t.Fatalf("PullSecrets: %v; want pipeline.ErrSecretNotFound", err)
	}
}

func TestAnEndedContext_StopsThePull(t *testing.T) {
	store := newFakeStore()
	store.set("item", "s3cret")
	w := newWriter(t, store, pipelinetest.NewProtector(t), pipeline.Options{}, "item")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if err := w.PullSecrets(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("PullSecrets: %v; want context.Canceled", err)
	}
	if len(store.reads) != 0 {
		t.Fatalf("read %q after the context ended", store.reads)
	}
}

func TestProtectedSecrets_IsACopy(t *testing.T) {
	store := newFakeStore()
	store.set("item", "s3cret")
	w := newWriter(t, store, pipelinetest.NewProtector(t), pipeline.Options{}, "item")
	if err := w.PullSecrets(t.Context()); err != nil {
		t.Fatal(err)
	}

	delete(w.ProtectedSecrets(), "item")

	if _, ok := w.ProtectedSecrets()["item"]; !ok {
		t.Fatal("changing the copy changed the writer")
	}
}

func TestThroughTheInterface_ClosingClosesTheStoreOnce(t *testing.T) {
	store := newFakeStore()
	var w hkdfguard.SecretPipelineWriter = newWriter(t, store, pipelinetest.NewProtector(t), pipeline.Options{}, "app")

	_ = w.Close()
	_ = w.Close()

	if store.closed != 1 {
		t.Fatalf("the store was closed %d times; want once", store.closed)
	}
}

func TestFileName_ReplacesEachSeparator(t *testing.T) {
	for secretName, want := range map[string]string{"prod/app#password": "prod__app__password", "prod/app": "prod__app", "app": "app"} {
		if got := pipeline.FileName(secretName); got != want {
			t.Errorf("FileName(%q) = %q; want %q", secretName, got, want)
		}
	}
}

func TestNamesMappingToOneFileName_AreRefused(t *testing.T) {
	if _, err := pipeline.New(pipelinetest.NewProtector(t), []string{"a/b", "a#b"}, newFakeStore(), pipeline.Options{}); !errors.Is(err, pipeline.ErrInvalidArgument) {
		t.Fatalf("New: %v; want pipeline.ErrInvalidArgument", err)
	}
}

func TestNew_ChecksTheDefaultKeyAndTheStore(t *testing.T) {
	protector := pipelinetest.NewProtector(t)
	if _, err := pipeline.New(protector, []string{"app"}, newFakeStore(), pipeline.Options{DefaultKey: "a#b"}); !errors.Is(err, pipeline.ErrInvalidArgument) {
		t.Errorf("a default key holding '#': %v; want pipeline.ErrInvalidArgument", err)
	}
	if _, err := pipeline.New(protector, []string{"app"}, nil, pipeline.Options{}); !errors.Is(err, pipeline.ErrInvalidArgument) {
		t.Errorf("no store: %v; want pipeline.ErrInvalidArgument", err)
	}
}

// bodyStore answers every read with one response body, read with ProtectBodyKeys or
// ProtectBodyValue.
type bodyStore struct {
	body       string
	objectPath []string
	text, bin  string // ProtectBodyValue's properties; "" to read keys
}

func (bodyStore) IsValidName(string) bool { return true }

func (b bodyStore) ReadSecret(ctx context.Context, _ string, secret *pipeline.Secret) error {
	if b.text == "" {
		return secret.ProtectBodyKeys(ctx, []byte(b.body), b.objectPath)
	}
	return secret.ProtectBodyValue(ctx, []byte(b.body), b.text, b.bin)
}

func pullBody(t *testing.T, store bodyStore, names ...string) (map[string]string, error) {
	t.Helper()
	w, err := pipeline.New(pipelinetest.NewProtector(t), names, store, pipeline.Options{})
	if err != nil {
		t.Fatal(err)
	}
	err = w.PullSecrets(t.Context())
	return w.ProtectedSecrets(), err
}

func TestProtectBodyKeys_FollowsThePath(t *testing.T) {
	secrets, err := pullBody(t, bodyStore{body: `{"data":"x","x":{"data":{"k":"v"}},"data":{"data":{"k":"v"}}}`, objectPath: []string{"data", "data"}}, "s#k")
	if err != nil || len(secrets) != 1 {
		t.Fatalf("PullSecrets: %v, kept %d; want s__k", err, len(secrets))
	}

	_, err = pullBody(t, bodyStore{body: `{"data":{"metadata":{}}}`, objectPath: []string{"data", "data"}}, "s#k")
	if !errors.Is(err, pipeline.ErrSecretNotFound) {
		t.Fatalf("a path leading to no object: %v; want pipeline.ErrSecretNotFound", err)
	}
	for _, body := range []string{`[]`, ``, `{"data":`, "{\"data\":\"\xff\"}"} {
		if _, err := pullBody(t, bodyStore{body: body, objectPath: []string{"data"}}, "s#k"); !errors.Is(err, pipeline.ErrInvalidSecretData) {
			t.Errorf("%q: %v; want pipeline.ErrInvalidSecretData", body, err)
		}
	}
}

func TestProtectBodyValue_TakesTheTextProperty_AndRefusesABinaryOne(t *testing.T) {
	secrets, err := pullBody(t, bodyStore{body: `{"Name":"s","SecretString":"{\"k\":\"v\"}","SecretBinary":""}`, text: "SecretString", bin: "SecretBinary"}, "s", "s#k")
	if err != nil || len(secrets) != 2 {
		t.Fatalf("PullSecrets: %v, kept %d; want s and s__k", err, len(secrets))
	}
	for name, body := range map[string]string{
		"a binary value": `{"SecretBinary":"AQID"}`,
		"two values":     `{"SecretString":"a","SecretString":"b"}`,
		"not an object":  `["SecretString"]`,
		"malformed":      `{"SecretString":"x" `,
		"an empty body":  ``,
	} {
		if _, err := pullBody(t, bodyStore{body: body, text: "SecretString", bin: "SecretBinary"}, "s"); !errors.Is(err, pipeline.ErrInvalidSecretData) {
			t.Errorf("%s: %v; want pipeline.ErrInvalidSecretData", name, err)
		}
	}
	if _, err := pullBody(t, bodyStore{body: `{"value":5}`, text: "value"}, "s"); !errors.Is(err, pipeline.ErrSecretNotFound) {
		t.Errorf("a value that isn't a string: %v; want pipeline.ErrSecretNotFound", err)
	}
}

func TestReadBody_ReadsTheWholeBody_GrowingAsNeeded(t *testing.T) {
	body, _ := json.Marshal(map[string]string{"value": strings.Repeat("x", 100_000)})

	read, err := pipeline.ReadBody(iotest.OneByteReader(bytes.NewReader(body)))

	if err != nil || !bytes.Equal(read, body) {
		t.Fatalf("ReadBody: %d bytes, %v; want the body", len(read), err)
	}
}

func TestReadBody_RefusesABodyOfTheMaximumOrMore_OrNone(t *testing.T) {
	if _, err := pipeline.ReadBody(bytes.NewReader(make([]byte, pipeline.MaxBodyLength))); !errors.Is(err, pipeline.ErrInvalidSecretData) {
		t.Errorf("a body of the maximum: %v; want pipeline.ErrInvalidSecretData", err)
	}
	if _, err := pipeline.ReadBody(nil); !errors.Is(err, pipeline.ErrInvalidArgument) {
		t.Errorf("no body: %v; want pipeline.ErrInvalidArgument", err)
	}
	broken := errors.New("broken")
	if read, err := pipeline.ReadBody(io.MultiReader(strings.NewReader("abc"), iotest.ErrReader(broken))); !errors.Is(err, broken) || read != nil {
		t.Errorf("a failing body: %q, %v; want nil and its error", read, err)
	}
}

func TestNamesWindowsWouldOpenAsAnotherFileOrADevice_AreRefused(t *testing.T) {
	for _, names := range [][]string{{"app#v."}, {"nul"}, {"COM1"}, {"aux"}, {"app", "app#v."}} {
		if _, err := pipeline.New(pipelinetest.NewProtector(t), names, newFakeStore(), pipeline.Options{}); !errors.Is(err, pipeline.ErrInvalidArgument) {
			t.Errorf("New(%q): %v; want pipeline.ErrInvalidArgument", names, err)
		}
	}
}

func TestADeviceNameInsideALongerFileName_IsAnOrdinaryName(t *testing.T) {
	// "app#COM1" is the file app__COM1, whose stem isn't a device's.
	if _, err := pipeline.New(pipelinetest.NewProtector(t), []string{"app#COM1", "nul/app"}, newFakeStore(), pipeline.Options{}); err != nil {
		t.Errorf("New: %v", err)
	}
}
