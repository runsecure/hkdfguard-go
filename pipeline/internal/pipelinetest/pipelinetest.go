// Package pipelinetest is what every hkdfguard.SecretPipelineWriter must do, whatever its store -
// the Go port of the .NET SecretPipelineWriterContractTests. Each store's tests run Contract against
// their writer and fake, so every writer meets every scenario. Secret names here are lower-case
// letters, digits and hyphens, which every store accepts; a store's own tests cover what only it
// does.
//
// Test support only: it is internal to the pipeline modules, and nothing outside a _test.go file
// imports it.
package pipelinetest

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/cryptoprovider/aesgcm256"
	"github.com/runsecure/hkdfguard-go/dek"
	"github.com/runsecure/hkdfguard-go/pipeline"
)

// KeyVersion is the version every Protector stamps.
const KeyVersion = 3

// Store is one store's writer and its fake, fresh for each scenario.
type Store interface {
	// NewWriter is the store's writer, reading from this fake.
	NewWriter(protector hkdfguard.PipelineDataProtector, secretNames []string) (hkdfguard.SecretPipelineWriter, error)

	// SetText stores text as the value a name without a key reads.
	SetText(name, text string)

	// SetKeys stores a secret whose keys are the members of json, a JSON object - which may hold a
	// member twice.
	SetKeys(name, json string)

	// FailReads makes every later read fail as the store fails.
	FailReads()

	// IsReadFailure reports whether err is the failure FailReads causes.
	IsReadFailure(err error) bool

	// Reads is the name of every secret the store was asked for, in order.
	Reads() []string
}

// NewProtector is the only key in a pipeline - no key ring anywhere - closed when the test ends.
func NewProtector(t testing.TB) *aesgcm256.PipelineDataProtector {
	t.Helper()
	protector, err := aesgcm256.NewPipelineDataProtector(dek.NewDefaultFormatProvider(), KeyVersion)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = protector.Close() })
	return protector
}

// Decrypt is encrypted's plaintext, as encrypted for fileName.
func Decrypt(t testing.TB, protector hkdfguard.PipelineDataProtector, encrypted, fileName string) string {
	t.Helper()
	plaintext, err := TryDecrypt(protector, encrypted, fileName)
	if err != nil {
		t.Fatalf("decrypting %s: %v", fileName, err)
	}
	return plaintext
}

// TryDecrypt is Decrypt, returning its error.
func TryDecrypt(protector hkdfguard.PipelineDataProtector, encrypted, fileName string) (string, error) {
	ctx := context.Background()
	maxLength, err := protector.MaxDecryptedLength(ctx, encrypted)
	if err != nil {
		return "", err
	}
	result := make([]byte, maxLength)
	n, err := protector.Decrypt(ctx, encrypted, fileName, result)
	return string(result[:n]), err
}

// FileNames are the names of the files in folder, sorted.
func FileNames(t testing.TB, folder string) []string {
	t.Helper()
	entries, err := os.ReadDir(folder)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	slices.Sort(names)
	return names
}

// JSONMembers are the names of the members of contents, one JSON object, in the order it holds
// them, and their string values; it fails the test unless contents is exactly that object.
func JSONMembers(t testing.TB, contents []byte) ([]string, map[string]string) {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(contents))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		t.Fatalf("the JSON starts %v, %v; want an object", token, err)
	}
	var names []string
	values := map[string]string{}
	for decoder.More() {
		name, err := decoder.Token()
		if err != nil {
			t.Fatal(err)
		}
		var value string
		if err := decoder.Decode(&value); err != nil {
			t.Fatalf("%v: %v", name, err)
		}
		names = append(names, name.(string))
		values[name.(string)] = value
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		t.Fatalf("the JSON object ends %v, %v", token, err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		t.Fatalf("more follows the JSON object: %v", err)
	}
	return names, values
}

// TarEntry is one file in a tar archive.
type TarEntry struct {
	Header *tar.Header
	Value  string
}

// TarEntries are the entries of the tar archive in contents, in order.
func TarEntries(t testing.TB, contents []byte) []TarEntry {
	t.Helper()
	archive := tar.NewReader(bytes.NewReader(contents))
	var entries []TarEntry
	for {
		header, err := archive.Next()
		if err == io.EOF {
			return entries
		}
		if err != nil {
			t.Fatal(err)
		}
		value, err := io.ReadAll(archive)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, TarEntry{Header: header, Value: string(value)})
	}
}

// flushRecorder is a destination that records what is written to it, whether it was flushed, and
// whether it was closed.
type flushRecorder struct {
	bytes.Buffer
	flushed bool
	closed  bool
}

func (f *flushRecorder) Flush() error { f.flushed = true; return nil }
func (f *flushRecorder) Close() error { f.closed = true; return nil }

// scenario is one Contract test's store, protector and folder.
type scenario struct {
	t         *testing.T
	store     Store
	protector *aesgcm256.PipelineDataProtector
	folder    string // doesn't exist until a test makes it
}

func (s *scenario) writer(secretNames ...string) hkdfguard.SecretPipelineWriter {
	s.t.Helper()
	w, err := s.store.NewWriter(s.protector, secretNames)
	if err != nil {
		s.t.Fatalf("creating a writer for %q: %v", secretNames, err)
	}
	s.t.Cleanup(func() { _ = w.Close() })
	return w
}

func (s *scenario) pull(w hkdfguard.SecretPipelineWriter) {
	s.t.Helper()
	if err := w.PullSecrets(s.t.Context()); err != nil {
		s.t.Fatalf("PullSecrets: %v", err)
	}
}

func (s *scenario) decrypt(secrets map[string]string, fileName string) string {
	s.t.Helper()
	encrypted, ok := secrets[fileName]
	if !ok {
		s.t.Fatalf("no secret was kept as %s; kept %q", fileName, keys(secrets))
	}
	return Decrypt(s.t, s.protector, encrypted, fileName)
}

func keys(m map[string]string) []string {
	var names []string
	for name := range m {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// Contract runs every scenario against the writer newStore makes, a fresh store for each.
func Contract(t *testing.T, newStore func(t *testing.T) Store) {
	for _, c := range contract {
		t.Run(c.name, func(t *testing.T) {
			c.run(&scenario{t: t, store: newStore(t), protector: NewProtector(t), folder: filepath.Join(t.TempDir(), "secrets")})
		})
	}
}

var contract = []struct {
	name string
	run  func(s *scenario)
}{
	{"Pull_ReadsEachSecretOnce_AndKeepsEveryValueEncryptedForItsFileName", func(s *scenario) {
		s.store.SetKeys("db-login", `{"username":"app","password":"s3cr\"et","port":5432,"tls":true,"off":false,"unasked":"x"}`)
		s.store.SetText("api-key", "api-key-value")
		w := s.writer("db-login#username", "db-login#password", "db-login#port", "db-login#tls", "db-login#off", "api-key")

		s.pull(w)

		secrets := w.ProtectedSecrets()
		if len(secrets) != 6 {
			s.t.Fatalf("kept %q; want 6 secrets", keys(secrets))
		}
		if !strings.HasPrefix(secrets["db-login__password"], "enc::v3::") {
			s.t.Fatalf("db-login__password is %q; want enc::v3::...", secrets["db-login__password"])
		}
		for fileName, want := range map[string]string{
			"db-login__username": "app", "db-login__password": `s3cr"et`, "db-login__port": "5432",
			"db-login__tls": "true", "db-login__off": "false", "api-key": "api-key-value",
		} {
			if got := s.decrypt(secrets, fileName); got != want {
				s.t.Errorf("%s is %q; want %q", fileName, got, want)
			}
		}
		if got := s.store.Reads(); !slices.Equal(got, []string{"db-login", "api-key"}) {
			s.t.Fatalf("read %q; want each secret once, in order", got)
		}
	}},

	{"AValue_IsBoundToItsFileName", func(s *scenario) {
		s.store.SetText("item", "s3cret")
		w := s.writer("item")
		s.pull(w)

		if _, err := TryDecrypt(s.protector, w.ProtectedSecrets()["item"], "other"); !errors.Is(err, hkdfguard.ErrAuthenticationFailed) {
			s.t.Fatalf("decrypting under another name: %v; want hkdfguard.ErrAuthenticationFailed", err)
		}
	}},

	{"ALargeValue_IsProtected", func(s *scenario) {
		// Far beyond the 1 KiB the .NET port decodes on the stack, within the default format's 4096 characters.
		large := strings.Repeat("x", 2500)
		s.store.SetText("big", large)
		w := s.writer("big")

		s.pull(w)

		if s.decrypt(w.ProtectedSecrets(), "big") != large {
			s.t.Fatal("the large value didn't round-trip")
		}
	}},

	{"APullAgain_ReplacesWhatTheLastKept", func(s *scenario) {
		s.store.SetText("item", "first")
		w := s.writer("item")
		s.pull(w)
		s.store.SetText("item", "second")

		s.pull(w)

		if got := s.decrypt(w.ProtectedSecrets(), "item"); got != "second" {
			s.t.Fatalf("item is %q; want second", got)
		}
	}},

	{"MissingValues_AreAllReported_AndTheRestKept", func(s *scenario) {
		s.store.SetKeys("db-login", `{"username":"app","empty":"","nothing":null,"nested":{"a":"b"},"list":[1]}`)
		s.store.SetText("plain", "not json")
		s.store.SetText("trailing", `{"key":"v"} more`)
		s.store.SetText("array", `["key"]`)
		s.store.SetText("blank", "")
		w := s.writer("absent", "db-login#username", "db-login#password", "db-login#empty", "db-login#nothing",
			"db-login#nested", "db-login#list", "plain#key", "trailing#key", "array#key", "blank")

		err := w.PullSecrets(s.t.Context())

		var missing *pipeline.MissingSecretsError
		if !errors.Is(err, pipeline.ErrSecretNotFound) || !errors.As(err, &missing) {
			s.t.Fatalf("PullSecrets: %v; want a *pipeline.MissingSecretsError", err)
		}
		const want = "pipeline: the secret store holds no value for: absent, db-login#password, db-login#empty, db-login#nothing, " +
			"db-login#nested, db-login#list, plain#key, trailing#key, array#key, blank"
		if err.Error() != want {
			s.t.Fatalf("PullSecrets: %q;\nwant %q", err.Error(), want)
		}
		if got := keys(w.ProtectedSecrets()); !slices.Equal(got, []string{"db-login__username"}) {
			s.t.Fatalf("kept %q; want only db-login__username", got)
		}

		// What was found is still written.
		if err := w.WriteProtectedSecretFiles(s.folder); err != nil {
			s.t.Fatal(err)
		}
		if got := FileNames(s.t, s.folder); !slices.Equal(got, []string{"db-login__username"}) {
			s.t.Fatalf("wrote %q; want only db-login__username", got)
		}
	}},

	{"ASecretHoldingAKeyTwice_IsRefused", func(s *scenario) {
		s.store.SetKeys("db-login", `{"password":"a","password":"b"}`)
		w := s.writer("db-login#password")

		if err := w.PullSecrets(s.t.Context()); !errors.Is(err, pipeline.ErrInvalidSecretData) {
			s.t.Fatalf("PullSecrets: %v; want pipeline.ErrInvalidSecretData", err)
		}
		if got := w.ProtectedSecrets(); len(got) != 0 {
			s.t.Fatalf("kept %q; want nothing", keys(got))
		}
	}},

	{"AFailedRead_Propagates_AndKeepsNothing", func(s *scenario) {
		s.store.SetText("item", "s3cret")
		w := s.writer("item")
		s.pull(w)
		s.store.FailReads()

		err := w.PullSecrets(s.t.Context())

		if err == nil || !s.store.IsReadFailure(err) {
			s.t.Fatalf("PullSecrets: %v; want the store's read failure", err)
		}
		if got := w.ProtectedSecrets(); len(got) != 0 {
			s.t.Fatalf("kept %q; want nothing", keys(got))
		}
		if err := w.WriteProtectedSecretFiles(s.folder); !errors.Is(err, pipeline.ErrNotPulled) {
			s.t.Fatalf("WriteProtectedSecretFiles after a failed pull: %v; want pipeline.ErrNotPulled", err)
		}
	}},

	{"ThroughTheInterface_WritesOneFilePerSecret_AsUTF8WithoutABOM", func(s *scenario) {
		s.store.SetKeys("db-login", `{"password":"pässwörd"}`)
		s.store.SetText("api-key", "key")
		w := s.writer("db-login#password", "api-key")
		s.pull(w)

		if err := w.WriteProtectedSecretFiles(s.folder); err != nil {
			s.t.Fatal(err)
		}

		if got := FileNames(s.t, s.folder); !slices.Equal(got, []string{"api-key", "db-login__password"}) {
			s.t.Fatalf("wrote %q", got)
		}
		contents, err := os.ReadFile(filepath.Join(s.folder, "db-login__password"))
		if err != nil {
			s.t.Fatal(err)
		}
		if contents[0] == 0xEF {
			s.t.Fatal("the file starts with a byte order mark")
		}
		if got := Decrypt(s.t, s.protector, string(contents), "db-login__password"); got != "pässwörd" {
			s.t.Fatalf("the file holds %q; want pässwörd", got)
		}
	}},

	{"WriteProtectedSecretFiles_ReplacesOnlyItsOwnFiles", func(s *scenario) {
		if err := os.MkdirAll(s.folder, 0o700); err != nil {
			s.t.Fatal(err)
		}
		write := func(name, contents string) {
			if err := os.WriteFile(filepath.Join(s.folder, name), []byte(contents), 0o600); err != nil {
				s.t.Fatal(err)
			}
		}
		write("item", "old")
		write("unrelated", "untouched")
		s.store.SetText("item", "new")
		w := s.writer("item")
		s.pull(w)

		if err := w.WriteProtectedSecretFiles(s.folder); err != nil {
			s.t.Fatal(err)
		}

		item, _ := os.ReadFile(filepath.Join(s.folder, "item"))
		if got := Decrypt(s.t, s.protector, string(item), "item"); got != "new" {
			s.t.Fatalf("item holds %q; want new", got)
		}
		if unrelated, _ := os.ReadFile(filepath.Join(s.folder, "unrelated")); string(unrelated) != "untouched" {
			s.t.Fatalf("unrelated holds %q; want it untouched", unrelated)
		}
	}},

	{"WriteProtectedSecretFiles_BeforeAPull_OrWithoutAFolder_Fails", func(s *scenario) {
		w := s.writer("item")

		if err := w.WriteProtectedSecretFiles(s.folder); !errors.Is(err, pipeline.ErrNotPulled) {
			s.t.Fatalf("before a pull: %v; want pipeline.ErrNotPulled", err)
		}
		if err := w.WriteProtectedSecretFiles(""); !errors.Is(err, pipeline.ErrInvalidArgument) {
			s.t.Fatalf("without a folder: %v; want pipeline.ErrInvalidArgument", err)
		}
		if _, err := os.Stat(s.folder); !errors.Is(err, os.ErrNotExist) {
			s.t.Fatalf("the folder was made: %v", err)
		}
	}},

	{"ThroughTheInterface_WritesOneJSONObject_OfFileNamesAndValues", func(s *scenario) {
		s.store.SetKeys("db-login", `{"password":"pässwörd"}`)
		s.store.SetText("api-key", "key")
		w := s.writer("db-login#password", "api-key")
		s.pull(w)
		path := filepath.Join(s.folder, "nested", "secrets.json")

		if err := w.WriteJSONSecrets(path); err != nil {
			s.t.Fatal(err)
		}

		contents, err := os.ReadFile(path)
		if err != nil {
			s.t.Fatal(err)
		}
		if contents[0] != '{' {
			s.t.Fatalf("the file starts %q; want the object, without a byte order mark", contents[:1])
		}
		names, values := JSONMembers(s.t, contents)
		if !slices.Equal(names, []string{"api-key", "db-login__password"}) {
			s.t.Fatalf("the members are %q", names)
		}
		if values["db-login__password"] != w.ProtectedSecrets()["db-login__password"] {
			s.t.Fatal("db-login__password isn't the value kept")
		}
		if got := Decrypt(s.t, s.protector, values["db-login__password"], "db-login__password"); got != "pässwörd" {
			s.t.Fatalf("db-login__password holds %q; want pässwörd", got)
		}
		if bytes.Contains(contents, []byte(`\u`)) {
			s.t.Fatalf("the file escapes what it needn't: %s", contents)
		}
	}},

	{"WriteJSONSecrets_ReplacesTheFile_AndNeedsAPullAndAPath", func(s *scenario) {
		w := s.writer("item")
		path := filepath.Join(s.folder, "secrets.json")
		if err := w.WriteJSONSecrets(path); !errors.Is(err, pipeline.ErrNotPulled) {
			s.t.Fatalf("before a pull: %v; want pipeline.ErrNotPulled", err)
		}
		if err := w.WriteJSONSecrets(""); !errors.Is(err, pipeline.ErrInvalidArgument) {
			s.t.Fatalf("without a path: %v; want pipeline.ErrInvalidArgument", err)
		}
		if _, err := os.Stat(s.folder); !errors.Is(err, os.ErrNotExist) {
			s.t.Fatalf("the folder was made: %v", err)
		}

		if err := os.MkdirAll(s.folder, 0o700); err != nil {
			s.t.Fatal(err)
		}
		stale := `{"stale":"value","padding":"making the old file longer than the new one"}`
		if err := os.WriteFile(path, []byte(stale), 0o600); err != nil {
			s.t.Fatal(err)
		}
		s.store.SetText("item", "new")
		s.pull(w)

		if err := w.WriteJSONSecrets(path); err != nil {
			s.t.Fatal(err)
		}

		contents, _ := os.ReadFile(path)
		names, values := JSONMembers(s.t, contents)
		if !slices.Equal(names, []string{"item"}) {
			s.t.Fatalf("the members are %q; want only item", names)
		}
		if got := Decrypt(s.t, s.protector, values["item"], "item"); got != "new" {
			s.t.Fatalf("item holds %q; want new", got)
		}
	}},

	{"ThroughTheInterface_StreamsATarOfTheFiles_ThatAnyTarUnpacks", func(s *scenario) {
		s.store.SetKeys("db-login", `{"password":"pässwörd"}`)
		s.store.SetText("api-key", "key")
		w := s.writer("db-login#password", "api-key")
		s.pull(w)
		stdin := &flushRecorder{}

		if err := w.WriteProtectedSecretFilesTo(s.t.Context(), stdin); err != nil {
			s.t.Fatal(err)
		}

		if !stdin.flushed || stdin.closed {
			s.t.Fatalf("flushed %v, closed %v; want flushed and left open", stdin.flushed, stdin.closed)
		}
		entries := TarEntries(s.t, stdin.Bytes())
		var names []string
		for _, entry := range entries {
			names = append(names, entry.Header.Name)
			if entry.Header.Typeflag != tar.TypeReg || entry.Header.Mode != 0o644 || entry.Header.Format != tar.FormatPAX {
				s.t.Errorf("%s is type %c, mode %o, format %v; want a regular PAX file, mode 0644",
					entry.Header.Name, entry.Header.Typeflag, entry.Header.Mode, entry.Header.Format)
			}
		}
		if !slices.Equal(names, []string{"api-key", "db-login__password"}) {
			s.t.Fatalf("the archive holds %q", names)
		}
		if entries[1].Value != w.ProtectedSecrets()["db-login__password"] {
			s.t.Fatal("db-login__password isn't the value kept")
		}
		if got := Decrypt(s.t, s.protector, entries[1].Value, "db-login__password"); got != "pässwörd" {
			s.t.Fatalf("db-login__password holds %q; want pässwörd", got)
		}

		// The same files WriteProtectedSecretFiles writes, byte for byte.
		if err := w.WriteProtectedSecretFiles(s.folder); err != nil {
			s.t.Fatal(err)
		}
		for _, entry := range entries {
			onDisk, err := os.ReadFile(filepath.Join(s.folder, entry.Header.Name))
			if err != nil || string(onDisk) != entry.Value || entry.Header.Size != int64(len(onDisk)) {
				s.t.Errorf("%s: the archive holds %q, the file %q (%v)", entry.Header.Name, entry.Value, onDisk, err)
			}
		}
	}},

	{"ThroughTheInterface_StreamsTheJSONObject_AsTheFileHoldsIt", func(s *scenario) {
		s.store.SetText("item", "s3cret")
		w := s.writer("item")
		s.pull(w)
		stdin := &flushRecorder{}

		if err := w.WriteJSONSecretsTo(s.t.Context(), stdin); err != nil {
			s.t.Fatal(err)
		}
		path := filepath.Join(s.folder, "secrets.json")
		if err := w.WriteJSONSecrets(path); err != nil {
			s.t.Fatal(err)
		}

		if !stdin.flushed || stdin.closed {
			s.t.Fatalf("flushed %v, closed %v; want flushed and left open", stdin.flushed, stdin.closed)
		}
		if onDisk, _ := os.ReadFile(path); !bytes.Equal(onDisk, stdin.Bytes()) {
			s.t.Fatalf("streamed %q; the file holds %q", stdin.Bytes(), onDisk)
		}
		_, values := JSONMembers(s.t, stdin.Bytes())
		if got := Decrypt(s.t, s.protector, values["item"], "item"); got != "s3cret" {
			s.t.Fatalf("item holds %q; want s3cret", got)
		}
	}},

	{"TheStreamWrites_NeedAPullAStreamAndALiveContext", func(s *scenario) {
		w := s.writer("item")
		var stdin bytes.Buffer
		ended, cancel := context.WithCancel(s.t.Context())
		cancel()
		for name, try := range map[string]func() error{
			"a tar before a pull":    func() error { return w.WriteProtectedSecretFilesTo(s.t.Context(), &stdin) },
			"the JSON before a pull": func() error { return w.WriteJSONSecretsTo(s.t.Context(), &stdin) },
		} {
			if err := try(); !errors.Is(err, pipeline.ErrNotPulled) {
				s.t.Errorf("%s: %v; want pipeline.ErrNotPulled", name, err)
			}
		}
		for name, try := range map[string]func() error{
			"a tar to nothing":    func() error { return w.WriteProtectedSecretFilesTo(s.t.Context(), nil) },
			"the JSON to nothing": func() error { return w.WriteJSONSecretsTo(s.t.Context(), nil) },
		} {
			if err := try(); !errors.Is(err, pipeline.ErrInvalidArgument) {
				s.t.Errorf("%s: %v; want pipeline.ErrInvalidArgument", name, err)
			}
		}

		s.store.SetText("item", "s3cret")
		s.pull(w)
		for name, try := range map[string]func() error{
			"a tar once ctx has ended":    func() error { return w.WriteProtectedSecretFilesTo(ended, &stdin) },
			"the JSON once ctx has ended": func() error { return w.WriteJSONSecretsTo(ended, &stdin) },
		} {
			if err := try(); !errors.Is(err, context.Canceled) {
				s.t.Errorf("%s: %v; want context.Canceled", name, err)
			}
		}
		if stdin.Len() != 0 {
			s.t.Fatalf("%d bytes were written", stdin.Len())
		}
	}},

	{"AnInvalidName_IsRefused", func(s *scenario) {
		for _, secretName := range []string{"", "bad name", "#key", "db-login#", "db-login#bad key", "db-login#a:b"} {
			if _, err := s.store.NewWriter(s.protector, []string{secretName}); !errors.Is(err, pipeline.ErrInvalidArgument) {
				s.t.Errorf("%q: %v; want pipeline.ErrInvalidArgument", secretName, err)
			}
		}
	}},

	{"New_ChecksTheListAndTheProtector", func(s *scenario) {
		for name, try := range map[string]func() error{
			"no protector":            func() error { _, err := s.store.NewWriter(nil, []string{"item"}); return err },
			"no names":                func() error { _, err := s.store.NewWriter(s.protector, nil); return err },
			"an empty list":           func() error { _, err := s.store.NewWriter(s.protector, []string{}); return err },
			"an empty name":           func() error { _, err := s.store.NewWriter(s.protector, []string{""}); return err },
			"names differing in case": func() error { _, err := s.store.NewWriter(s.protector, []string{"item", "ITEM"}); return err },
			"a name twice":            func() error { _, err := s.store.NewWriter(s.protector, []string{"item", "item"}); return err },
		} {
			if err := try(); !errors.Is(err, pipeline.ErrInvalidArgument) {
				s.t.Errorf("%s: %v; want pipeline.ErrInvalidArgument", name, err)
			}
		}
	}},

	{"TheListIsCopied", func(s *scenario) {
		s.store.SetText("item", "s3cret")
		s.store.SetText("other", "s3cret")
		names := []string{"item", "x"}
		w, err := s.store.NewWriter(s.protector, names[:1])
		if err != nil {
			s.t.Fatal(err)
		}
		defer func() { _ = w.Close() }()
		names[0] = "other"

		s.pull(w)

		if got := keys(w.ProtectedSecrets()); !slices.Equal(got, []string{"item"}) {
			s.t.Fatalf("kept %q; want only item", got)
		}
	}},
}
