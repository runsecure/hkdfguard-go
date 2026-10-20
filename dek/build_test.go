package dek

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/runsecure/hkdfguard-go"
)

func writeKeyFile(t *testing.T, contents []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "key.bin")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func baseConfig(f *recordingFactory) Config {
	return Config{KeyWrapper: nopKeyWrapper{}, CryptoProviderFactory: f, KeyRefreshInterval: time.Minute}
}

func mustBuild(t *testing.T, config Config) *KeyRing {
	t.Helper()
	ring, err := Build(bg, config)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	t.Cleanup(func() { _ = ring.Close() })
	return ring
}

func TestBuild_RefusesAnIncompleteOrOutOfRangeConfig(t *testing.T) {
	f := &recordingFactory{t: t}
	valid := baseConfig(f)
	valid.EphemeralKeys = []int{1}

	cases := map[string]func(*Config){
		"no key wrapper":          func(c *Config) { c.KeyWrapper = nil },
		"no factory":              func(c *Config) { c.CryptoProviderFactory = nil },
		"no keys":                 func(c *Config) { c.EphemeralKeys = nil },
		"no refresh interval":     func(c *Config) { c.KeyRefreshInterval = 0 },
		"refresh interval > 300s": func(c *Config) { c.KeyRefreshInterval = 301 * time.Second },
		"rotation < 1h":           func(c *Config) { c.EphemeralKeyRotation = 59 * time.Minute },
		"retention < 1m":          func(c *Config) { c.EphemeralKeyRetention = 59 * time.Second },
	}
	for name, mutate := range cases {
		config := valid
		mutate(&config)
		if _, err := Build(bg, config); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s: %v", name, err)
		}
	}

	badName := valid
	badName.ServiceName = "my..service"
	if _, err := Build(bg, badName); !errors.Is(err, hkdfguard.ErrInvalidServiceName) {
		t.Errorf("bad service name: %v", err)
	}
	badPolicy := valid
	badPolicy.RefreshFailurePolicy = hkdfguard.FailClosedAfter(0)
	if _, err := Build(bg, badPolicy); !errors.Is(err, hkdfguard.ErrInvalidRefreshFailurePolicy) {
		t.Errorf("bad policy: %v", err)
	}
	if len(f.providers()) != 0 {
		t.Error("an invalid config created providers")
	}
}

func TestBuild_RegistersKeyFilesAndEphemeralKeys_TheHighestBeingCurrent(t *testing.T) {
	f := &recordingFactory{t: t}
	config := baseConfig(f)
	config.KeyFiles = map[int]string{1: writeKeyFile(t, []byte("wrapped one")), 3: writeKeyFile(t, []byte("wrapped three"))}
	config.EphemeralKeys = []int{5}
	config.RefreshFailurePolicy = hkdfguard.FailClosedAfter(4)

	ring := mustBuild(t, config)

	requireCurrent(t, ring, 5)
	for _, version := range []int{1, 3, 5} {
		if _, ok := ring.TryGet(bg, version); !ok {
			t.Errorf("version %d is not registered", version)
		}
	}
	if len(f.wrapped) != 2 || string(f.wrapped[0]) != "wrapped one" || string(f.wrapped[1]) != "wrapped three" || f.ephemerals != 1 {
		t.Errorf("factory saw %q and %d ephemeral", f.wrapped, f.ephemerals)
	}
	for i := range f.expiries {
		if limit, _ := f.policies[i].MaxFailures(); f.expiries[i] != time.Minute || limit != 4 {
			t.Errorf("provider %d got %v and %v", i, f.expiries[i], f.policies[i])
		}
	}

	protector, _ := ring.CreateProtector("built")
	if got, err := unprotect(protector, protect(t, protector, "hello")); err != nil || got != "hello" {
		t.Errorf("%q, %v", got, err)
	}
}

func TestBuild_UsesTheConfiguredFormatProvider(t *testing.T) {
	f := &recordingFactory{t: t}
	config := baseConfig(f)
	config.EphemeralKeys = []int{1}
	custom, _ := NewDefaultFormatProviderWithLimit(17)
	config.FormatProvider = custom

	protector, _ := mustBuild(t, config).CreateProtector("custom")

	if _, err := protector.Encrypt(bg, []byte("too long for 17 characters")); !errors.Is(err, ErrInvalidFormat) {
		t.Errorf("error = %v", err)
	}
}

func TestBuild_FailingPartway_ClosesEveryKeyItCreated(t *testing.T) {
	cases := map[string]func(*Config){
		"a version registered twice": func(c *Config) {
			c.KeyFiles = map[int]string{1: writeKeyFile(t, []byte("wrapped"))}
			c.EphemeralKeys = []int{2, 1}
		},
		"an unreadable key file": func(c *Config) {
			c.EphemeralKeys = []int{2}
			c.KeyFiles = map[int]string{1: writeKeyFile(t, []byte("wrapped")), 3: filepath.Join(t.TempDir(), "missing")}
		},
	}
	for name, mutate := range cases {
		f := &recordingFactory{t: t}
		config := baseConfig(f)
		mutate(&config)

		if _, err := Build(bg, config); err == nil {
			t.Fatalf("%s: Build succeeded", name)
		}
		for i, p := range f.providers() {
			if p.closes() != 1 {
				t.Errorf("%s: provider %d closed %d times", name, i, p.closes())
			}
		}
	}
}

func TestBuild_WhenCancelled_CreatesNothing(t *testing.T) {
	f := &recordingFactory{t: t}
	config := baseConfig(f)
	config.KeyFiles = map[int]string{1: writeKeyFile(t, []byte("wrapped"))}
	config.EphemeralKeys = []int{2}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := Build(ctx, config); !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v", err)
	}
	if len(f.providers()) != 0 {
		t.Error("a cancelled Build created providers")
	}
}

// keyFileReadingWrapper is a KeyWrapper that reads its own key files (hkdfguard.KeyFileReader).
type keyFileReadingWrapper struct {
	nopKeyWrapper
	paths    []string
	contents map[string][]byte
	err      error
}

func (w *keyFileReadingWrapper) ReadKeyFile(_ context.Context, path string) ([]byte, error) {
	w.paths = append(w.paths, path)
	if w.err != nil {
		return nil, w.err
	}
	return w.contents[path], nil
}

func TestBuild_ReadsEachKeyFileThroughAWrapperThatReadsItsOwn(t *testing.T) {
	f := &recordingFactory{t: t}
	config := baseConfig(f)
	// Paths that don't exist: only the wrapper can produce their bytes.
	wrapper := &keyFileReadingWrapper{contents: map[string][]byte{"/keys/one": []byte("from the wrapper one"), "/keys/two": []byte("from the wrapper two")}}
	config.KeyWrapper = wrapper
	config.KeyFiles = map[int]string{1: "/keys/one", 2: "/keys/two"}

	ring := mustBuild(t, config)

	requireCurrent(t, ring, 2)
	if len(wrapper.paths) != 2 || wrapper.paths[0] != "/keys/one" || wrapper.paths[1] != "/keys/two" {
		t.Errorf("the wrapper was asked for %v", wrapper.paths)
	}
	if len(f.wrapped) != 2 || string(f.wrapped[0]) != "from the wrapper one" || string(f.wrapped[1]) != "from the wrapper two" {
		t.Errorf("factory saw %q", f.wrapped)
	}
}

func TestBuild_AKeyFileTheWrapperRefuses_FailsTheBuild_WithTheWrappersError(t *testing.T) {
	f := &recordingFactory{t: t}
	config := baseConfig(f)
	refusal := fmt.Errorf("%w: refused by the native library", ErrInvalidKeyFile)
	config.KeyWrapper = &keyFileReadingWrapper{err: refusal}
	config.KeyFiles = map[int]string{1: writeKeyFile(t, []byte("a perfectly readable file"))}
	config.EphemeralKeys = []int{2}

	_, err := Build(bg, config)

	if !errors.Is(err, refusal) || !errors.Is(err, hkdfguard.ErrInvalidKeyFile) {
		t.Errorf("error = %v; want the wrapper's refusal", err)
	}
	if len(f.wrapped) != 0 {
		t.Error("a refused key file reached the factory")
	}
}

func TestBuild_WithAWrapperThatDoesNotReadKeyFiles_ReadsThemItself(t *testing.T) {
	// nopKeyWrapper doesn't implement hkdfguard.KeyFileReader.
	if _, ok := any(nopKeyWrapper{}).(hkdfguard.KeyFileReader); ok {
		t.Fatal("nopKeyWrapper reads key files")
	}
	f := &recordingFactory{t: t}
	config := baseConfig(f)
	config.KeyFiles = map[int]string{1: writeKeyFile(t, nil)}

	if _, err := Build(bg, config); !errors.Is(err, ErrInvalidKeyFile) {
		t.Errorf("an empty key file: %v; want ErrInvalidKeyFile", err)
	}
	if ErrInvalidKeyFile != hkdfguard.ErrInvalidKeyFile {
		t.Error("dek.ErrInvalidKeyFile is not hkdfguard.ErrInvalidKeyFile")
	}
}
