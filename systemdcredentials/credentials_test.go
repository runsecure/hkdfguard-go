package systemdcredentials

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// The port of the .NET SystemdCredentialsTests, against fakeCreds.

// fakeCreds stands in for systemd-creds: it records each run, and "encrypts" a credential into a
// file bound to its name, which it "decrypts" only under that name - as systemd-creds refuses a
// renamed one.
type fakeCreds struct {
	runs []fakeRun
	// fail, when set, makes every run fail with this exit code and stderr.
	fail *struct {
		exitCode int
		stderr   string
	}
}

type fakeRun struct {
	executable string
	arguments  []string
	stdin      []byte
	timeout    time.Duration
}

func (f *fakeCreds) run(ctx context.Context, executable string, arguments []string, stdin []byte, timeout time.Duration) (runResult, error) {
	if err := ctx.Err(); err != nil {
		return runResult{}, err
	}
	f.runs = append(f.runs, fakeRun{executable, slices.Clone(arguments), slices.Clone(stdin), timeout})
	if f.fail != nil {
		return runResult{exitCode: f.fail.exitCode, output: output(nil), stderr: f.fail.stderr}, nil
	}

	var name string
	for _, a := range arguments {
		if n, ok := strings.CutPrefix(a, "--name="); ok {
			name = n
		}
	}
	last := len(arguments) - 1
	if slices.Contains(arguments, "encrypt") {
		if arguments[last-1] != "-" {
			return runResult{}, fmt.Errorf("encrypt reads %q, not stdin", arguments[last-1])
		}
		err := os.WriteFile(arguments[last], []byte(name+":"+base64.StdEncoding.EncodeToString(stdin)), 0o600)
		return runResult{output: output(nil)}, err
	}

	if arguments[last] != "-" {
		return runResult{}, fmt.Errorf("decrypt writes %q, not stdout", arguments[last])
	}
	stored, err := os.ReadFile(arguments[last-1])
	if err != nil {
		return runResult{}, err
	}
	embedded, encoded, _ := strings.Cut(string(stored), ":")
	if embedded != name {
		return runResult{exitCode: 1, output: output(nil),
			stderr: fmt.Sprintf("Embedded credential name '%s' does not match filename '%s', refusing.\n", embedded, name)}, nil
	}
	value, _ := base64.StdEncoding.DecodeString(encoded)
	return runResult{output: output(value)}, nil
}

func output(value []byte) *Credential {
	c, err := readCredential(bytes.NewReader(value))
	if err != nil {
		panic(err)
	}
	return c
}

func newCredentials(t *testing.T, options Options, creds *fakeCreds) *Credentials {
	t.Helper()
	c, err := newWithRunner(options, creds)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func mustValue(t *testing.T, c *Credential) []byte {
	t.Helper()
	value, err := c.Value()
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestEncrypt_WritesThePlaintextToStdin_AndTheFileIsSystemdCredsOwn(t *testing.T) {
	creds := &fakeCreds{}
	path := filepath.Join(t.TempDir(), "tls-password.cred")

	if err := newCredentials(t, Options{}, creds).Encrypt(context.Background(), "tls-password", []byte("pässwörd"), path); err != nil {
		t.Fatal(err)
	}

	if len(creds.runs) != 1 {
		t.Fatalf("%d runs", len(creds.runs))
	}
	run := creds.runs[0]
	if run.executable != "/usr/bin/systemd-creds" || run.timeout != 30*time.Second ||
		!slices.Equal(run.arguments, []string{"--name=tls-password", "--with-key=auto", "encrypt", "-", path}) || string(run.stdin) != "pässwörd" {
		t.Fatalf("%+v", run)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}

func TestEncrypt_UsesTheKeyAndScopeAsked(t *testing.T) {
	for key, argument := range map[Key]string{KeyAuto: "auto", KeyHost: "host", KeyTPM2: "tpm2", KeyHostAndTPM2: "host+tpm2"} {
		creds := &fakeCreds{}
		path := filepath.Join(t.TempDir(), "item.cred")
		options := Options{Key: key, UserScope: true, ExecutablePath: "/usr/local/bin/systemd-creds", Timeout: 5 * time.Second}

		if err := newCredentials(t, options, creds).Encrypt(context.Background(), "item", []byte("v"), path); err != nil {
			t.Fatal(err)
		}

		run := creds.runs[0]
		if !slices.Equal(run.arguments, []string{"--name=item", "--with-key=" + argument, "--user", "encrypt", "-", path}) ||
			run.executable != "/usr/local/bin/systemd-creds" || run.timeout != 5*time.Second {
			t.Fatalf("%+v", run)
		}
	}
}

func TestDecrypt_ReadsTheValueFromStdout_IntoACredentialThatWipesOnClose(t *testing.T) {
	creds := &fakeCreds{}
	credentials := newCredentials(t, Options{}, creds)
	path := filepath.Join(t.TempDir(), "tls-password.cred")
	if err := credentials.Encrypt(context.Background(), "tls-password", []byte("s3cret"), path); err != nil {
		t.Fatal(err)
	}

	value, err := credentials.Decrypt(context.Background(), "tls-password", path)
	if err != nil {
		t.Fatal(err)
	}

	run := creds.runs[len(creds.runs)-1]
	if !slices.Equal(run.arguments, []string{"--name=tls-password", "--newline=no", "decrypt", path, "-"}) || len(run.stdin) != 0 {
		t.Fatalf("%+v", run)
	}
	held := mustValue(t, value)
	if string(held) != "s3cret" || value.Len() != 6 {
		t.Fatalf("%q", held)
	}

	_ = value.Close()
	_ = value.Close()
	if _, err := value.Value(); !errors.Is(err, ErrClosed) {
		t.Fatalf("reading after Close: %v", err)
	}
	if !bytes.Equal(held, make([]byte, 6)) {
		t.Fatal("Close didn't wipe the value")
	}
}

func TestDecrypt_InUserScope_AsksForIt(t *testing.T) {
	creds := &fakeCreds{}
	credentials := newCredentials(t, Options{UserScope: true}, creds)
	path := filepath.Join(t.TempDir(), "item.cred")
	_ = credentials.Encrypt(context.Background(), "item", []byte("v"), path)

	value, err := credentials.Decrypt(context.Background(), "item", path)
	if err != nil {
		t.Fatal(err)
	}
	defer value.Close()

	if run := creds.runs[len(creds.runs)-1]; !slices.Equal(run.arguments, []string{"--name=item", "--newline=no", "--user", "decrypt", path, "-"}) {
		t.Fatalf("%+v", run)
	}
}

func TestARenamedCredential_FailsToDecrypt_WithSystemdCredsMessage(t *testing.T) {
	credentials := newCredentials(t, Options{}, &fakeCreds{})
	path := filepath.Join(t.TempDir(), "tls-password.cred")
	_ = credentials.Encrypt(context.Background(), "tls-password", []byte("s3cret"), path)

	_, err := credentials.Decrypt(context.Background(), "db-password", path)

	var command *CommandError
	if !errors.As(err, &command) || !errors.Is(err, ErrCommandFailed) || command.Verb != "decrypt" || command.ExitCode != 1 {
		t.Fatalf("got %v", err)
	}
	if want := "systemd-creds decrypt failed with exit code 1: Embedded credential name 'tls-password' does not match filename 'db-password', refusing."; err.Error() != want {
		t.Fatalf("%q", err.Error())
	}
}

func TestAFailureWithoutAMessage_GivesTheExitCode(t *testing.T) {
	creds := &fakeCreds{fail: &struct {
		exitCode int
		stderr   string
	}{243, " "}}

	err := newCredentials(t, Options{}, creds).Encrypt(context.Background(), "item", []byte("v"), filepath.Join(t.TempDir(), "item.cred"))

	if err == nil || err.Error() != "systemd-creds encrypt failed with exit code 243" {
		t.Fatalf("got %v", err)
	}
}

func TestARunnerError_IsReturned(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	path := filepath.Join(t.TempDir(), "item.cred")

	if err := newCredentials(t, Options{}, &fakeCreds{}).Encrypt(ctx, "item", []byte("v"), path); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	if _, err := newCredentials(t, Options{}, &fakeCreds{}).Decrypt(ctx, "item", path); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}

func TestAnInvalidName_IsRefused_BeforeSystemdCredsRuns(t *testing.T) {
	for _, name := range []string{"", ".", "..", "-n", "a/b", "a b", "é"} {
		creds := &fakeCreds{}
		credentials := newCredentials(t, Options{}, creds)
		path := filepath.Join(t.TempDir(), "x.cred")

		if IsValidName(name) {
			t.Errorf("%q is valid", name)
		}
		if err := credentials.Encrypt(context.Background(), name, []byte("v"), path); !errors.Is(err, ErrInvalidName) || !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("%q: %v", name, err)
		}
		if _, err := credentials.Decrypt(context.Background(), name, path); !errors.Is(err, ErrInvalidName) {
			t.Errorf("%q: %v", name, err)
		}
		if len(creds.runs) != 0 {
			t.Errorf("%q ran systemd-creds", name)
		}
	}
}

func TestAValidName_HoldsLettersDigitsDotsUnderscoresAndHyphens(t *testing.T) {
	if !IsValidName("tls.pfx_password-2") || !IsValidName(strings.Repeat("a", MaxNameLength)) || IsValidName(strings.Repeat("a", MaxNameLength+1)) {
		t.Fatal("the name rule isn't systemd's")
	}
}

func TestARelativePath_IsRefused(t *testing.T) {
	credentials := newCredentials(t, Options{}, &fakeCreds{})
	for _, path := range []string{"", "relative/item.cred"} {
		if err := credentials.Encrypt(context.Background(), "item", []byte("v"), path); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("%q: %v", path, err)
		}
		if _, err := credentials.Decrypt(context.Background(), "item", path); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("%q: %v", path, err)
		}
	}
}

func TestTheOptions_AreChecked(t *testing.T) {
	for _, options := range []Options{{ExecutablePath: "systemd-creds"}, {ExecutablePath: `C:\systemd-creds`}, {Key: 9}, {Key: -1}, {Timeout: -time.Second}} {
		if _, err := newWithRunner(options, &fakeCreds{}); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("%+v: %v", options, err)
		}
	}
}

func TestThePublicConstructor_IsLinuxOnly(t *testing.T) {
	if requireLinux(true) != nil || !errors.Is(requireLinux(false), ErrUnsupportedPlatform) {
		t.Fatal("requireLinux")
	}
	_, err := New(Options{})
	if runtime.GOOS == "linux" && err != nil || runtime.GOOS != "linux" && !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("New on %s: %v", runtime.GOOS, err)
	}
}

func TestALoadedCredential_IsReadFromTheCredentialsDirectory(t *testing.T) {
	folder := t.TempDir()
	if err := os.WriteFile(filepath.Join(folder, "tls-password"), []byte("s3cret"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Mkdir(filepath.Join(folder, "a-directory"), 0o700)

	value, err := ReadLoadedCredential("tls-password", folder)
	if err != nil || value == nil {
		t.Fatalf("%v, %v", value, err)
	}
	defer value.Close()
	if string(mustValue(t, value)) != "s3cret" {
		t.Fatal("not the value")
	}
	for _, name := range []string{"absent", "a-directory"} {
		if c, err := ReadLoadedCredential(name, folder); c != nil || err != nil {
			t.Fatalf("%s: %v, %v", name, c, err)
		}
	}
	if _, err := ReadLoadedCredential("../etc", folder); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("got %v", err)
	}
}

func TestALoadedCredential_IsFoundThroughTheEnvironment(t *testing.T) {
	folder := t.TempDir()
	_ = os.WriteFile(filepath.Join(folder, "tls-password"), []byte("s3cret"), 0o600)

	t.Setenv(CredentialsDirectoryVariable, folder)
	value, err := ReadLoadedCredential("tls-password", "")
	if err != nil || value == nil {
		t.Fatalf("%v, %v", value, err)
	}
	_ = value.Close()

	t.Setenv(CredentialsDirectoryVariable, "")
	if value, err := ReadLoadedCredential("tls-password", ""); value != nil || err != nil {
		t.Fatalf("without a credentials directory: %v, %v", value, err)
	}
}

func TestAValue_GrowsAsItIsRead_UpToSystemdsLimit(t *testing.T) {
	large := make([]byte, MaxLength)
	_, _ = rand.Read(large)

	value, err := readCredential(bytes.NewReader(large))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mustValue(t, value), large) {
		t.Fatal("not the value")
	}
	_ = value.Close()

	if _, err := readCredential(bytes.NewReader(make([]byte, MaxLength+1))); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("got %v", err)
	}
}

// Each smaller buffer is wiped as the value grows out of it.
func TestAGrowingValue_WipesEachBufferItDrops(t *testing.T) {
	reader := &recordingReader{data: bytes.Repeat([]byte{0xAA}, 3*initialBufferLength)}

	value, err := readCredential(reader)
	if err != nil {
		t.Fatal(err)
	}
	defer value.Close()

	dropped := 0
	for _, read := range reader.reads {
		if arrayEnd(read.p) == arrayEnd(value.buffer) {
			continue // the buffer the value is in
		}
		dropped++
		if !bytes.Equal(read.p[:read.n], make([]byte, read.n)) {
			t.Fatal("a dropped buffer still holds the value")
		}
	}
	if dropped == 0 {
		t.Fatal("the value never grew out of a buffer")
	}
}

// recordingReader reads data out, 1000 bytes at a time, remembering each slice it filled.
type recordingReader struct {
	data  []byte
	reads []struct {
		p []byte
		n int
	}
}

func (r *recordingReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.data[:min(len(r.data), 1000)])
	r.data = r.data[n:]
	r.reads = append(r.reads, struct {
		p []byte
		n int
	}{p, n})
	return n, nil
}

// arrayEnd is the last element of the array b is a slice of: readCredential reads into
// buffer[length:], which always runs to its buffer's end.
func arrayEnd(b []byte) *byte { return &b[:cap(b)][cap(b)-1] }

func TestAFileOverSystemdsLimit_IsRefused(t *testing.T) {
	folder := t.TempDir()
	file, _ := os.Create(filepath.Join(folder, "big"))
	_ = file.Truncate(MaxLength + 1)
	_ = file.Close()

	if _, err := ReadLoadedCredential("big", folder); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("got %v", err)
	}
}

func TestAFileThatCantBeRead_IsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "write-only")
	_ = os.WriteFile(path, []byte("s3cret"), 0o600)
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	if _, err := readCredentialFrom(file); err == nil {
		t.Fatal("a write-only handle was read")
	}
}

func TestAFailingRead_WipesWhatItHad(t *testing.T) {
	reader := &failingReader{data: []byte("partial")}

	if _, err := readCredential(reader); err == nil || err.Error() != "lost" {
		t.Fatalf("got %v", err)
	}
	if !bytes.Equal(reader.buffer[:7], make([]byte, 7)) {
		t.Fatal("what was read survives")
	}
}

type failingReader struct {
	data   []byte
	buffer []byte
	read   bool
}

func (r *failingReader) Read(p []byte) (int, error) {
	if r.read {
		return 0, errors.New("lost")
	}
	r.read, r.buffer = true, p
	return copy(p, r.data), nil
}
