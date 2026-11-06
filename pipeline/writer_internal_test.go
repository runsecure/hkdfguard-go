package pipeline

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// What only the Writer's own code can show: the JSON's exact layout, and the stream writes'
// failures. The .NET bytes below are what its SecretPipelineWriter writes for the same secrets.

// pulledWriter is a Writer that has pulled secrets, without a store or protector.
func pulledWriter(secrets map[string]string) *Writer {
	return &Writer{protected: secrets, pulled: true}
}

func TestTheJSON_IsLaidOutAsDotNetWritesIt_ByteForByte(t *testing.T) {
	w := pulledWriter(map[string]string{
		"db-login__password": "enc::v3::AbC+/de==",
		"api-key":            "enc::v3::xYz+<&>",
		"Zeta":               "z",
	})
	nl := newLineFor(runtime.GOOS)
	want := "{" + nl +
		`  "Zeta": "z",` + nl +
		`  "api-key": "enc::v3::xYz+<&>",` + nl +
		`  "db-login__password": "enc::v3::AbC+/de=="` + nl +
		"}"

	if got := string(w.jsonSecrets()); got != want {
		t.Fatalf("wrote\n%q\nwant\n%q", got, want)
	}
	if got := string(pulledWriter(map[string]string{}).jsonSecrets()); got != "{}" {
		t.Fatalf("no secrets wrote %q; want {}", got)
	}
}

func TestTheJSON_EndsLinesAsDotNetsEnvironmentNewLine(t *testing.T) {
	if newLineFor("windows") != "\r\n" || newLineFor("linux") != "\n" || newLineFor("darwin") != "\n" {
		t.Fatal("the line endings aren't Environment.NewLine's")
	}
	if jsonNewLine != newLineFor(runtime.GOOS) {
		t.Fatal("jsonNewLine isn't this platform's")
	}
}

func TestTheJSON_EscapesOnlyWhatJSONNeeds(t *testing.T) {
	var out bytes.Buffer
	writeJSONString(&out, "a\"b\\c\nd+<>&é")
	if got := out.String(); got != `"a\"b\\c\nd+<>&é"` {
		t.Fatalf("wrote %s", got)
	}
}

// failingWriter fails its failAt'th write (from 1), or - when failAt is 0 - its flush.
type failingWriter struct {
	failAt int
	writes int
}

var errWrite = errors.New("write failed")

func (f *failingWriter) Write(b []byte) (int, error) {
	f.writes++
	if f.writes == f.failAt {
		return 0, errWrite
	}
	return len(b), nil
}

func (f *failingWriter) Flush() error {
	if f.failAt == 0 {
		return errWrite
	}
	return nil
}

func TestTheStreamWrites_ReturnAFailedWriteOrFlush(t *testing.T) {
	w := pulledWriter(map[string]string{"a": "enc::v3::a", "b": "enc::v3::b"})
	for name, try := range map[string]func(io.Writer) error{
		"tar":  func(d io.Writer) error { return w.WriteProtectedSecretFilesTo(t.Context(), d) },
		"JSON": func(d io.Writer) error { return w.WriteJSONSecretsTo(t.Context(), d) },
	} {
		// Every write a tar makes - header, value, padding, end - and the flush.
		for failAt := range 20 {
			destination := &failingWriter{failAt: failAt}
			err := try(destination)
			if failAt == 0 || failAt <= destination.writes {
				if !errors.Is(err, errWrite) {
					t.Errorf("%s, failing write %d: %v; want the write's error", name, failAt, err)
				}
			} else if err != nil {
				t.Errorf("%s, %d writes: %v", name, destination.writes, err)
			}
		}
	}
}

func TestTheStreamWrites_WriteToADestinationWithoutFlush(t *testing.T) {
	w := pulledWriter(map[string]string{"a": "enc::v3::a"})
	var archive, json bytes.Buffer
	if err := w.WriteProtectedSecretFilesTo(t.Context(), &archive); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteJSONSecretsTo(t.Context(), &json); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(json.Bytes(), w.jsonSecrets()) {
		t.Errorf("streamed %q", json.Bytes())
	}
	header, err := tar.NewReader(&archive).Next()
	if err != nil || header.Name != "a" {
		t.Fatalf("the archive holds %v, %v", header, err)
	}
	if age := time.Since(header.ModTime); age < 0 || age > time.Minute {
		t.Errorf("the file was modified %v ago; want now", age)
	}
}

func TestNoSecrets_StreamAnEmptyArchive(t *testing.T) {
	var archive bytes.Buffer
	if err := pulledWriter(map[string]string{}).WriteProtectedSecretFilesTo(t.Context(), &archive); err != nil {
		t.Fatal(err)
	}
	if _, err := tar.NewReader(&archive).Next(); err != io.EOF {
		t.Fatalf("the archive holds an entry: %v", err)
	}
}

// cancellingWriter ends ctx after its first write of anything: tar first writes no padding.
type cancellingWriter struct {
	bytes.Buffer
	cancel context.CancelFunc
}

func (c *cancellingWriter) Write(b []byte) (int, error) {
	if len(b) > 0 {
		defer c.cancel()
	}
	return c.Buffer.Write(b)
}

func TestATarStops_WhenCtxEndsPartWay(t *testing.T) {
	w := pulledWriter(map[string]string{"a": "enc::v3::a", "b": "enc::v3::b"})
	ctx, cancel := context.WithCancel(t.Context())
	destination := &cancellingWriter{cancel: cancel}

	if err := w.WriteProtectedSecretFilesTo(ctx, destination); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v; want context.Canceled", err)
	}
	if destination.Len() == 0 {
		t.Fatal("nothing was written before ctx ended")
	}
}

func TestWriteJSONSecrets_FailsAsTheFilesystemDoes(t *testing.T) {
	w := pulledWriter(map[string]string{"a": "enc::v3::a"})
	folder := t.TempDir()
	blocker := filepath.Join(folder, "file")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := w.WriteJSONSecrets(filepath.Join(blocker, "secrets.json")); err == nil {
		t.Error("a folder under a file was made")
	}
	if err := w.WriteJSONSecrets(folder); err == nil {
		t.Error("a folder was replaced by the file")
	}
}
