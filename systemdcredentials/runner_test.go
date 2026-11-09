package systemdcredentials

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

// The real processRunner, running this test binary as a stand-in for systemd-creds: TestMain turns
// it into the helper helperVariable names, so the pipes, exit codes, timeout and cancellation are
// those of a real process, on any OS.

const helperVariable = "HKDFGUARD_SYSTEMDCREDS_TEST_HELPER"

func TestMain(m *testing.M) {
	if mode := os.Getenv(helperVariable); mode != "" {
		os.Exit(helper(mode, os.Args[1:]))
	}
	os.Exit(m.Run())
}

// helper is what the stand-in does: echo stdin to stdout with its arguments on stderr, fail,
// hang, flood stdout, close stdout and then hang, or (on Linux) start a child that hangs.
func helper(mode string, args []string) int {
	switch mode {
	case "echo":
		fmt.Fprint(os.Stderr, strings.Join(args, " "))
		_, _ = io.Copy(os.Stdout, os.Stdin)
		return 0
	case "fail":
		fmt.Fprintln(os.Stderr, "Embedded credential name 'a' does not match filename 'b', refusing.")
		return 3
	case "hang":
		time.Sleep(time.Minute)
		return 0
	case "flood":
		_, _ = os.Stdout.Write(make([]byte, MaxLength+1))
		time.Sleep(time.Minute)
		return 0
	case "env":
		fmt.Fprint(os.Stderr, strings.Join(os.Environ(), "\n"))
		return 0
	case "flood-stderr":
		_, _ = os.Stderr.Write(bytes.Repeat([]byte("e"), 64*1024))
		return 4
	case "close-and-hang":
		_ = os.Stdout.Close()
		time.Sleep(time.Minute)
		return 0
	case "spawn":
		return spawnHangingChild()
	}
	return 99
}

func runHelper(t *testing.T, ctx context.Context, mode string, stdin []byte, timeout time.Duration) (runResult, error) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// The child inherits nothing, so the helper's own settings are handed to it explicitly.
	extra := []string{helperVariable + "=" + mode}
	for _, variable := range os.Environ() {
		if strings.HasPrefix(variable, "HKDFGUARD_SYSTEMDCREDS_TEST_") && !strings.HasPrefix(variable, helperVariable+"=") {
			extra = append(extra, variable)
		}
	}
	return processRunner{extraEnv: extra}.run(ctx, executable, []string{"--name=item", "decrypt"}, stdin, timeout)
}

// systemd-creds is given the system PATH and nothing of this process's environment: a variable set
// for the application - a secret, or one systemd-creds reads - never reaches it.
func TestTheProcess_InheritsNoEnvironment(t *testing.T) {
	t.Setenv("SYSTEMD_CREDENTIAL_SECRET", "/tmp/another-host-key")
	t.Setenv("HKDFGUARD_UNRELATED_SECRET", "s3cret")

	result, err := runHelper(t, context.Background(), "env", nil, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer result.output.Close()
	environment := strings.Split(result.stderr, "\n")
	for _, leaked := range []string{"SYSTEMD_CREDENTIAL_SECRET=", "HKDFGUARD_UNRELATED_SECRET="} {
		for _, variable := range environment {
			if strings.HasPrefix(variable, leaked) {
				t.Errorf("the child was given %s", variable)
			}
		}
	}
	if !slices.Contains(environment, childPath) {
		t.Errorf("the child's environment %q lacks %s", environment, childPath)
	}
}

// A process that floods its standard error leaves only maxStderr bytes of it in the error, marked
// as cut off.
func TestAFloodedStderr_IsCutToItsLimit_InTheError(t *testing.T) {
	result, err := runHelper(t, context.Background(), "flood-stderr", nil, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer result.output.Close()
	if result.exitCode != 4 || result.stderr != strings.Repeat("e", maxStderr)+truncatedStderr {
		t.Fatalf("exit %d, %d bytes of stderr", result.exitCode, len(result.stderr))
	}
	message := (&CommandError{Verb: "decrypt", ExitCode: 4, Stderr: result.stderr}).Error()
	if len(message) > maxStderr+100 {
		t.Fatalf("the error is %d bytes", len(message))
	}
}

func TestTheProcess_GetsItsArgumentsAndStdin_AndItsStdoutIsTheValue(t *testing.T) {
	stdin := bytes.Repeat([]byte("pässwörd"), 20_000) // larger than a pipe's buffer, both ways

	result, err := runHelper(t, context.Background(), "echo", stdin, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer result.output.Close()

	value, _ := result.output.Value()
	if result.exitCode != 0 || !bytes.Equal(value, stdin) || result.stderr != "--name=item decrypt" {
		t.Fatalf("exit %d, %d bytes, stderr %q", result.exitCode, len(value), result.stderr)
	}
}

func TestAFailingProcess_GivesItsExitCodeAndStderr(t *testing.T) {
	result, err := runHelper(t, context.Background(), "fail", nil, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if result.exitCode != 3 || !strings.Contains(result.stderr, "does not match") {
		t.Fatalf("exit %d, stderr %q", result.exitCode, result.stderr)
	}
}

func TestAProcessThatOutlastsTheTimeout_IsKilled(t *testing.T) {
	for _, mode := range []string{"hang", "close-and-hang"} {
		start := time.Now()
		_, err := runHelper(t, context.Background(), mode, nil, 500*time.Millisecond)
		if !errors.Is(err, ErrTimeout) || !strings.Contains(err.Error(), "didn't finish within 500ms") {
			t.Fatalf("%s: %v", mode, err)
		}
		if elapsed := time.Since(start); elapsed > 20*time.Second {
			t.Fatalf("%s: took %v", mode, elapsed)
		}
	}
}

func TestACancelledRun_IsKilled_AndReportsTheCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	if _, err := runHelper(t, ctx, "hang", nil, time.Minute); !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrTimeout) {
		t.Fatalf("got %v", err)
	}
}

func TestAnOutputOverSystemdsLimit_IsRefused_AndTheProcessKilled(t *testing.T) {
	start := time.Now()
	if _, err := runHelper(t, context.Background(), "flood", nil, time.Minute); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Fatalf("took %v", elapsed)
	}
}

func TestAProcessThatWontStart_IsReported(t *testing.T) {
	_, err := processRunner{}.run(context.Background(), string(os.PathSeparator)+"no-such-systemd-creds", nil, nil, time.Second)
	if err == nil || !strings.Contains(err.Error(), "starting") {
		t.Fatalf("got %v", err)
	}
}

func TestStderr_IsKeptUpToItsLimit(t *testing.T) {
	b := &limitedBuffer{limit: 4}
	if n, _ := b.Write([]byte("abc")); n != 3 {
		t.Fatal(n)
	}
	_, _ = b.Write([]byte("def"))
	if b.String() != "abcd"+truncatedStderr {
		t.Fatal(b.String())
	}
	exact := &limitedBuffer{limit: 3}
	_, _ = exact.Write([]byte("abc"))
	if exact.String() != "abc" {
		t.Fatalf("%q: nothing was discarded", exact.String())
	}
}
