package systemdcredentials

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"
)

// runResult is what one systemd-creds run gave back: its exit code, its standard output as a
// Credential, and its standard error.
type runResult struct {
	exitCode int
	output   *Credential
	stderr   string
}

// runner runs systemd-creds with arguments, writing stdin to it; the tests run a fake.
type runner interface {
	run(ctx context.Context, executablePath string, arguments []string, stdin []byte, timeout time.Duration) (runResult, error)
}

// maxStderr is how much of systemd-creds' standard error is kept for a CommandError: enough for
// its message, never so much that an error - and every log it reaches - carries a flood.
const maxStderr = 1024

// truncatedStderr marks standard error cut off at maxStderr.
const truncatedStderr = " [truncated]"

// childPath is the only PATH systemd-creds is given: the system's own directories.
const childPath = "PATH=/usr/sbin:/usr/bin:/sbin:/bin"

// processRunner runs the real systemd-creds: arguments as an argument list, never through a shell;
// stdin written straight to the pipe, with no buffer of its own that couldn't be wiped; stdout read
// straight off the pipe into a Credential. If it outlasts the timeout or ctx is cancelled it is
// killed - on Linux with every process it started, as its own process group (process_linux.go).
//
// It is given a fixed environment - childPath, and nothing of this process's - so no variable set
// for the application can steer it: SYSTEMD_CREDENTIAL_SECRET pointing it at another host key,
// SYSTEMD_LOG_LEVEL making it write more than its message, LD_PRELOAD, or a secret it has no use
// for. extraEnv adds to that; only the tests set it.
type processRunner struct {
	extraEnv []string
}

func (r processRunner) run(ctx context.Context, executablePath string, arguments []string, stdin []byte, timeout time.Duration) (runResult, error) {
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, executablePath, arguments...)
	cmd.Env = append([]string{childPath}, r.extraEnv...)
	killProcessGroupOnCancel(cmd)
	// Once killed, Wait gives up on pipes a stray descendant still holds open after this long.
	cmd.WaitDelay = time.Second
	stderr := &limitedBuffer{limit: maxStderr}
	cmd.Stderr = stderr
	input, err := cmd.StdinPipe()
	if err != nil {
		return runResult{}, err
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		return runResult{}, err
	}
	if err := cmd.Start(); err != nil {
		return runResult{}, fmt.Errorf("starting %s: %w", executablePath, err)
	}

	// Written while stdout is read, so neither pipe can fill and stall the other; a process that
	// exits without reading it all ends the write with a broken pipe, which its exit code explains.
	go func() {
		if len(stdin) > 0 {
			_, _ = input.Write(stdin)
		}
		_ = input.Close()
	}()

	value, readErr := readCredential(output)
	expired := runCtx.Err() != nil // the timeout, or ctx, ended the run - not this
	if readErr != nil {
		cancel() // stop a process whose output was refused, rather than wait for it
	}
	waitErr := cmd.Wait()
	if readErr == nil && runCtx.Err() != nil {
		expired = true // it closed its output, then outlasted the timeout
	}

	if expired {
		if value != nil {
			_ = value.Close()
		}
		if ctx.Err() != nil {
			return runResult{}, ctx.Err()
		}
		return runResult{}, fmt.Errorf("%w: systemd-creds didn't finish within %v", ErrTimeout, timeout)
	}
	if readErr != nil {
		return runResult{}, readErr
	}
	var exit *exec.ExitError
	switch {
	case waitErr == nil:
		return runResult{exitCode: 0, output: value, stderr: stderr.String()}, nil
	case errors.As(waitErr, &exit) && exit.ExitCode() >= 0:
		return runResult{exitCode: exit.ExitCode(), output: value, stderr: stderr.String()}, nil
	}
	_ = value.Close()
	return runResult{}, fmt.Errorf("running %s: %w", executablePath, waitErr)
}

// limitedBuffer keeps the first limit bytes written to it, and discards the rest - saying so when
// it is read. Its buffer is a field, not embedded: an embedded bytes.Buffer's ReadFrom would be
// promoted, and io.Copy - which exec uses to fill it - would call that, keeping everything.
type limitedBuffer struct {
	kept      bytes.Buffer
	limit     int
	truncated bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	room := max(b.limit-b.kept.Len(), 0)
	b.kept.Write(p[:min(len(p), room)])
	if len(p) > room {
		b.truncated = true
	}
	return len(p), nil
}

// String is what was kept, followed by truncatedStderr when anything was discarded.
func (b *limitedBuffer) String() string {
	if b.truncated {
		return b.kept.String() + truncatedStderr
	}
	return b.kept.String()
}
