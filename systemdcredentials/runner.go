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

// maxStderr is how much of systemd-creds' standard error is kept for a CommandError.
const maxStderr = 64 * 1024

// processRunner runs the real systemd-creds: arguments as an argument list, never through a shell;
// stdin written straight to the pipe, with no buffer of its own that couldn't be wiped; stdout read
// straight off the pipe into a Credential. If it outlasts the timeout or ctx is cancelled it is
// killed - on Linux with every process it started, as its own process group (process_linux.go).
type processRunner struct{}

func (processRunner) run(ctx context.Context, executablePath string, arguments []string, stdin []byte, timeout time.Duration) (runResult, error) {
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, executablePath, arguments...)
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

// limitedBuffer keeps the first limit bytes written to it, and discards the rest.
type limitedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := b.limit - b.Len(); room > 0 {
		b.Buffer.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}
