//go:build linux

package nativev1

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"strings"
	"time"
)

// linuxListingTimeout bounds the dynamic linker's list run: it only maps files and reads headers.
const linuxListingTimeout = 30 * time.Second

// linuxVerifyBeforeLoading asks this process's own dynamic linker, in list mode, where it would
// find everything library pulls in, and requires each of those files to pass the path checks -
// before dlopen, so nothing that would fail them ever runs here (see linuxpolicy.go, check 4).
// initialEnvironment is /proc/self/environ's block.
func linuxVerifyBeforeLoading(library string, initialEnvironment []byte) error {
	interpreter, err := elfReadInterpreterFile("/proc/self/exe")
	if err != nil {
		return untrustedCause(err, "Could not read which dynamic linker this process runs under")
	}
	if interpreter == "" {
		return untrusted("This process has no dynamic linker (a statically linked executable), so it can't be asked what '%s' would load; refusing to load it.", library)
	}
	trustedInterpreter, err := linuxTrustedFile(interpreter)
	if err != nil {
		return untrustedCause(err, "This process's dynamic linker '%s' is not trusted, so it can't be asked what '%s' would load", interpreter, library)
	}

	output, err := linuxListDependencies(trustedInterpreter, library, linuxListingEnvironment(initialEnvironment))
	if err != nil {
		return err
	}
	paths, err := linuxParseListing(library, output)
	if err != nil {
		return err
	}
	return linuxVerifyListing(library, paths, linuxTrustedFile)
}

// linuxListDependencies runs `interpreter --list library` with exactly environment, and returns
// what it printed. A run that fails or times out refuses the load.
func linuxListDependencies(interpreter, library string, environment []string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), linuxListingTimeout)
	defer cancel()

	command := exec.CommandContext(ctx, interpreter, "--list", library)
	command.Env = environment
	if command.Env == nil {
		command.Env = []string{} // nil would mean "inherit this process's environment"
	}
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return "", untrusted("The dynamic linker did not say within %v what '%s' would load; refusing to load it.", linuxListingTimeout, library)
		}
		return "", untrustedCause(err, "The dynamic linker could not say what '%s' would load (%s)", library, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}
