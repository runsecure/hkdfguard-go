package systemdcredentials

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// CredentialsDirectoryVariable is the environment variable systemd names a service's credentials
// directory in.
const CredentialsDirectoryVariable = "CREDENTIALS_DIRECTORY"

// MaxNameLength is the longest credential name.
const MaxNameLength = 255

// Credentials encrypts and decrypts Linux credentials with systemd-creds, which binds each to this
// machine's host key, its TPM, or both (Options.Key), and to its name: a credential renamed fails
// to decrypt. Safe for concurrent use.
type Credentials struct {
	executablePath string
	key            string
	userScope      bool
	timeout        time.Duration
	runner         runner
}

// New returns Credentials that run systemd-creds as options say. It fails with
// ErrUnsupportedPlatform anywhere but Linux, and with ErrInvalidArgument for an executable path
// that isn't absolute, a Key that isn't one, or a negative timeout.
func New(options Options) (*Credentials, error) {
	if err := requireLinux(runtime.GOOS == "linux"); err != nil {
		return nil, err
	}
	return newWithRunner(options, processRunner{})
}

func requireLinux(isLinux bool) error {
	if !isLinux {
		return ErrUnsupportedPlatform
	}
	return nil
}

// newWithRunner runs systemd-creds through runner, on any OS, for tests.
func newWithRunner(options Options, runner runner) (*Credentials, error) {
	path := options.ExecutablePath
	if path == "" {
		path = DefaultExecutablePath
	}
	if path[0] != '/' {
		return nil, fmt.Errorf("%w: the systemd-creds path must be absolute, not '%s'", ErrInvalidArgument, options.ExecutablePath)
	}
	key, ok := options.Key.argument()
	if !ok {
		return nil, fmt.Errorf("%w: the key must be KeyAuto, KeyHost, KeyTPM2 or KeyHostAndTPM2, not %d", ErrInvalidArgument, options.Key)
	}
	timeout := options.Timeout
	switch {
	case timeout == 0:
		timeout = DefaultTimeout
	case timeout < 0:
		return nil, fmt.Errorf("%w: the timeout must be positive, not %v", ErrInvalidArgument, options.Timeout)
	}
	return &Credentials{executablePath: path, key: key, userScope: options.UserScope, timeout: timeout, runner: runner}, nil
}

// IsValidName reports whether name can be a credential's name: 1-MaxNameLength ASCII letters,
// digits, '.', '_' and '-', not "." or "..", and not starting with '-', so it is always a file name
// and never an option.
func IsValidName(name string) bool {
	if name == "" || len(name) > MaxNameLength || name == "." || name == ".." || name[0] == '-' {
		return false
	}
	for i := range len(name) {
		c := name[i]
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// Encrypt encrypts plaintext as the credential name, written to outputPath - systemd-creds encrypt
// --name=name - with the plaintext on its standard input, never a file or its command line.
// plaintext is the caller's, and isn't wiped. It fails with ErrInvalidName or ErrInvalidArgument
// before anything runs, with a *CommandError when systemd-creds fails, and with ErrTimeout when it
// doesn't finish in time; ctx cancels the run, killing it.
func (c *Credentials) Encrypt(ctx context.Context, name string, plaintext []byte, outputPath string) error {
	if err := checkName(name); err != nil {
		return err
	}
	if err := checkPath(outputPath); err != nil {
		return err
	}
	arguments := []string{"--name=" + name, "--with-key=" + c.key}
	if c.userScope {
		arguments = append(arguments, "--user")
	}
	arguments = append(arguments, "encrypt", "-", outputPath)

	// Encrypting writes to outputPath, not stdout: there is nothing to keep.
	output, err := c.run(ctx, "encrypt", arguments, plaintext)
	if err != nil {
		return err
	}
	return output.Close()
}

// Decrypt decrypts the credential name from inputPath - systemd-creds decrypt --name=name -
// reading the value straight from its standard output into a Credential. A credential encrypted
// under another name fails, as does one encrypted on another machine. Close the Credential once
// used, which wipes it.
//
// Decrypting a system credential directly needs what encrypting it used: root, for the host key,
// and access to the TPM for a TPM-bound one. An unprivileged service reads it through
// LoadCredentialEncrypted= instead (ReadLoadedCredential), or uses Options.UserScope credentials.
func (c *Credentials) Decrypt(ctx context.Context, name, inputPath string) (*Credential, error) {
	if err := checkName(name); err != nil {
		return nil, err
	}
	if err := checkPath(inputPath); err != nil {
		return nil, err
	}
	arguments := []string{"--name=" + name, "--newline=no"}
	if c.userScope {
		arguments = append(arguments, "--user")
	}
	arguments = append(arguments, "decrypt", inputPath, "-")
	return c.run(ctx, "decrypt", arguments, nil)
}

func (c *Credentials) run(ctx context.Context, verb string, arguments []string, stdin []byte) (*Credential, error) {
	result, err := c.runner.run(ctx, c.executablePath, arguments, stdin, c.timeout)
	if err != nil {
		return nil, err
	}
	if result.exitCode == 0 {
		return result.output, nil
	}
	_ = result.output.Close()
	return nil, &CommandError{Verb: verb, ExitCode: result.exitCode, Stderr: result.stderr}
}

// ReadLoadedCredential reads the credential name that systemd decrypted for this service -
// LoadCredentialEncrypted= or SetCredentialEncrypted= in its unit - from its in-memory credentials
// directory under /run, which only the service can read: credentialsDirectory, or, when that is
// empty, the one $CREDENTIALS_DIRECTORY names. It returns nil and no error when there is no such
// credential, or no credentials directory; ErrInvalidName for a name that can't be one; and
// ErrTooLarge for a credential longer than MaxLength. Close the Credential once used.
func ReadLoadedCredential(name, credentialsDirectory string) (*Credential, error) {
	path, err := loadedCredentialPath(name, credentialsDirectory)
	if err != nil || path == "" || !isFile(path) {
		return nil, err
	}
	return readCredentialFile(path)
}

// loadedCredentialPath is where the loaded credential name would be; empty when there is no
// credentials directory.
func loadedCredentialPath(name, credentialsDirectory string) (string, error) {
	if err := checkName(name); err != nil {
		return "", err
	}
	directory := credentialsDirectory
	if directory == "" {
		directory = os.Getenv(CredentialsDirectoryVariable)
	}
	if directory == "" {
		return "", nil
	}
	return filepath.Join(directory, name), nil
}

// isFile reports whether path is a file, not a directory, that exists.
func isFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func checkName(name string) error {
	if !IsValidName(name) {
		return fmt.Errorf("%w: '%s' isn't a credential name: 1-%d ASCII letters, digits, '.', '_' and '-', not starting with '-'",
			ErrInvalidName, name, MaxNameLength)
	}
	return nil
}

func checkPath(path string) error {
	if path == "" || !filepath.IsAbs(path) {
		return fmt.Errorf("%w: the credential file's path must be absolute, not '%s'", ErrInvalidArgument, path)
	}
	return nil
}
