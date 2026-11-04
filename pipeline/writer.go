package pipeline

import (
	"context"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/cache/filepersecret"
)

// KeySeparator separates a secret's name from the key it reads: "prod/app#password".
const KeySeparator = '#'

// FileNameSeparator replaces each '/' and '#' of a secret name in its file name.
const FileNameSeparator = "__"

// The modes a folder WriteProtectedSecretFiles creates, and a file it creates, are given before the
// umask: only encrypted values are written, but cache/filepersecret refuses a folder or file anyone
// but administrators and the principals it trusts can modify.
const (
	folderMode = 0o755
	fileMode   = 0o644
)

// SecretStore is the one thing a Writer needs of a secret store: a call that reads one secret by
// name - never a listing - and the rule for which names it can hold.
type SecretStore interface {
	// IsValidName reports whether the store can hold a secret named name - the part of a secret
	// name before any KeySeparator. A secret name whose name it rejects is refused by New.
	IsValidName(name string) bool

	// ReadSecret reads the one secret named name and encrypts the value each of secret.Requests()
	// asks for, through secret's Protect methods - or returns nil without doing so when it doesn't
	// exist. Any other failure is returned. A request left without a value is reported missing. It
	// must honour ctx.
	ReadSecret(ctx context.Context, name string, secret *Secret) error
}

// Options are a Writer's settings; the zero value reads a secret's whole value for a name without a
// key.
type Options struct {
	// DefaultKey is the key a name without one reads, for a store whose secrets are all sets of keys
	// (HashiCorp Vault's KV); "" - the default - when such a name reads the secret's whole value. It
	// must not hold KeySeparator.
	DefaultKey string
}

// SecretRequest is one secret name a Writer pulls: what to read, and the file it is written as.
type SecretRequest struct {
	// SecretName is the name as it was given, key and all.
	SecretName string

	// Key is the key to read; "" for the secret's whole value.
	Key string

	// FileName is the file it is written as, and the name its value is bound to.
	FileName string
}

// Writer is the hkdfguard.SecretPipelineWriter over one secret store - the Go port of the .NET
// SecretPipelineWriter: see the package documentation. The store supplies only IsValidName and
// ReadSecret; naming, grouping, encrypting, keeping and writing are the Writer's. It isn't safe for
// concurrent use.
type Writer struct {
	protector hkdfguard.PipelineDataProtector
	store     SecretStore

	// The secrets to pull, by the store's name, each read once for its whole value and its keys; and
	// those names in the order they were first given.
	requests map[string][]SecretRequest
	order    []string

	// Each secret's encrypted, formatted value, by file name.
	protected map[string]string
	pulled    bool
	closed    bool
}

var _ hkdfguard.SecretPipelineWriter = (*Writer)(nil)

// New returns a Writer pulling secretNames from store, every value encrypted by protector. The
// protector is the caller's: the writer never closes it. secretNames is copied: a later change to
// the slice isn't seen. Each is a name the store can hold, optionally followed by KeySeparator and
// the key to read: "prod/app#password" reads the password key of the secret prod/app, and a name
// without a key reads options.DefaultKey, or the secret's whole value when there is none.
//
// It fails with ErrInvalidArgument when protector or store is nil; secretNames is empty, or holds a
// name the store can't hold, an empty key, a name whose file name (see FileName) isn't one
// cache/filepersecret can read (see filepersecret.IsValidName), or two names with the same file name
// ignoring case; or options.DefaultKey holds KeySeparator.
func New(protector hkdfguard.PipelineDataProtector, secretNames []string, store SecretStore, options Options) (*Writer, error) {
	switch {
	case protector == nil:
		return nil, invalidArgument("a pipeline data protector is required")
	case store == nil:
		return nil, invalidArgument("a secret store is required")
	case strings.IndexByte(options.DefaultKey, KeySeparator) >= 0:
		return nil, invalidArgument("the default key '%s' isn't a key", options.DefaultKey)
	case len(secretNames) == 0:
		return nil, invalidArgument("no secrets are named")
	}

	w := &Writer{protector: protector, store: store, requests: map[string][]SecretRequest{}, protected: map[string]string{}}
	fileNames := map[string]struct{}{}
	for _, secretName := range secretNames {
		name, key, hasKey := strings.Cut(secretName, string(KeySeparator))
		if !hasKey {
			key = options.DefaultKey
		}
		if name == "" || !store.IsValidName(name) || (hasKey && key == "") {
			return nil, invalidArgument("'%s' isn't a secret name this store can hold, with a key after '%c' if any", secretName, KeySeparator)
		}
		fileName := FileName(secretName)
		if !filepersecret.IsValidName(fileName) {
			return nil, invalidArgument("'%s' can't be written as a file: its file name '%s' must be 1-%d ASCII letters, digits, '-', '_' and '.', not starting with '.'",
				secretName, fileName, filepersecret.MaxNameLength)
		}
		// File names are found ignoring case on Windows and macOS, so two differing only in case are one.
		folded := strings.ToLower(fileName)
		if _, taken := fileNames[folded]; taken {
			return nil, invalidArgument("'%s' would be written as '%s', as another secret named is", secretName, fileName)
		}
		fileNames[folded] = struct{}{}

		if _, seen := w.requests[name]; !seen {
			w.order = append(w.order, name)
		}
		w.requests[name] = append(w.requests[name], SecretRequest{SecretName: secretName, Key: key, FileName: fileName})
	}
	return w, nil
}

// FileName is the file a secret name is written as: the name with every '/' and KeySeparator
// replaced by FileNameSeparator - "prod/app#password" is prod__app__password - and the name its
// value is bound to, so the one to look it up by in cache/filepersecret.
func FileName(secretName string) string {
	return strings.NewReplacer("/", FileNameSeparator, string(KeySeparator), FileNameSeparator).Replace(secretName)
}

// ProtectedSecrets implements hkdfguard.SecretPipelineWriter: a copy of every secret pulled, by file
// name, its value encrypted and formatted as its file will hold it.
func (w *Writer) ProtectedSecrets() map[string]string { return maps.Clone(w.protected) }

// PullSecrets reads every secret named in New from the store and encrypts each value, keeping it in
// ProtectedSecrets - replacing whatever an earlier pull kept. All of them are read before any
// missing one is reported: a secret that doesn't exist, or has no such key, or whose value there is
// empty or isn't a value, fails the pull with a *MissingSecretsError (ErrSecretNotFound) naming
// every one, and every other secret is kept. Any other failure the store's ReadSecret returns, or
// ctx ending, is returned as it is, and nothing is kept.
func (w *Writer) PullSecrets(ctx context.Context) error {
	clear(w.protected)
	w.pulled = false

	pulled := map[string]string{}
	for _, name := range w.order {
		if err := ctx.Err(); err != nil {
			return err
		}
		requests := w.requests[name]
		secret := &Secret{protector: w.protector, requests: requests, values: map[string]string{}}
		if err := w.store.ReadSecret(ctx, name, secret); err != nil {
			return err
		}
		for _, request := range requests {
			if value, ok := secret.values[request.FileName]; ok {
				pulled[request.FileName] = value
			}
		}
	}
	w.protected = pulled
	w.pulled = true

	var missing []string
	for _, name := range w.order {
		for _, request := range w.requests[name] {
			if _, ok := pulled[request.FileName]; !ok {
				missing = append(missing, request.SecretName)
			}
		}
	}
	if len(missing) > 0 {
		return &MissingSecretsError{SecretNames: missing}
	}
	return nil
}

// WriteProtectedSecretFiles writes every secret in ProtectedSecrets as a file in folderPath -
// absolute or relative to the working directory - creating the folder if it doesn't exist: the file
// named for it, holding its encrypted, formatted value as UTF-8, without a byte order mark. A file
// already there by that name is replaced; any other file is left as it is.
//
// Only encrypted values are written, but cache/filepersecret refuses a folder or file anyone but
// administrators and the principals it trusts can modify: write them where the deployment can set
// that, or set it once they're written. A folder made here is given mode 0755 and a file 0644, less
// the umask; a file that already exists keeps its own.
//
// It fails with ErrInvalidArgument when folderPath is empty, and with ErrNotPulled when no pull has
// completed; and as the filesystem does.
func (w *Writer) WriteProtectedSecretFiles(folderPath string) error {
	if folderPath == "" {
		return invalidArgument("a folder path is required")
	}
	if !w.pulled {
		return ErrNotPulled
	}
	folder, err := filepath.Abs(folderPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(folder, folderMode); err != nil {
		return err
	}
	for _, fileName := range slices.Sorted(maps.Keys(w.protected)) {
		if err := os.WriteFile(filepath.Join(folder, fileName), []byte(w.protected[fileName]), fileMode); err != nil {
			return err
		}
	}
	return nil
}

// Close releases the store's connection, when the store is an io.Closer; the protector is left as
// it is. Only the first call closes the store.
func (w *Writer) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true
	if closer, ok := w.store.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
