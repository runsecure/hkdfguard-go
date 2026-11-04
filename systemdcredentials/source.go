package systemdcredentials

import (
	"context"
	"fmt"
	"os"

	"github.com/runsecure/hkdfguard-go"
)

// Source is a hkdfguard.ProtectedReadOnlyCache over systemd credentials - for the certificate
// loader's password, say. A name is looked for first among the credentials systemd decrypted for
// this service (LoadCredentialEncrypted=, in its in-memory credentials directory), then among the
// encrypted credential files it was given, which systemd-creds decrypts by that name. Nothing is
// cached: every lookup reads the credential again, into a buffer wiped as soon as it has been
// copied out. A name it doesn't have - or that can't be a credential's - is reported missing:
// Decrypt returns 0. Names are matched exactly. Safe for concurrent use.
type Source struct {
	credentials          *Credentials
	encryptedFiles       map[string]string
	credentialsDirectory string
}

var _ hkdfguard.ProtectedReadOnlyCache = (*Source)(nil)

// NewSource returns a Source over the service's credentials directory - credentialsDirectory, or,
// when that is empty, $CREDENTIALS_DIRECTORY's - and encryptedFiles, encrypted credential files by
// credential name, absolute paths, which credentials decrypts (nil when there are none). It fails
// with ErrInvalidArgument for a name that isn't one, a path that isn't absolute, or files without
// credentials to decrypt them.
func NewSource(credentials *Credentials, encryptedFiles map[string]string, credentialsDirectory string) (*Source, error) {
	files := make(map[string]string, len(encryptedFiles))
	for name, path := range encryptedFiles {
		if !IsValidName(name) {
			return nil, fmt.Errorf("%w: '%s' isn't a credential name", ErrInvalidName, name)
		}
		if err := checkPath(path); err != nil {
			return nil, fmt.Errorf("%w: the credential file for '%s' must be an absolute path, not '%s'", ErrInvalidArgument, name, path)
		}
		files[name] = path
	}
	if len(files) > 0 && credentials == nil {
		return nil, fmt.Errorf("%w: encrypted credential files need Credentials to decrypt them", ErrInvalidArgument)
	}
	return &Source{credentials: credentials, encryptedFiles: files, credentialsDirectory: credentialsDirectory}, nil
}

// Decrypt reads the credential name into result, returning how many bytes it wrote, or 0 when
// there is no such credential. It fails with ErrResultTooSmall when result can't hold it.
func (s *Source) Decrypt(ctx context.Context, name string, result []byte) (int, error) {
	credential, err := s.read(ctx, name)
	if err != nil || credential == nil {
		return 0, err
	}
	defer credential.Close()
	value, _ := credential.Value()
	if len(value) > len(result) {
		return 0, fmt.Errorf("%w: the credential is %d bytes; result holds %d", ErrResultTooSmall, len(value), len(result))
	}
	return copy(result, value), nil
}

// MaxDecryptedLength is the credential file's length: never less than its value's. ok is false
// when there is no such credential, or it is empty.
func (s *Source) MaxDecryptedLength(_ context.Context, name string) (int, bool, error) {
	path := s.locate(name)
	if path == "" {
		return 0, false, nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return 0, false, nil
	}
	length := int(min(info.Size(), int64(^uint(0)>>1)))
	return length, length > 0, nil
}

// locate is the file name's value comes from: the loaded credential if there is one, else its
// encrypted file; empty when there is neither.
func (s *Source) locate(name string) string {
	if !IsValidName(name) {
		return ""
	}
	if loaded, _ := loadedCredentialPath(name, s.credentialsDirectory); loaded != "" && isFile(loaded) {
		return loaded
	}
	if encrypted, ok := s.encryptedFiles[name]; ok && isFile(encrypted) {
		return encrypted
	}
	return ""
}

func (s *Source) read(ctx context.Context, name string) (*Credential, error) {
	path := s.locate(name)
	if path == "" {
		return nil, nil
	}
	if encrypted, ok := s.encryptedFiles[name]; !ok || encrypted != path {
		return ReadLoadedCredential(name, s.credentialsDirectory)
	}
	return s.credentials.Decrypt(ctx, name, path)
}
