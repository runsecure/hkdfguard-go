package googlesecretmanager

import (
	"context"
	"hash/crc32"
	"strings"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/pipeline"
)

// MaxSecretNameLength is the longest ID Secret Manager accepts for a secret.
const MaxSecretNameLength = 255

// Client is what the writer needs of a Secret Manager client: the one call it makes, as
// cloud.google.com/go/secretmanager/apiv1 defines it. A *secretmanager.Client is one - over gRPC
// (secretmanager.NewClient) or REST (secretmanager.NewRESTClient) - and so is a test double. Only
// AccessSecretVersion is called; every response is checked before it is used.
type Client interface {
	AccessSecretVersion(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest,
		opts ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error)
}

var _ Client = (*secretmanager.Client)(nil)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// New returns a *pipeline.Writer pulling secretNames from one Google Cloud project's Secret Manager
// through client (a *secretmanager.Client), every value encrypted by protector - the Go port of the
// .NET GoogleSecretManagerSecretPipelineWriter:
//
//	client, err := secretmanager.NewClient(ctx) // Application Default Credentials: Workload Identity on GKE
//	writer, err := googlesecretmanager.New(client, "my-project", protector, []string{"db-login#password", "api-key"})
//
// Each secret's latest version (projects/{project}/secrets/{id}/versions/latest) is read once with
// AccessSecretVersion, so the principal needs only secretmanager.versions.access (the Secret Manager
// Secret Accessor role), never a list permission; naming, encrypting, keeping and writing are the
// pipeline.Writer's.
//
// A secret name is a Secret Manager secret ID - 1-255 ASCII letters, digits, hyphens and
// underscores - optionally with a key after '#': "api-key" reads the latest version's whole
// payload, and "db-login#password" the password member of a payload holding a JSON object (written
// as api-key and db-login__password). A member's string is read as its text; a number, true or
// false as its JSON text. A payload that isn't UTF-8 text fails the pull with
// pipeline.ErrInvalidSecretData: the protector encrypts text.
//
// A secret that doesn't exist, or has no versions (NOT_FOUND), or whose payload is empty is
// reported missing (pipeline.ErrSecretNotFound). A response naming a different secret, or whose
// payload doesn't match the CRC32C Google returns with it, is refused with ErrInvalidResponse. Any
// other failure (permission denied, a disabled or destroyed latest version, Google unreachable, no
// credentials) is returned with the client's error wrapped, so errors.As reaches its
// *apierror.APIError and status.Code reads its gRPC status; when the pull's context has ended it
// also matches the context's error.
//
// The secret never becomes a string. Its payload arrives as protobuf bytes, which the writer
// encrypts straight from the response and then zeroes, refused or not. Over gRPC, the writer also
// has the call decode the response with a codec that zeroes the buffer gRPC received the message
// into once it has been decoded, which gRPC would otherwise return to its buffer pool still holding
// the secret. What can't be zeroed is below the codec: the connection's read buffer and TLS's
// decryption buffers. Over REST the response is a JSON body the client decodes out of the writer's
// reach; prefer gRPC. And keep the client's debug logging off: it logs every response in full.
//
// The client is the application's: it creates it (credentials, transport, retries), and closes it
// once the pull is done; the writer never creates or closes one, and Close leaves it open. The
// protector is the caller's too: the writer never closes it. New makes no call.
//
// It fails with ErrInvalidArgument when client is nil, or projectID is empty or holds anything but
// ASCII letters, digits, hyphens, dots and colons - it is spliced into every resource name, so
// nothing that could change the path is allowed; and, matching pipeline.ErrInvalidArgument too,
// when pipeline.New refuses the protector or secretNames: no protector, no names, an ID Secret
// Manager can't hold (see IsValidSecretName) with a key after '#' if any, one whose file name
// cache/filepersecret can't read, or two with the same file name in any case.
func New(client Client, projectID string, protector hkdfguard.PipelineDataProtector, secretNames []string) (*pipeline.Writer, error) {
	if client == nil {
		return nil, invalidArgument("a Secret Manager client is required (a *secretmanager.Client).")
	}
	if !isProjectID(projectID) {
		return nil, invalidArgument("'%s' isn't a Google Cloud project ID or number.", projectID)
	}
	writer, err := pipeline.New(protector, secretNames, &secretStore{
		client:      client,
		projectID:   projectID,
		callOptions: []gax.CallOption{gax.WithGRPCOptions(grpc.ForceCodecV2(receiveBufferScrubber{}))},
	}, pipeline.Options{})
	if err != nil {
		return nil, &argumentError{err: err}
	}
	return writer, nil
}

// IsValidSecretName reports whether Secret Manager accepts name as a secret ID: 1-255 ASCII letters,
// digits, hyphens and underscores.
func IsValidSecretName(name string) bool {
	if name == "" || len(name) > MaxSecretNameLength {
		return false
	}
	for i := 0; i < len(name); i++ {
		if c := name[i]; !isASCIILetterOrDigit(c) && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

// isProjectID reports whether id can be spliced into a resource name as its project: 1 or more
// ASCII letters, digits, hyphens, dots and colons.
func isProjectID(id string) bool {
	if id == "" {
		return false
	}
	for i := 0; i < len(id); i++ {
		if c := id[i]; !isASCIILetterOrDigit(c) && c != '-' && c != '.' && c != ':' {
			return false
		}
	}
	return true
}

func isASCIILetterOrDigit(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9'
}

// secretStore is the pipeline.SecretStore the Writer reads through.
type secretStore struct {
	client    Client
	projectID string

	// callOptions go with every call: over gRPC, the codec that zeroes the receive buffer.
	callOptions []gax.CallOption
}

func (s *secretStore) IsValidName(name string) bool { return IsValidSecretName(name) }

// ReadSecret reads the latest version of the secret name, checks the response, and encrypts its
// payload - zeroing the payload either way.
func (s *secretStore) ReadSecret(ctx context.Context, name string, secret *pipeline.Secret) error {
	response, err := s.client.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: "projects/" + s.projectID + "/secrets/" + name + "/versions/latest",
	}, s.callOptions...)
	if err != nil {
		if status.Code(err) == codes.NotFound && ctx.Err() == nil {
			return nil
		}
		return failed(ctx, name, err)
	}

	// The bytes the client decoded the payload into, which nothing else holds: zeroed whatever
	// happens.
	payload := response.GetPayload().GetData()
	defer hkdfguard.Wipe(payload)
	if err := checkResponse(response, name, payload); err != nil {
		return err
	}
	// A payload holding a JSON object is read whole and by key; an empty one is none.
	return secret.ProtectSecret(ctx, payload)
}

// checkResponse requires the response to be a version of the secret asked for (its project comes
// back as a number, so only the secret ID can be compared), and its payload to match its checksum
// when it has one.
func checkResponse(response *secretmanagerpb.AccessSecretVersionResponse, name string, payload []byte) error {
	if secret, ok := secretOfVersion(response.GetName()); !ok || secret != name {
		return invalidResponse("Secret Manager answered a request for secret '%s' with '%s'.", name, response.GetName())
	}
	if p := response.GetPayload(); p != nil && p.DataCrc32C != nil && *p.DataCrc32C != crc32c(payload) {
		return invalidResponse("The payload of secret '%s' doesn't match its CRC32C: it was corrupted in transit.", name)
	}
	return nil
}

// secretOfVersion is the secret ID in a secret version's resource name,
// projects/{project}/secrets/{secret}/versions/{version}; ok is false for anything else.
func secretOfVersion(resourceName string) (string, bool) {
	parts := strings.Split(resourceName, "/")
	if len(parts) != 6 || parts[0] != "projects" || parts[2] != "secrets" || parts[4] != "versions" ||
		parts[1] == "" || parts[3] == "" || parts[5] == "" {
		return "", false
	}
	return parts[3], true
}

// crc32c is the CRC32C (Castagnoli) checksum of data, as Secret Manager checksums payloads.
func crc32c(data []byte) int64 { return int64(crc32.Checksum(data, castagnoli)) }
