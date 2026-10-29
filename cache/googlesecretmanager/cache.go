package googlesecretmanager

import (
	"context"
	"hash/crc32"
	"log/slog"
	"strings"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/cache"
)

// MaxSecretNameLength is the longest ID Secret Manager accepts for a secret.
const MaxSecretNameLength = 255

// Client is what the cache needs of a Secret Manager client: the one call it makes, as
// cloud.google.com/go/secretmanager/apiv1 defines it. A *secretmanager.Client is one - over gRPC
// (secretmanager.NewClient) or REST (secretmanager.NewRESTClient) - and so is a test double. Only
// AccessSecretVersion is called; every response is checked before it is used.
type Client interface {
	AccessSecretVersion(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest,
		opts ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error)
}

var _ Client = (*secretmanager.Client)(nil)

// Options are the cache's optional settings; the zero value logs nothing.
type Options struct {
	// Logger receives a debug record per fetched secret's name (never a value) while sensitive
	// logging is enabled (diagnostics.Cache), and an error record per failed fetch; see
	// cache.RemoteOptions.
	Logger *slog.Logger
}

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// New returns a cache.RemoteCache over the secrets in one Google Cloud project's Secret Manager,
// every call made through client (a *secretmanager.Client):
//
//	client, err := secretmanager.NewClient(ctx) // the application's: credentials, transport, retries
//	secrets, err := googlesecretmanager.New(client, "my-project", ring, googlesecretmanager.Options{})
//
// The first lookup of a name that isn't cached yet reads that one secret's latest version
// (projects/{project}/secrets/{name}/versions/latest) with AccessSecretVersion; fetching,
// encryption, caching and telemetry are cache.RemoteCache's. The cache never lists secrets or
// versions, so the principal needs only secretmanager.versions.access on the secrets it reads (the
// Secret Manager Secret Accessor role), never secretmanager.secrets.list.
//
// Names are matched exactly, as Secret Manager matches secret IDs: "Db-Password" and "db-password"
// are two secrets and two entries. A name Secret Manager can't hold - anything but 1-255 ASCII
// letters, digits, hyphens and underscores (see IsValidSecretName), such as the configuration path
// "ConnectionStrings:Admin" - is reported missing without a call, so the cache can sit last in a
// cache.Collection behind sources with other naming rules.
//
// A payload holding a JSON object, such as {"username":"app","password":"..."}, is cached whole
// under the secret's ID and each member under "id#key" - "Db-Login#password" - all from one call
// (see cache.SecretSink.SetBytesWithJSONKeys); any other payload, text or binary, is cached as its
// bytes.
//
// A secret that doesn't exist, or has no versions (NOT_FOUND), or whose payload is empty is
// reported missing - Decrypt returns 0 - and is looked up again next time. Any other failure
// (permission denied, a disabled or destroyed latest version, Google unreachable, no credentials)
// is returned with the client's error wrapped, so errors.As reaches its *apierror.APIError and
// status.Code reads its gRPC status; when the lookup's context has ended it also matches the
// context's error. A response naming a different secret, or whose payload doesn't match the
// CRC32C Google returns with it, is refused with ErrInvalidResponse. Nothing a failed fetch read is
// cached. A cached value isn't refreshed: a new secret version is picked up by a new cache.
//
// The secret never becomes a string. Its payload arrives as protobuf bytes, which the cache
// encrypts and then zeroes, refused or not. Over gRPC, the cache also has the call decode the
// response with a codec that zeroes the buffer gRPC received the message into once it has been
// decoded (proto.Unmarshal copies the payload out first), which gRPC would otherwise return to its
// buffer pool, or leave to the garbage collector, still holding the secret. What can't be zeroed is
// below the codec: the connection's read buffer and TLS's decryption buffers. Over REST the
// response is a JSON body the client reads into a []byte of its own and decodes from base64, out of
// the cache's reach; prefer gRPC. And keep the client's debug logging off: with
// GOOGLE_SDK_GO_LOGGING_LEVEL=debug, or a logger given to the client, it logs every response in
// full, secret payloads included.
//
// The client is the application's: it creates it (credentials, transport, retries - by default it
// retries UNAVAILABLE and RESOURCE_EXHAUSTED for up to 60 seconds), keeps it for as long as the
// cache is used, and closes it; the cache never creates or closes one. The ring is the caller's
// too: the cache never closes keys. New makes no call.
//
// It fails with ErrInvalidArgument when client or ring is nil, or projectID is empty or holds
// anything but ASCII letters, digits, hyphens, dots and colons (a project ID, a project number, or
// a legacy domain-scoped ID such as "example.com:my-project") - it is spliced into every resource
// name, so nothing that could change the path is allowed.
func New(client Client, projectID string, ring hkdfguard.KeyRing, options Options) (*cache.RemoteCache, error) {
	if client == nil {
		return nil, invalidArgument("a Secret Manager client is required (a *secretmanager.Client).")
	}
	if ring == nil {
		return nil, invalidArgument("a key ring is required.")
	}
	if !isProjectID(projectID) {
		return nil, invalidArgument("'%s' isn't a Google Cloud project ID or number.", projectID)
	}
	return cache.NewRemote(ring, &secretStore{
		client:      client,
		projectID:   projectID,
		callOptions: []gax.CallOption{gax.WithGRPCOptions(grpc.ForceCodecV2(receiveBufferScrubber{}))},
	}, cache.RemoteOptions{Matching: cache.Exact, Logger: options.Logger})
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

// secretStore is the cache.SecretStore the RemoteCache fetches through.
type secretStore struct {
	client    Client
	projectID string

	// callOptions go with every call: over gRPC, the codec that zeroes the receive buffer.
	callOptions []gax.CallOption
}

func (s *secretStore) IsValidName(name string) bool { return IsValidSecretName(name) }

// Fetch reads the latest version of the secret name, checks the response, and hands its payload to
// sink - zeroing the payload either way.
func (s *secretStore) Fetch(ctx context.Context, name string, sink *cache.SecretSink) error {
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
	// happens - here for a refused response, which never reaches the sink, and by the sink, which
	// zeroes what it is given.
	payload := response.GetPayload().GetData()
	defer hkdfguard.Wipe(payload)
	if err := checkResponse(response, name, payload); err != nil {
		return err
	}
	// A payload holding a JSON object is cached whole and by key; an empty one is none.
	return sink.SetBytesWithJSONKeys(payload)
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
