// Package googlesecretmanager is a provisioning pipeline's hkdfguard.SecretPipelineWriter over one
// Google Cloud project's Secret Manager - the Go port of the .NET
// HkdfGuard.Pipeline.GoogleSecretManager library. New returns a *pipeline.Writer that pulls a fixed
// list of secrets' latest versions with AccessSecretVersion, through a *secretmanager.Client
// (cloud.google.com/go/secretmanager/apiv1) the application creates and configures, encrypts each
// with a hkdfguard.PipelineDataProtector as soon as it is read, and writes them out as one file per
// secret - the folder layout cache/filepersecret reads at runtime. It is independent of
// cache/googlesecretmanager's runtime cache, and of any key ring:
//
//	protector, err := aesgcm256.NewPipelineDataProtector(dek.NewDefaultFormatProvider(), 3)
//	if err != nil { ... }
//	defer protector.Close()
//	client, err := secretmanager.NewClient(ctx) // Application Default Credentials: Workload Identity on GKE
//	if err != nil { ... }
//	defer client.Close()
//	writer, err := googlesecretmanager.New(client, "my-project", protector,
//		[]string{"db-login#username", "db-login#password", "api-key"})
//	if err != nil { ... }
//	if err := writer.PullSecrets(ctx); err != nil { ... }
//	if err := writer.WriteProtectedSecretFiles(`C:\HkdfGuardSecrets\myapp`); err != nil { ... }
//	// Then hand protector.KeyBase64() to the wrap tool, and register the key at version 3.
//
// A name without a key reads the latest version's whole payload; "id#key" a member of a payload
// holding a JSON object. Each payload is checked against its CRC32C and the secret it names, and
// zeroed once encrypted, as is gRPC's receive buffer (see New).
//
// It is a module of its own (github.com/runsecure/hkdfguard-go/pipeline/googlesecretmanager) so that
// only pipelines that use it depend on the Google Cloud client libraries.
package googlesecretmanager
