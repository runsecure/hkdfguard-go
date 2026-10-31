// Package googlesecretmanager implements a hkdfguard.ProtectedReadOnlyCache over the secrets in one
// Google Cloud project's Secret Manager - the Go port of the .NET HkdfGuard.Cache.GoogleSecretManager
// library. The first lookup of a name that isn't cached yet reads that one secret's latest version
// with AccessSecretVersion, through a *secretmanager.Client (cloud.google.com/go/secretmanager/apiv1)
// the application creates and configures; fetching, encryption, caching and telemetry are
// cache.RemoteCache's. It never lists secrets or versions, so the principal needs only
// secretmanager.versions.access on the secrets it reads (the Secret Manager Secret Accessor role):
//
//	client, err := secretmanager.NewClient(ctx) // Application Default Credentials
//	if err != nil { ... }
//	defer client.Close()
//	secrets, err := googlesecretmanager.New(client, "my-project", ring, googlesecretmanager.Options{})
//	if err != nil { ... }
//
//	buffer := make([]byte, 256)
//	n, err := secrets.Decrypt(ctx, "Db-Password", buffer) // 0 if the secret doesn't exist
//
// A payload holding a JSON object, such as {"username":"app","password":"..."}, is cached whole
// under the secret's ID and each member under "id#key" - "Db-Login#password" - all from one call.
//
// It is a module of its own (github.com/runsecure/hkdfguard-go/cache/googlesecretmanager) so that
// only applications that use it depend on the Google Cloud client libraries.
package googlesecretmanager
