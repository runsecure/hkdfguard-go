// Package awssecretsmanager is a hkdfguard.ProtectedReadOnlyCache over the secrets in AWS Secrets
// Manager - the Go port of the .NET HkdfGuard.Cache.AwsSecretsManager library. The first lookup of a
// name that isn't cached yet reads that one secret's current version (AWSCURRENT) with
// GetSecretValue, through a *secretsmanager.Client (the AWS SDK for Go v2) the application creates
// and configures; fetching, encryption, caching and telemetry are cache.RemoteCache's. It never
// lists secrets (ListSecrets, BatchGetSecretValue), so the principal needs only
// secretsmanager:GetSecretValue on the secrets it reads (and kms:Decrypt on a customer managed key
// that encrypts them):
//
//	cfg, err := config.LoadDefaultConfig(ctx) // the application's: credentials, region, retries
//	if err != nil { ... }
//	secrets, err := awssecretsmanager.New(secretsmanager.NewFromConfig(cfg), ring, awssecretsmanager.Options{})
//	if err != nil { ... }
//
//	result := make([]byte, 256)
//	n, err := secrets.Decrypt(ctx, "prod/Db-Password", result) // 0 if the secret doesn't exist
//	defer hkdfguard.Wipe(result)
//
// A key/value secret - a SecretString holding a JSON object, as the console stores one - is cached
// whole under its name and each member under "name#key" ("prod/app#password"), all from one call.
//
// The secret never becomes a Go string: every GetSecretValue the cache makes carries a middleware
// that takes SecretString or SecretBinary out of the raw response body before the SDK parses it,
// and hands the SDK the body with both blanked.
//
// It is a module of its own (github.com/runsecure/hkdfguard-go/cache/awssecretsmanager) so that only
// applications that use it depend on the AWS SDK.
package awssecretsmanager
