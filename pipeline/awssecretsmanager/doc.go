// Package awssecretsmanager is a provisioning pipeline's hkdfguard.SecretPipelineWriter over AWS
// Secrets Manager - the Go port of the .NET HkdfGuard.Pipeline.AwsSecretsManager library. New
// returns a *pipeline.Writer that pulls a fixed list of secrets with GetSecretValue, through a
// *secretsmanager.Client (the AWS SDK for Go v2) the application creates and configures, encrypts
// each with a hkdfguard.PipelineDataProtector as soon as it is read, and writes them out as one
// file per secret - the folder layout cache/filepersecret reads at runtime. It is independent of
// cache/awssecretsmanager's runtime cache, and of any key ring:
//
//	protector, err := aesgcm256.NewPipelineDataProtector(dek.NewDefaultFormatProvider(), 3)
//	if err != nil { ... }
//	defer protector.Close()
//	cfg, err := config.LoadDefaultConfig(ctx) // credentials (IRSA or EKS Pod Identity on EKS), region, retries
//	if err != nil { ... }
//	writer, err := awssecretsmanager.New(secretsmanager.NewFromConfig(cfg), protector,
//		[]string{"prod/app#username", "prod/app#password", "prod/api-key"})
//	if err != nil { ... }
//	if err := writer.PullSecrets(ctx); err != nil { ... }
//	if err := writer.WriteProtectedSecretFiles(`C:\HkdfGuardSecrets\myapp`); err != nil { ... }
//	// Then hand protector.KeyBase64() to the wrap tool, and register the key at version 3.
//
// A name without a key reads the secret's whole SecretString; "name#key" a member of a key/value
// secret. A SecretBinary is refused: the protector encrypts text.
//
// The secret never becomes a Go string: every GetSecretValue the writer makes carries a middleware
// that takes SecretString out of the raw response body before the SDK parses it, and hands the SDK
// an empty object in its place (see New).
//
// It is a module of its own (github.com/runsecure/hkdfguard-go/pipeline/awssecretsmanager) so that
// only pipelines that use it depend on the AWS SDK.
package awssecretsmanager
