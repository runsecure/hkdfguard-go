// Package azurekeyvault is a provisioning pipeline's hkdfguard.SecretPipelineWriter over one Azure
// Key Vault - the Go port of the .NET HkdfGuard.Pipeline.AzureKeyVault library. New returns a
// *pipeline.Writer that pulls a fixed list of secrets with GetSecret, through its own
// azsecrets.Client, encrypts each with a hkdfguard.PipelineDataProtector as soon as it is read, and
// writes them out as one file per secret - the folder layout cache/filepersecret reads at runtime.
// It is independent of cache/azurekeyvault's runtime cache, and of any key ring:
//
//	protector, err := aesgcm256.NewPipelineDataProtector(dek.NewDefaultFormatProvider(), 3)
//	if err != nil { ... }
//	defer protector.Close()
//	credential, err := azidentity.NewDefaultAzureCredential(nil) // Workload Identity on AKS
//	if err != nil { ... }
//	writer, err := azurekeyvault.New("https://myvault.vault.azure.net/", credential, protector,
//		[]string{"Db-Login#username", "Db-Login#password", "Api-Key"}, azurekeyvault.Options{})
//	if err != nil { ... }
//	if err := writer.PullSecrets(ctx); err != nil { ... }
//	if err := writer.WriteProtectedSecretFiles(`C:\HkdfGuardSecrets\myapp`); err != nil { ... }
//	// Then hand protector.KeyBase64() to the wrap tool, and register the key at version 3.
//
// A name without a key reads the secret's whole value; "name#key" a member of a value holding a
// JSON object.
//
// The secret never becomes a Go string: the writer's own Key Vault client takes the value out of
// the response body, as bytes, before the SDK parses it, and hands the SDK an empty object in its
// place (see New).
//
// It is a module of its own (github.com/runsecure/hkdfguard-go/pipeline/azurekeyvault) so that only
// pipelines that use it depend on the Azure SDK.
package azurekeyvault
