// Package azurekeyvault is a hkdfguard.ProtectedReadOnlyCache over the secrets in one Azure Key
// Vault - the Go port of the .NET HkdfGuard.Cache.AzureKeyVault library. Nothing is fetched up
// front: the first lookup of a name reads that one secret (its current version) with GetSecret,
// encrypts it under the key ring's current key, bound to its name, and caches only the ciphertext;
// later lookups never call Key Vault. It never lists the vault, so the application needs only get
// on secrets (the Key Vault Secrets User role):
//
//	credential, err := azidentity.NewDefaultAzureCredential(nil)
//	if err != nil { ... }
//	secrets, err := azurekeyvault.New("https://myvault.vault.azure.net/", credential, ring, azurekeyvault.Options{})
//	if err != nil { ... }
//
//	buffer := make([]byte, 256)
//	n, err := secrets.Decrypt(ctx, "Db-Password", buffer) // 0 if the secret doesn't exist
//	defer hkdfguard.Wipe(buffer)
//
// The secret never becomes a Go string: the cache's own Key Vault client takes the value out of the
// response body, as bytes, before the SDK parses it (see New).
//
// It is a module of its own (github.com/runsecure/hkdfguard-go/cache/azurekeyvault) so that only
// applications that use it depend on the Azure SDK.
package azurekeyvault
