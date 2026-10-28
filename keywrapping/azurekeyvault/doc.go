// Package azurekeyvault implements hkdfguard.KeyWrapper over two Azure Key Vault keys - the Go port
// of the .NET HkdfGuard.KeyWrapping.AzureKeyVault library. DEKs are wrapped and unwrapped under an
// RSA key (RSA-OAEP-256), and every wrapped DEK is signed by a separate EC P-256 key (ES256) and
// verified before it is unwrapped, through the Azure SDK for Go (azkeys) and a credential the
// application provides. Wrapped DEKs are byte for byte those of the .NET, Java, Python and Node
// wrappers, so a key file made by any of them unwraps here, and the reverse, given the same keys and
// context.
//
// Key files are read only from where no untrusted account could have written or replaced them
// (package securefile):
//
//	credential, err := azidentity.NewDefaultAzureCredential(nil)
//	if err != nil { ... }
//	wrapper, err := azurekeyvault.New(
//		"https://myvault.vault.azure.net/keys/myapp-wrap",
//		"https://myvault.vault.azure.net/keys/myapp-sign",
//		credential, azurekeyvault.Options{Context: "com.example.myapp"})
//
// It is a module of its own (github.com/runsecure/hkdfguard-go/keywrapping/azurekeyvault) so that
// only applications that use it depend on the Azure SDK.
package azurekeyvault
