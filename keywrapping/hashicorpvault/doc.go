// Package hashicorpvault implements hkdfguard.KeyWrapper over one key in a HashiCorp Vault transit
// secrets engine - the Go port of the .NET HkdfGuard.KeyWrapping.HashiCorpVault library. DEKs are
// wrapped with encrypt, revealed with decrypt and, when no context is bound, generated in Vault with
// datakey/wrapped, through a *api.Client (github.com/hashicorp/vault/api) the application creates
// and configures: its address, TLS, namespace, token and auth method, timeout and retries are the
// client's. A wrapped DEK is Vault's ciphertext as it returns it, "vault:v{version}:{base64}", in
// ASCII, and the requests are byte for byte those the .NET wrapper sends, so a key file made by
// either unwraps through the other, given the same Vault key and context.
//
// Key files are read only from where no untrusted account could have written or replaced them
// (package securefile), since anyone whose policy allows encrypt on the key could otherwise choose
// the DEK new data is encrypted under:
//
//	client, err := api.NewClient(api.DefaultConfig()) // VAULT_ADDR, VAULT_TOKEN, VAULT_CACERT...
//	if err != nil { ... }
//	wrapper, err := hashicorpvault.New(client, "myapp-kek",
//		hashicorpvault.Options{Context: "com.example.myapp"})
//
// It is a module of its own (github.com/runsecure/hkdfguard-go/keywrapping/hashicorpvault) so that
// only applications that use it depend on Vault's API client.
package hashicorpvault
