// Package googlekms implements hkdfguard.KeyWrapper over one symmetric Google Cloud KMS key - the Go
// port of the .NET HkdfGuard.KeyWrapping.GoogleKms library. DEKs are wrapped with Encrypt and
// revealed with Decrypt, the key pinned, every request and response checksummed with CRC32C, through
// a *kms.KeyManagementClient (cloud.google.com/go/kms/apiv1) the application creates and configures.
// Wrapped DEKs are byte for byte those of the .NET, Java, Python and Node wrappers, so a key file
// made by any of them unwraps here, and the reverse, given the same key and context.
//
// Key files are read only from where no untrusted account could have written or replaced them
// (package securefile), since anyone who may encrypt under the key could otherwise choose the DEK new
// data is encrypted under:
//
//	client, err := kms.NewKeyManagementClient(ctx) // Application Default Credentials
//	if err != nil { ... }
//	defer client.Close()
//	wrapper, err := googlekms.New(client,
//		"projects/my-project/locations/us-east1/keyRings/myapp/cryptoKeys/myapp-wrap",
//		googlekms.Options{Context: "com.example.myapp"})
//
// It is a module of its own (github.com/runsecure/hkdfguard-go/keywrapping/googlekms) so that only
// applications that use it depend on the Google Cloud client libraries.
package googlekms
