// Package awskms implements hkdfguard.KeyWrapper over one symmetric AWS KMS key - the Go port of
// the .NET HkdfGuard.KeyWrapping.AwsKms library. DEKs are wrapped with Encrypt, revealed with
// Decrypt (the key and SYMMETRIC_DEFAULT pinned) and generated with
// GenerateDataKeyWithoutPlaintext, through a *kms.Client (the AWS SDK for Go v2) the application
// creates and configures. The ports send KMS the same requests, so a key file wrapped by the .NET,
// Java, Python or Node wrapper under the same key and encryption context unwraps here, and the
// reverse.
//
// Key files are read only from where no untrusted account could have written or replaced them
// (package securefile), since anyone who may call kms:Encrypt could otherwise choose the DEK new
// data is encrypted under:
//
//	cfg, err := config.LoadDefaultConfig(ctx)
//	if err != nil { ... }
//	wrapper, err := awskms.New(kms.NewFromConfig(cfg),
//		"arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
//		awskms.Options{EncryptionContext: map[string]string{"purpose": "com.example.myapp"}})
//
// It is a module of its own (github.com/runsecure/hkdfguard-go/keywrapping/awskms) so that only
// applications that use it depend on the AWS SDK.
package awskms
