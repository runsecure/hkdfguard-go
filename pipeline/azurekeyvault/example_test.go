package azurekeyvault_test

import (
	"context"
	"log"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	"github.com/runsecure/hkdfguard-go/cryptoprovider/aesgcm256"
	"github.com/runsecure/hkdfguard-go/dek"
	"github.com/runsecure/hkdfguard-go/pipeline/azurekeyvault"
)

// A pipeline pulling three secrets and writing them as files for cache/filepersecret.
func ExampleNew() {
	ctx := context.Background()
	protector, err := aesgcm256.NewPipelineDataProtector(dek.NewDefaultFormatProvider(), 3)
	if err != nil {
		log.Fatal(err)
	}
	defer protector.Close()
	credential, err := azidentity.NewDefaultAzureCredential(nil) // Workload Identity on AKS
	if err != nil {
		log.Fatal(err)
	}
	writer, err := azurekeyvault.New("https://myvault.vault.azure.net/", credential, protector,
		[]string{"Db-Login#username", "Db-Login#password", "Api-Key"}, azurekeyvault.Options{})
	if err != nil {
		log.Fatal(err)
	}
	defer writer.Close()
	if err := writer.PullSecrets(ctx); err != nil {
		log.Fatal(err)
	}
	if err := writer.WriteProtectedSecretFiles(`C:\HkdfGuardSecrets\myapp`); err != nil {
		log.Fatal(err)
	}
	// Then hand protector.KeyBase64() to the wrap tool, and register the key at version 3.
}
