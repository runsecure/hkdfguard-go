package googlesecretmanager_test

import (
	"context"
	"log"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"

	"github.com/runsecure/hkdfguard-go/cryptoprovider/aesgcm256"
	"github.com/runsecure/hkdfguard-go/dek"
	"github.com/runsecure/hkdfguard-go/pipeline/googlesecretmanager"
)

// A pipeline pulling three secrets and writing them as files for cache/filepersecret.
func ExampleNew() {
	ctx := context.Background()
	protector, err := aesgcm256.NewPipelineDataProtector(dek.NewDefaultFormatProvider(), 3)
	if err != nil {
		log.Fatal(err)
	}
	defer protector.Close()
	client, err := secretmanager.NewClient(ctx) // Application Default Credentials: Workload Identity on GKE
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
	writer, err := googlesecretmanager.New(client, "my-project", protector,
		[]string{"db-login#username", "db-login#password", "api-key"})
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
