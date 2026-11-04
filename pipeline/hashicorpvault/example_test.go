package hashicorpvault_test

import (
	"context"
	"log"

	"github.com/hashicorp/vault/api"

	"github.com/runsecure/hkdfguard-go/cryptoprovider/aesgcm256"
	"github.com/runsecure/hkdfguard-go/dek"
	"github.com/runsecure/hkdfguard-go/pipeline/hashicorpvault"
)

// A pipeline pulling three secrets and writing them as files for cache/filepersecret.
func ExampleNew() {
	ctx := context.Background()
	protector, err := aesgcm256.NewPipelineDataProtector(dek.NewDefaultFormatProvider(), 3)
	if err != nil {
		log.Fatal(err)
	}
	defer protector.Close()
	config := api.DefaultConfig()        // VAULT_ADDR, VAULT_CACERT, VAULT_NAMESPACE, ... from the environment
	config.DisableRedirects = true       // or VAULT_DISABLE_REDIRECTS=true; New refuses a client that follows redirects
	client, err := api.NewClient(config) // VAULT_TOKEN, or log in with an auth method and SetToken
	if err != nil {
		log.Fatal(err)
	}
	writer, err := hashicorpvault.New(client, protector,
		[]string{"myapp/db#username", "myapp/db#password", "myapp/api"}, hashicorpvault.Options{})
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
