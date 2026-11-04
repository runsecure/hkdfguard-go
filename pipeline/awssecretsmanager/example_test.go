package awssecretsmanager_test

import (
	"context"
	"log"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"

	"github.com/runsecure/hkdfguard-go/cryptoprovider/aesgcm256"
	"github.com/runsecure/hkdfguard-go/dek"
	"github.com/runsecure/hkdfguard-go/pipeline/awssecretsmanager"
)

// A pipeline pulling three secrets and writing them as files for cache/filepersecret.
func ExampleNew() {
	ctx := context.Background()
	protector, err := aesgcm256.NewPipelineDataProtector(dek.NewDefaultFormatProvider(), 3)
	if err != nil {
		log.Fatal(err)
	}
	defer protector.Close()
	cfg, err := config.LoadDefaultConfig(ctx) // credentials (IRSA or EKS Pod Identity on EKS), region, retries
	if err != nil {
		log.Fatal(err)
	}
	writer, err := awssecretsmanager.New(secretsmanager.NewFromConfig(cfg), protector,
		[]string{"prod/app#username", "prod/app#password", "prod/api-key"})
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
