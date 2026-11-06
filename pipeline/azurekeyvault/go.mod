module github.com/runsecure/hkdfguard-go/pipeline/azurekeyvault

go 1.27.1

toolchain go1.27.3

require (
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.24.0
	github.com/Azure/azure-sdk-for-go/sdk/azidentity v1.15.0
	github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets v1.5.1
	github.com/runsecure/hkdfguard-go v0.9.1
	github.com/runsecure/hkdfguard-go/cryptoprovider/aesgcm256 v0.9.1
	github.com/runsecure/hkdfguard-go/pipeline v0.9.1
)

require (
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.13.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/internal v1.2.0 // indirect
	github.com/AzureAD/microsoft-authentication-library-for-go v1.10.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/pkg/browser v0.0.0-20240102092130-5ac0b6a4141c // indirect
	github.com/runsecure/hkdfguard-go/cache/filepersecret v0.9.1 // indirect
	github.com/runsecure/hkdfguard-go/securefile v0.9.1 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/otel v1.47.0 // indirect
	go.opentelemetry.io/otel/log v1.47.0 // indirect
	go.opentelemetry.io/otel/metric v1.47.0 // indirect
	go.opentelemetry.io/otel/trace v1.47.0 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/net v0.62.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
)

replace (
	github.com/runsecure/hkdfguard-go => ../..
	github.com/runsecure/hkdfguard-go/cache/filepersecret => ../../cache/filepersecret
	github.com/runsecure/hkdfguard-go/cryptoprovider/aesgcm256 => ../../cryptoprovider/aesgcm256
	github.com/runsecure/hkdfguard-go/pipeline => ..
	github.com/runsecure/hkdfguard-go/securefile => ../../securefile
)
