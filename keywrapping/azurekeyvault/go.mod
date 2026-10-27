module github.com/runsecure/hkdfguard-go/keywrapping/azurekeyvault

go 1.27.1

toolchain go1.27.2

replace (
	github.com/runsecure/hkdfguard-go => ../..
	github.com/runsecure/hkdfguard-go/securefile => ../../securefile
)

require (
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.23.3
	github.com/Azure/azure-sdk-for-go/sdk/azidentity v1.14.1
	github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys v1.5.0
	github.com/runsecure/hkdfguard-go v0.0.0-00010101000000-000000000000
	github.com/runsecure/hkdfguard-go/securefile v0.0.0-00010101000000-000000000000
	golang.org/x/sys v0.48.0
)

require (
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.13.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/internal v1.2.0 // indirect
	github.com/AzureAD/microsoft-authentication-library-for-go v1.8.0 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/pkg/browser v0.0.0-20240102092130-5ac0b6a4141c // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/net v0.60.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/text v0.42.0 // indirect
)
