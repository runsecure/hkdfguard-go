module github.com/runsecure/hkdfguard-go/integration

go 1.27.1

toolchain go1.27.2

require (
	github.com/aws/aws-sdk-go-v2 v1.47.3
	github.com/aws/aws-sdk-go-v2/service/kms v1.61.4
	github.com/runsecure/hkdfguard-go v0.0.0-00010101000000-000000000000
	github.com/runsecure/hkdfguard-go/cryptoprovider/aesgcm256 v0.0.0-00010101000000-000000000000
	github.com/runsecure/hkdfguard-go/keywrapping/awskms v0.0.0-00010101000000-000000000000
	github.com/runsecure/hkdfguard-go/keywrapping/nativev1 v0.0.0-00010101000000-000000000000
	github.com/runsecure/hkdfguard-go/securefile v0.0.0-00010101000000-000000000000
)

require (
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.5.6 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.8.6 // indirect
	github.com/aws/smithy-go v1.28.5 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/otel v1.46.0 // indirect
	go.opentelemetry.io/otel/metric v1.46.0 // indirect
	go.opentelemetry.io/otel/trace v1.46.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
)

replace (
	github.com/runsecure/hkdfguard-go => ../
	github.com/runsecure/hkdfguard-go/cryptoprovider/aesgcm256 => ../cryptoprovider/aesgcm256
	github.com/runsecure/hkdfguard-go/keywrapping/awskms => ../keywrapping/awskms
	github.com/runsecure/hkdfguard-go/keywrapping/nativev1 => ../keywrapping/nativev1
	github.com/runsecure/hkdfguard-go/securefile => ../securefile
)
