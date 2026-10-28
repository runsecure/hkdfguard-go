module github.com/runsecure/hkdfguard-go/integration

go 1.27.1

toolchain go1.27.2

require (
	cloud.google.com/go/kms v1.35.0
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.23.3
	github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys v1.5.0
	github.com/aws/aws-sdk-go-v2 v1.47.3
	github.com/aws/aws-sdk-go-v2/service/kms v1.61.4
	github.com/googleapis/gax-go/v2 v2.23.0
	github.com/runsecure/hkdfguard-go v0.0.0-00010101000000-000000000000
	github.com/runsecure/hkdfguard-go/cryptoprovider/aesgcm256 v0.0.0-00010101000000-000000000000
	github.com/runsecure/hkdfguard-go/keywrapping/awskms v0.0.0-00010101000000-000000000000
	github.com/runsecure/hkdfguard-go/keywrapping/azurekeyvault v0.0.0-00010101000000-000000000000
	github.com/runsecure/hkdfguard-go/keywrapping/googlekms v0.0.0-00010101000000-000000000000
	github.com/runsecure/hkdfguard-go/keywrapping/nativev1 v0.0.0-00010101000000-000000000000
	github.com/runsecure/hkdfguard-go/securefile v0.0.0-00010101000000-000000000000
	google.golang.org/grpc v1.83.2
	google.golang.org/protobuf v1.36.11
)

require (
	cloud.google.com/go v0.123.0 // indirect
	cloud.google.com/go/auth v0.20.0 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.2.8 // indirect
	cloud.google.com/go/compute/metadata v0.9.0 // indirect
	cloud.google.com/go/iam v1.11.0 // indirect
	cloud.google.com/go/longrunning v1.2.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.13.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/internal v1.2.0 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.5.6 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.8.6 // indirect
	github.com/aws/smithy-go v1.28.5 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/google/s2a-go v0.1.9 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.17 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.67.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.67.0 // indirect
	go.opentelemetry.io/otel v1.46.0 // indirect
	go.opentelemetry.io/otel/metric v1.46.0 // indirect
	go.opentelemetry.io/otel/trace v1.46.0 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/net v0.60.0 // indirect
	golang.org/x/oauth2 v0.36.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	google.golang.org/api v0.287.1 // indirect
	google.golang.org/genproto v0.0.0-20260319201613-d00831a3d3e7 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260630182238-925bb5da69e7 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260630182238-925bb5da69e7 // indirect
)

replace (
	github.com/runsecure/hkdfguard-go => ../
	github.com/runsecure/hkdfguard-go/cryptoprovider/aesgcm256 => ../cryptoprovider/aesgcm256
	github.com/runsecure/hkdfguard-go/keywrapping/awskms => ../keywrapping/awskms
	github.com/runsecure/hkdfguard-go/keywrapping/azurekeyvault => ../keywrapping/azurekeyvault
	github.com/runsecure/hkdfguard-go/keywrapping/nativev1 => ../keywrapping/nativev1
	github.com/runsecure/hkdfguard-go/securefile => ../securefile
)

replace github.com/runsecure/hkdfguard-go/keywrapping/googlekms => ../keywrapping/googlekms
