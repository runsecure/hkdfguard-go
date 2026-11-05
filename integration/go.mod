module github.com/runsecure/hkdfguard-go/integration

go 1.27.1

toolchain go1.27.3

require (
	cloud.google.com/go/kms v1.36.1
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.24.0
	github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys v1.5.0
	github.com/aws/aws-sdk-go-v2 v1.47.6
	github.com/aws/aws-sdk-go-v2/service/kms v1.62.3
	github.com/googleapis/gax-go/v2 v2.27.0
	github.com/runsecure/hkdfguard-go v0.9.1
	github.com/runsecure/hkdfguard-go/cryptoprovider/aesgcm256 v0.9.1
	github.com/runsecure/hkdfguard-go/keywrapping/awskms v0.9.1
	github.com/runsecure/hkdfguard-go/keywrapping/azurekeyvault v0.9.1
	github.com/runsecure/hkdfguard-go/keywrapping/googlekms v0.9.1
	github.com/runsecure/hkdfguard-go/keywrapping/nativev1 v0.9.1
	github.com/runsecure/hkdfguard-go/securefile v0.9.1
	google.golang.org/grpc v1.85.0
	google.golang.org/protobuf v1.36.12
)

require (
	cloud.google.com/go v0.123.0 // indirect
	cloud.google.com/go/auth v0.24.2 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.3.1 // indirect
	cloud.google.com/go/compute/metadata v0.10.0 // indirect
	cloud.google.com/go/iam v1.15.1 // indirect
	cloud.google.com/go/longrunning v1.5.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.13.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/internal v1.2.0 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.5.9 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.8.9 // indirect
	github.com/aws/smithy-go v1.28.8 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/felixge/httpsnoop v1.1.0 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/google/s2a-go v0.1.11 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.25 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.72.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.72.0 // indirect
	go.opentelemetry.io/otel v1.47.0 // indirect
	go.opentelemetry.io/otel/log v1.47.0 // indirect
	go.opentelemetry.io/otel/metric v1.47.0 // indirect
	go.opentelemetry.io/otel/trace v1.47.0 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/net v0.62.0 // indirect
	golang.org/x/oauth2 v0.37.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	golang.org/x/time v0.16.0 // indirect
	google.golang.org/api v0.311.0 // indirect
	google.golang.org/genproto v0.0.0-20261104224025-d1e00e9f33ab // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20261104224025-d1e00e9f33ab // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20261104224025-d1e00e9f33ab // indirect
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
