module github.com/runsecure/hkdfguard-go/cache/jsonsecretsfile

go 1.27.1

toolchain go1.27.3

require (
	github.com/runsecure/hkdfguard-go v0.9.1
	github.com/runsecure/hkdfguard-go/cache/filepersecret v0.9.1
	github.com/runsecure/hkdfguard-go/cryptoprovider/aesgcm256 v0.9.1
	github.com/runsecure/hkdfguard-go/pipeline v0.9.1
	github.com/runsecure/hkdfguard-go/securefile v0.9.1
	go.opentelemetry.io/otel v1.47.0
	go.opentelemetry.io/otel/metric v1.47.0
	go.opentelemetry.io/otel/sdk/metric v1.47.0
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/otel/log v1.47.0 // indirect
	go.opentelemetry.io/otel/sdk v1.47.0 // indirect
	go.opentelemetry.io/otel/trace v1.47.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
)

replace (
	github.com/runsecure/hkdfguard-go => ../..
	github.com/runsecure/hkdfguard-go/cache/filepersecret => ../filepersecret
	github.com/runsecure/hkdfguard-go/cryptoprovider/aesgcm256 => ../../cryptoprovider/aesgcm256
	github.com/runsecure/hkdfguard-go/pipeline => ../../pipeline
	github.com/runsecure/hkdfguard-go/securefile => ../../securefile
)
