module github.com/runsecure/hkdfguard-go/securefile

go 1.27.1

toolchain go1.27.2

require (
	github.com/runsecure/hkdfguard-go v0.0.0-00010101000000-000000000000
	golang.org/x/sys v0.48.0
)

replace github.com/runsecure/hkdfguard-go => ../
