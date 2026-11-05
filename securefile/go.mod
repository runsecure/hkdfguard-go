module github.com/runsecure/hkdfguard-go/securefile

go 1.27.1

toolchain go1.27.3

require (
	github.com/runsecure/hkdfguard-go v0.9.1
	golang.org/x/sys v0.49.0
)

replace github.com/runsecure/hkdfguard-go => ../
