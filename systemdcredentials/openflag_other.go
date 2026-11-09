//go:build !linux

package systemdcredentials

// nonBlockingOpenFlag is nothing off Linux, where systemd credentials don't exist and only the
// tests read one.
const nonBlockingOpenFlag = 0
