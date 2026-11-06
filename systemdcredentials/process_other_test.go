//go:build !linux

package systemdcredentials

// spawnHangingChild is only the Linux process-group test's.
func spawnHangingChild() int { return 99 }
