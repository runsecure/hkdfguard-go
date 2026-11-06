//go:build !linux

package systemdcredentials

import "os/exec"

// killProcessGroupOnCancel leaves cancelling cmd to kill it alone: systemd-creds runs only on
// Linux, and New refuses anywhere else, so off Linux only the tests run a process here.
func killProcessGroupOnCancel(*exec.Cmd) {}
