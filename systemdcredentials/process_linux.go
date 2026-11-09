//go:build linux

package systemdcredentials

import (
	"os/exec"
	"syscall"
)

// killProcessGroupOnCancel starts cmd as the leader of a process group of its own, and has
// cancelling it kill the whole group, so nothing systemd-creds started outlives it; the group is
// killed too if this process dies first.
func killProcessGroupOnCancel(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
