//go:build linux

package systemdcredentials

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const pidFileVariable = "HKDFGUARD_SYSTEMDCREDS_TEST_PIDFILE"

// spawnHangingChild starts a child that hangs - in the helper's own process group, as a process
// systemd-creds started would be - writes its pid to the pid file, and hangs too.
func spawnHangingChild() int {
	executable, _ := os.Executable()
	child := exec.Command(executable)
	child.Env = append(os.Environ(), helperVariable+"=hang")
	if err := child.Start(); err != nil {
		return 98
	}
	_ = os.WriteFile(os.Getenv(pidFileVariable), []byte(strconv.Itoa(child.Process.Pid)), 0o600)
	time.Sleep(time.Minute)
	return 0
}

// On Linux a timeout kills systemd-creds' whole process group: nothing it started outlives it.
func TestATimeout_KillsEveryProcessSystemdCredsStarted(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "pid")
	t.Setenv(pidFileVariable, pidFile)

	if _, err := runHelper(t, t.Context(), "spawn", nil, 2*time.Second); !errors.Is(err, ErrTimeout) {
		t.Fatalf("got %v", err)
	}
	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("the helper never started its child: %v", err)
	}
	pid, _ := strconv.Atoi(string(data))

	deadline := time.Now().Add(10 * time.Second)
	for !isGone(pid) {
		if time.Now().After(deadline) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			t.Fatalf("the child %d outlived the timeout", pid)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// isGone reports whether pid no longer runs: it doesn't exist, or is a zombie awaiting its reaper.
func isGone(pid int) bool {
	if syscall.Kill(pid, 0) == syscall.ESRCH {
		return true
	}
	stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return true
	}
	fields := strings.Fields(string(stat[strings.LastIndexByte(string(stat), ')')+1:]))
	return len(fields) > 0 && fields[0] == "Z"
}
