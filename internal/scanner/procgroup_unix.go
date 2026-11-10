//go:build unix

package scanner

import (
	"os/exec"
	"syscall"
	"time"
)

// ownGroup runs a tool in a process group of its own and, when its context
// ends — a timeout, or the task cancelled — kills the whole group. Killing
// only the process started leaves its children running: shuffledns starts
// massdns, which then went on resolving millions of names for a run already
// stopped, and held the output pipe open so the task did not end either.
func ownGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	// A pipe a grandchild still holds is not waited on for ever.
	cmd.WaitDelay = 10 * time.Second
}
