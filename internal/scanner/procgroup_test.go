//go:build unix

package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Cancelling a tool stops what it started too: shuffledns starts massdns,
// and killing only shuffledns left massdns resolving for a run already
// stopped, with the task waiting on the pipe it held.
func TestCancelKillsTheToolsChildren(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	start := time.Now()
	go func() {
		// sh starts a long sleep (the "massdns") that inherits its stdout.
		runTool(ctx, time.Minute, "", "sh", "-c", "sleep 300 & echo $! > "+pidFile+"; wait")
		close(done)
	}()
	var pid int
	for i := 0; i < 100 && pid == 0; i++ {
		time.Sleep(20 * time.Millisecond)
		if b, err := os.ReadFile(pidFile); err == nil {
			pid, _ = strconv.Atoi(strings.TrimSpace(string(b)))
		}
	}
	if pid == 0 {
		t.Fatal("the child never started")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("the tool did not return after cancel")
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Errorf("returned after %s; the child's pipe held it", took)
	}
	time.Sleep(100 * time.Millisecond)
	if err := syscall.Kill(pid, 0); err == nil {
		_ = syscall.Kill(pid, syscall.SIGKILL)
		t.Error("the child kept running after the tool was cancelled")
	}
}
