//go:build !unix

package scanner

import (
	"os/exec"
	"time"
)

// ownGroup: no process groups here; the tool itself is killed, and a pipe a
// child still holds is not waited on for ever.
func ownGroup(cmd *exec.Cmd) { cmd.WaitDelay = 10 * time.Second }
