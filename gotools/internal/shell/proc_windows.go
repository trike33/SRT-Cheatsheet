//go:build windows

package shell

import (
	"fmt"
	"os"
	"os/exec"
)

var sprintf = fmt.Sprintf

func setProcGroup(c *exec.Cmd) {}

// Windows has no SIGINT for child processes; stopping means killing.
func signalGroup(p *os.Process, kill bool) { _ = p.Kill() }
