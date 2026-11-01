//go:build !windows

package shell

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

var sprintf = fmt.Sprintf

// setProcGroup puts the command (and anything it spawns) in its own process
// group, so an interrupt reaches all of it without touching the shell.
func setProcGroup(c *exec.Cmd) { c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }

func signalGroup(p *os.Process, kill bool) {
	sig := syscall.SIGINT
	if kill {
		sig = syscall.SIGKILL
	}
	_ = syscall.Kill(-p.Pid, sig)
}

func rawShellCmd(line string) *exec.Cmd { return exec.Command("/bin/sh", "-c", line) }
