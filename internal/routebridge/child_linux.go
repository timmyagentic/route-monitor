//go:build linux

package routebridge

import (
	"os/exec"
	"syscall"
)

func hardenChild(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}
