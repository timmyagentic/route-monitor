//go:build !linux

package routebridge

import "os/exec"

func hardenChild(cmd *exec.Cmd) {}
