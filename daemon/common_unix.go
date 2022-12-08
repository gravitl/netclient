//go:build linux || darwin || freebsd
// +build linux darwin freebsd

package daemon

import (
	"fmt"
	"os"
	"syscall"

	"github.com/gravitl/netclient/ncutils"
)

// restart - restarts a system daemon
func restart() error {
	pid, err := ncutils.ReadPID()
	if err != nil {
		return fmt.Errorf("failed to find pid %w", err)
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("failed to find running process for pid %d -- %w", pid, err)
	}
	if err := p.Signal(syscall.SIGHUP); err != nil {
		return fmt.Errorf("SIGHUP failed -- %w", err)
	}
	return nil
}
