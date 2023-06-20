//go:build linux || darwin || freebsd
// +build linux darwin freebsd

package daemon

import (
	"fmt"
	"os"
	"syscall"

	"github.com/gravitl/netclient/ncutils"
	"golang.org/x/exp/slog"
)

// restart - restarts a system daemon
func restart() error {
	return signalDaemon(syscall.SIGHUP)
}

func signalDaemon(s syscall.Signal) error {
	pid, err := ncutils.ReadPID()
	if err != nil {
		return fmt.Errorf("failed to find pid %w", err)
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("failed to find running process for pid %d -- %w", pid, err)
	}
	slog.Info("Sending", "signal", s, "to PID", p)
	if err := p.Signal(s); err != nil {
		return fmt.Errorf("%s failed -- %w", s, err)
	}
	return nil
}
