// Package daemon provide functions to control execution of deamons
package daemon

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"golang.org/x/exp/slog"
)

// isDaemonProcess is set to true when the current process is the long-running
// daemon (as opposed to a short-lived CLI invocation like "netclient join").
// This lets restart logic choose between self-signalling (safe inside the
// daemon) and going through the service manager (required from CLI).
var isDaemonProcess bool

// SetDaemonMode marks the current process as the running daemon.
func SetDaemonMode() {
	isDaemonProcess = true
}

// Install - Calls the correct function to install the netclient as a daemon service on the given operating system.
func Install() error {
	return install()
}

// Restart - restarts a system daemon
func Restart() error {
	ncutils.TraceCaller()
	return restart()
}

// Start - starts system daemon using signals (unix) or init system (windows)
func Start() error {
	return start()
}

// HardRestart - restarts system daemon using init system
func HardRestart() error {
	ncutils.TraceCaller()
	return hardRestart()
}

// Stop - stops a system daemon
func Stop() error {
	return stop()
}

func CleanUp() error {
	return cleanUp()
}

// RemoveAllLockFiles - removes all lock files used by netclient
func RemoveAllLockFiles() {
	// remove config lockfile
	lockfile := filepath.Join(os.TempDir(), config.ConfigLockfile)
	err := os.Remove(lockfile)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		slog.Error("failed to remove config lockfile", "err", err)
	}

	// remove node lockfile
	lockfile = filepath.Join(os.TempDir(), config.NodeLockfile)
	err = os.Remove(lockfile)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		slog.Error("failed to remove node lockfile", "err", err)
	}

	// remove server lockfile
	lockfile = filepath.Join(os.TempDir(), config.ServerLockfile)
	err = os.Remove(lockfile)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		slog.Error("failed to remove server lockfile", "err", err)
	}

	// remove netclient lock file
	lockfile = filepath.Join(os.TempDir(), "netclient-lock")
	err = os.Remove(lockfile)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		slog.Error("failed to remove netclient lockfile", "err", err)
	}
}
