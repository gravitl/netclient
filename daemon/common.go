// Package daemon provide functions to control execution of deamons
package daemon

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/gravitl/netclient/config"
	"golang.org/x/exp/slog"
)

// Install - Calls the correct function to install the netclient as a daemon service on the given operating system.
func Install() error {
	return install()
}

// Restart - restarts a system daemon
func Restart() error {
	return restart()
}

// Start - starts system daemon using signals (unix) or init system (windows)
func Start() error {
	if err := removeAllLockFiles(); err != nil {
		slog.Error("failed to remove all lockfiles. remove them manually and restart daemon", "err", err)
	}
	return start()
}

// HardRestart - restarts system daemon using init system
func HardRestart() error {
	return hardRestart()
}

// Stop - stops a system daemon
func Stop() error {
	return stop()
}

func CleanUp() error {
	return cleanUp()
}

// removeAllLockFiles - removes all lock files used by netclient
func removeAllLockFiles() error {
	// remove config lockfile
	lockfile := filepath.Join(os.TempDir(), config.ConfigLockfile)
	err := os.Remove(lockfile)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	// remove node lockfile
	lockfile = filepath.Join(os.TempDir(), config.NodeLockfile)
	err = os.Remove(lockfile)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	// remove server lockfile
	lockfile = filepath.Join(os.TempDir(), config.ServerLockfile)
	err = os.Remove(lockfile)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	// remove gui lock file
	lockfile = filepath.Join(os.TempDir(), config.GUILockFile)
	err = os.Remove(lockfile)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	// remove netclient lock file
	lockfile = filepath.Join(os.TempDir(), "netclient-lock")
	err = os.Remove(lockfile)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	return nil
}
