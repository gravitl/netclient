// Package daemon provide functions to control execution of deamons
package daemon

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/logger"
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

// IsDaemonProcess reports whether this process is the long-running daemon.
func IsDaemonProcess() bool {
	return isDaemonProcess
}

var (
	inProcessResetMu sync.Mutex
	inProcessResetFn func(done chan struct{})
)

// SetInProcessReset registers the function the daemon uses to rebuild its
// goroutines without exiting. The callback receives a channel to close when
// the rebuild has finished. A Windows service restart drops the desktop API.
func SetInProcessReset(fn func(done chan struct{})) {
	inProcessResetMu.Lock()
	inProcessResetFn = fn
	inProcessResetMu.Unlock()
}

// RequestInProcessReset asks the daemon to rebuild in place and reports when
// that rebuild has finished. Nil means no daemon is listening.
func RequestInProcessReset() <-chan struct{} {
	inProcessResetMu.Lock()
	fn := inProcessResetFn
	inProcessResetMu.Unlock()
	if fn == nil {
		return nil
	}
	done := make(chan struct{})
	fn(done)
	return done
}

// Install - Calls the correct function to install the netclient as a daemon service on the given operating system.
func Install() error {
	return install()
}

// Restart - restarts a system daemon
func Restart() error {
	logRestartRequest("restart")
	return restart()
}

// Start - starts system daemon using signals (unix) or init system (windows)
func Start() error {
	return start()
}

// HardRestart - restarts system daemon using init system
func HardRestart() error {
	logRestartRequest("hard restart")
	return hardRestart()
}

// logRestartRequest names the caller at verbosity 1 (debug). Kept on logger.Log
// rather than slog.Debug so it still appears when -v is raised on Windows,
// where the service log drops slog.Debug.
func logRestartRequest(kind string) {
	caller := "unknown"
	if pc, file, line, ok := runtime.Caller(2); ok {
		name := "unknown"
		if fn := runtime.FuncForPC(pc); fn != nil {
			name = fn.Name()
		}
		caller = fmt.Sprintf("%s (%s:%d)", name, filepath.Base(file), line)
	}
	logger.Log(3, fmt.Sprintf("daemon %s requested by %s", kind, caller))
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
