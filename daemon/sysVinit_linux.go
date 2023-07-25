package daemon

import (
	"errors"

	"golang.org/x/exp/slog"
)

// setupSysVint - sets up sysVinit daemon
func setupSysVint() error {
	slog.Info("sysV not supported")
	return errors.New("sysV not supported")
}

// startSysVinit - starts sysVinit daemon
func startSysVinit() error {
	slog.Info("sysV not supported")
	return errors.New("sysV not supported")
}

// stopSysVinit - stops sysVinit daemon
func stopSysVinit() error {
	slog.Info("sysV not supported")
	return errors.New("sysV not supported")
}

// restartSysVinit - restarts sysVinit daemon
func restartSysVinit() error {
	slog.Info("sysV not supported")
	return errors.New("sysV not supported")
}

// removeSysVinit - removes sysVinit daemon
func removeSysVinit() error {
	slog.Info("sysV not supported")
	return errors.New("sysV not supported")
}
