package daemon

import (
	"errors"
	"os"

	"github.com/gravitl/netclient/ncutils"
	"golang.org/x/exp/slog"
)

// setupInitd - sets up initd daemon
func setupInitd() error {
	slog.Info("initd not supported")
	return errors.New("initd not supported")
}

// startInitd - starts initd daemon
func startInitd() error {
	slog.Info("starting netclient service")
	_, err := ncutils.RunCmd("/etc/init.d/netclient start", true)
	return err
}

// stopInitd - stops initd daemon
func stopInitd() error {
	slog.Info("stopping netclient service")
	_, err := ncutils.RunCmd("/etc/init.d/netclient stop", true)
	return err
}

// removeInitd - removes initd daemon
func removeInitd() error {
	var faults string
	if _, err := ncutils.RunCmd("/etc/init.d/netclient disable", true); err != nil {
		faults = faults + err.Error()
	}
	if ncutils.FileExists("/etc/init.d/netclient") {
		if err := os.Remove("/etc/init.d/netclient"); err != nil {
			slog.Info("Error removing /etc/init.d/netclient. Please investigate.")
			faults = faults + err.Error()
		}
	}
	if faults != "" {
		return errors.New(faults)
	}
	return nil
}
