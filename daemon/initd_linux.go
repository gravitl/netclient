package daemon

import (
	"errors"
	"os"

	"github.com/gravitl/netclient/ncutils"
	"golang.org/x/exp/slog"
)

// setupInitd - sets up initd daemon
func setupInitd() error {
	service := `#!/bin/sh /etc/rc.common
	START=99
	STOP=99
	USE_PROCD=1
	
	start_service() {
        procd_open_instance
        procd_set_param command /sbin/netclient daemon
        procd_set_param stdout 1
        procd_set_param stderr 1
        procd_close_instance
}
`
	bytes := []byte(service)
	if err := os.WriteFile("/etc/init.d/netclient", bytes, 0755); err != nil {
		slog.Debug("error writing initd service file", "error", err)
		return err
	}
	if _, err := ncutils.RunCmd("/etc/init.d/netclient enable", false); err != nil {
		slog.Debug("error enabling initd service", "error", err)
		return err
	}
	return nil
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

// restartInitd - restarts initd daemon
func restartInitd() error {
	slog.Info("restarting netclient service")
	_, err := ncutils.RunCmd("/etc/init.d/netclient restart", true)
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
