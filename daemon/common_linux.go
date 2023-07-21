package daemon

import (
	"errors"
	"os"
	"syscall"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/logger"
)

const ExecDir = "/sbin/"

func install() error {
	if _, err := os.Stat("/usr/bin/systemctl"); err == nil {
		return setupSystemDDaemon()
	}
	return errors.New("systemd not installed .. daemon not installed")
}

// start - starts daemon
func start() error {
	if _, err := os.Stat("/usr/bin/systemctl"); err == nil {
		return startSystemD()
	}
	return errors.New("systemd not installed .. daemon not started")
}

// stop - stops daemon
func stop() error {
	host := config.Netclient()
	if host.DaemonInstalled {
		if _, err := os.Stat("/usr/bin/systemctl"); err == nil {
			return stopSystemD()
		}
	} else {
		return signalDaemon(syscall.SIGTERM)
	}
	return nil
}

// cleanUp - cleans up neclient configs
func cleanUp() error {
	var faults string
	host := config.Netclient()
	if host.DaemonInstalled {
		if err := stop(); err != nil {
			logger.Log(0, "failed to stop netclient service", err.Error())
			faults = "failed to stop netclient service: "
		}
		if err := removeSystemDServices(); err != nil {
			faults = faults + err.Error()
		}
	} else if err := stop(); err != nil {
		logger.Log(0, "failed to stop netclient process", err.Error())
		faults = "failed to stop netclient process: "
	}
	if err := os.RemoveAll(config.GetNetclientPath()); err != nil {
		logger.Log(1, "Removing netclient configs: ", err.Error())
		faults = faults + err.Error()
	}
	if err := os.Remove(ExecDir + "netclient"); err != nil {
		logger.Log(1, "Removing netclient binary: ", err.Error())
		faults = faults + err.Error()
	}
	if faults != "" {
		return errors.New(faults)
	}
	return nil
}
