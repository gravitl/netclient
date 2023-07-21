package daemon

import (
	"errors"
	"os"
	"runtime"
	"strings"
	"syscall"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"golang.org/x/exp/slog"
)

const ExecDir = "/sbin/"

func install() error {
	switch config.Netclient().InitType {
	case config.Systemd:
		return setupSystemDDaemon()
	case config.SysVInit:
		return setupSysVint()
	case config.OpenRC:
		return setupOpenRC()
	case config.Runit:
		return setuprunit()
	case config.Initd:
		return setupInitd()
	default:
		return errors.New("unsupported init type")
	}
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

func GetInitType() config.InitType {
	slog.Debug("getting init type", "os", runtime.GOOS)
	if runtime.GOOS != "linux" {
		return config.UnKnown
	}
	out, err := ncutils.RunCmd("ls -l /sbin/init", false)
	if err != nil {
		slog.Error("error checking /sbin/init", "error", err)
		return config.UnKnown
	}
	slog.Debug("checking /sbin/init", "output ", out)
	if strings.Contains(out, "systemd") {
		// ubuntu, debian, fedora, suse, etc
		return config.Systemd
	}
	if strings.Contains(out, "runit-init") {
		// void linux
		return config.Runit
	}
	if strings.Contains(out, "busybox") {
		// alpine
		return config.OpenRC
	}
	out, err = ncutils.RunCmd("ls -l /bin/busybox", false)
	if err != nil {
		slog.Error("error checking /bin/busybox", "error", err)
		return config.UnKnown
	}
	if strings.Contains(out, "busybox") {
		// openwrt
		return config.Initd
	}
	out, err = ncutils.RunCmd("ls -l /etc/init.d", false)
	if err != nil {
		slog.Error("error checking /etc/init.d", "error", err)
		return config.UnKnown
	}
	if strings.Contains(out, "README") {
		// MXLinux
		return config.SysVInit
	}
	return config.UnKnown
}
