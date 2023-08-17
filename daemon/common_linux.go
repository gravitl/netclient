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
	slog.Info("installing netclient binary")
	binarypath, err := os.Executable()
	if err != nil {
		return err
	}
	if ncutils.FileExists(ExecDir + "netclient") {
		slog.Info("updating netclient binary in", "path", ExecDir)
	}
	err = ncutils.Copy(binarypath, ExecDir+"netclient")
	if err != nil {
		slog.Error(err.Error())
		return err
	}

	slog.Info("install netclient service file")
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
	host := config.Netclient()
	if !host.DaemonInstalled {
		slog.Warn("netclient daemon not installed")
	}
	switch host.InitType {
	case config.Systemd:
		return startSystemD()
	case config.SysVInit:
		return startSysVinit()
	case config.OpenRC:
		return startOpenRC()
	case config.Runit:
		return startrunit()
	case config.Initd:
		return startInitd()
	default:
		return errors.New("unsupported init type")
	}
}

// stop - stops daemon
func stop() error {
	host := config.Netclient()
	if !host.DaemonInstalled {
		slog.Warn("netclient daemon not installed")
	}
	switch host.InitType {
	case config.Systemd:
		return stopSystemD()
	case config.SysVInit:
		return stopSysVinit()
	case config.OpenRC:
		return stopOpenRC()
	case config.Runit:
		return stoprunit()
	case config.Initd:
		return stopInitd()
	default:
		return signalDaemon(syscall.SIGTERM)
	}
}

// restart - restarts daemon
func hardRestart() error {
	host := config.Netclient()
	if !host.DaemonInstalled {
		slog.Warn("netclient daemon not installed")
	}
	switch host.InitType {
	case config.Systemd:
		return restartSystemD()
	case config.SysVInit:
		return restartSysVinit()
	case config.OpenRC:
		return restartOpenRC()
	case config.Runit:
		return restartrunit()
	case config.Initd:
		return restartInitd()
	default:
		return errors.New("unsupported init type")
	}
}

// cleanUp - cleans up neclient configs
func cleanUp() error {
	var faults string
	host := config.Netclient()
	if host.DaemonInstalled {
		slog.Info("stopping netclient service")
		if err := stop(); err != nil {
			logger.Log(0, "failed to stop netclient service", err.Error())
			faults = "failed to stop netclient service: "
		}
		slog.Info("removing netclient service")
		var err error
		switch host.InitType {
		case config.Systemd:
			err = removeSystemDServices()
		case config.SysVInit:
			err = removeSysVinit()
		case config.OpenRC:
			err = removeOpenRC()
		case config.Runit:
			err = removerunit()
		case config.Initd:
			err = removeInitd()
		default:
			err = errors.New("unsupported init type")
		}
		if err != nil {
			faults = faults + err.Error()
		}
	}
	slog.Info("removing netclient config files")
	if err := os.RemoveAll(config.GetNetclientPath()); err != nil {
		slog.Error("Removing netclient configs:", "error", err)
		faults = faults + err.Error()
	}
	slog.Info("removing netclient binary")
	if err := os.Remove(ExecDir + "netclient"); err != nil {
		slog.Error("Removing netclient binary:", "error", err)
		faults = faults + err.Error()
	}
	slog.Info("removing netclient log")
	if host.InitType == config.Systemd || host.InitType == config.Initd {
		slog.Info("log files not removed for systemd or initd", "init type", host.InitType)
	} else {
		if err := os.Remove("/var/log/netclient.log"); err != nil {
			slog.Error("Removing netclient log:", "error", err)
			faults = faults + err.Error()
		}
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
