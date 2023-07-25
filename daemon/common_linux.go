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

// restart - restarts daemon
func hardRestart() error {
	host := config.Netclient()
	if host.DaemonInstalled {
		if _, err := os.Stat("/usr/bin/systemctl"); err == nil {
			return restartSystemD()
		}
	} else {
		return errors.New("systemd not installed .. daemon not started")
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

// setupSystemDDaemon - sets system daemon for supported machines
func setupSystemDDaemon() error {
	binarypath, err := os.Executable()
	if err != nil {
		return err
	}
	//install binary
	if ncutils.FileExists(ExecDir + "netclient") {
		logger.Log(0, "updating netclient binary in", ExecDir)
	}
	err = ncutils.Copy(binarypath, ExecDir+"netclient")
	if err != nil {
		logger.Log(0, err.Error())
		return err
	}
	systemservice := `[Unit]
Description=Netclient Daemon
Documentation=https://docs.netmaker.org https://k8s.netmaker.org
After=network-online.target
Wants=network-online.target

[Service]
User=root
Type=simple
ExecStartPre=/bin/sleep 17
ExecStart=/sbin/netclient daemon
Restart=on-failure
RestartSec=15s

[Install]
WantedBy=multi-user.target
`

	servicebytes := []byte(systemservice)

	if !ncutils.FileExists("/etc/systemd/system/netclient.service") {
		err = os.WriteFile("/etc/systemd/system/netclient.service", servicebytes, 0644)
		if err != nil {
			logger.Log(0, err.Error())
			return err
		}
	}
	_, _ = ncutils.RunCmd("systemctl enable netclient.service", true)
	_, _ = ncutils.RunCmd("systemctl daemon-reload", true)
	return nil
}

// startSystemD - starts systemd service
func startSystemD() error {
	logger.Log(3, "calling systemctl start netclient")
	_, err := ncutils.RunCmd("systemctl start netclient.service", false)
	return err
}

// stopSystemD - tells system to stop systemd
func stopSystemD() error {
	logger.Log(3, "calling systemctl stop netclient")
	_, err := ncutils.RunCmd("systemctl stop netclient.service", false)
	return err
}

// restartSystemD - restarts systemd service
func restartSystemD() error {
	logger.Log(3, "calling systemctl restart netclient")
	_, err := ncutils.RunCmd("systemctl restart netclient.service", false)
	return err
}

// removeSystemDServices - removes the systemd services on a machine
func removeSystemDServices() error {
	//sysExec, err := exec.LookPath("systemctl")
	var faults string

	if _, err := ncutils.RunCmd("systemctl disable netclient.service", false); err != nil {
		faults = faults + err.Error()
	}
	if ncutils.FileExists("/etc/systemd/system/netclient.service") {
		if err := os.Remove("/etc/systemd/system/netclient.service"); err != nil {
			logger.Log(0, "Error removing /etc/systemd/system/netclient.service. Please investigate.")
			faults = faults + err.Error()
		}
	}
	if _, err := ncutils.RunCmd("systemctl daemon-reload", false); err != nil {
		faults = faults + err.Error()
	}
	if _, err := ncutils.RunCmd("systemctl reset-failed", false); err != nil {
		faults = faults + err.Error()

	}
	logger.Log(0, "removed systemd remnants if any existed")
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
		return config.OpenRC
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
