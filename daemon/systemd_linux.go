package daemon

import (
	"errors"
	"os"

	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"golang.org/x/exp/slog"
)

// setupSystemDDaemon - sets system daemon for supported machines
func setupSystemDDaemon() error {
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
		err := os.WriteFile("/etc/systemd/system/netclient.service", servicebytes, 0644)
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

// restartSystemD - tells system to restart systemd
func restartSystemD() error {
	slog.Info("restarting netclient service")
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
