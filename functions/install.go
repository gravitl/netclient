package functions

import (
	"time"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/daemon"
	"github.com/gravitl/netmaker/logger"
)

// Install - installs binary/daemon
func Install() error {
	//TODO --- check for SUDO
	daemon.Stop()
	if err := daemon.InstallDaemon(); err != nil {
		logger.Log(0, "error installing daemon", err.Error())
		return err
	}
	config.Netclient.DaemonInstalled = true
	config.WriteNetclientConfig()
	time.Sleep(time.Second * 5)
	return daemon.Restart()
}
