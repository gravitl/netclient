package functions

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/daemon"
	"golang.org/x/exp/slog"
)

// Install - installs binary/daemon
func Install() error {
	source, err := os.Executable()
	if err != nil {
		return err
	}
	destination := config.GetNetclientInstallPath()
	if source == destination {

		fmt.Println("attempting to reinstall netclient on top of itself")
		fmt.Println("  specify the full path of the new binary")
		fmt.Println("  eg ./netclient install")
		return errors.New("path error")
	}
	_ = daemon.Stop()
	time.Sleep(time.Second << 1)
	if err := daemon.Install(); err != nil {
		slog.Error("daemon install error", "error", err)
		return err
	}
	config.Netclient().DaemonInstalled = true
	_ = config.WriteNetclientConfig()
	return daemon.Restart()
}
