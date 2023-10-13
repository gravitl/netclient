package daemon

import (
	"errors"
	"os"

	"github.com/gravitl/netclient/ncutils"
	"golang.org/x/exp/slog"
)

// setupOpenRC - sets up openrc daemon
func setupOpenRC() error {
	service := `#!/sbin/openrc-run

description="netclient daemon"
pidfile="/var/run/netclient.pid"
command="/sbin/netclient"
command_args="daemon"
command_user="root"
RC_SVCNAME="netclient"
supervisor="supervise-daemon"
output_log="/var/log/netclient.log"
error_log="/var/log/netclient.log"
depend() {
	need net
	after firewall
}
reload() {
	ebegin "Reloading netclient configuration"
	${supervisor} ${RC_SVCNAME} --signal HUP --pidfile "${pidfile}"
	eend $?
}
`
	bytes := []byte(service)
	if err := os.WriteFile("/etc/init.d/netclient", bytes, 0755); err != nil {
		return err
	}
	if _, err := ncutils.RunCmd("/sbin/rc-update add netclient default", false); err != nil {
		return err
	}
	return nil
}

func startOpenRC() error {
	slog.Info("starting netclient service")
	return nil
	_, err := ncutils.RunCmd("/sbin/rc-service netclient start -N", false)
	return err
}

func stopOpenRC() error {
	slog.Info("stopping netclient service")
	_, err := ncutils.RunCmd("/sbin/rc-service netclient stop -s", false)
	return err
}

func restartOpenRC() error {
	slog.Info("restarting netclient service")
	_, err := ncutils.RunCmd("/sbin/rc-service netclient restart", false)
	return err
}

func removeOpenRC() error {
	var faults string
	if _, err := ncutils.RunCmd("/sbin/rc-update del netclient -a", false); err != nil {
		faults = faults + err.Error()
	}
	if ncutils.FileExists("/etc/init.d/netclient") {
		if err := os.Remove("/etc/init.d/netclient"); err != nil {
			faults = faults + err.Error()
		}
	}
	if faults != "" {
		return errors.New(faults)
	}
	return nil
}
