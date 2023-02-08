package wireguard

import (
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"golang.zx2c4.com/wireguard/wgctrl"
)

const disconnectError = "node disconnected"

// ApplyWithoutWGQuick - Function for running the equivalent of "wg-quick up" for linux if wg-quick is missing
func ApplyWithoutWGQuick(nc *NCIface) error {
	ipExec, err := exec.LookPath("ip")
	if err != nil {
		return err
	}
	wgclient, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer wgclient.Close()
	err = setKernelDevice(nc)
	if err != nil {
		if err.Error() == disconnectError {
			return nil
		}
	}
	_, err = wgclient.Device(nc.Name)
	if err != nil {
		if !os.IsNotExist(err) {
			return errors.New("Unknown config error: " + err.Error())
		}
	}
	err = wgclient.ConfigureDevice(nc.Name, nc.Config)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Log(0, "Could not configure device: ", err.Error())
		}
	}
	if _, err := ncutils.RunCmd(ipExec+" link set down dev "+nc.Name, false); err != nil {
		logger.Log(1, "attempted to remove interface before editing")
		return err
	}
	// set MTU of node interface
	if _, err := ncutils.RunCmd(ipExec+" link set mtu "+strconv.Itoa(config.Netclient().MTU)+" up dev "+nc.Name, true); err != nil {
		logger.Log(1, "failed to create interface with mtu ", strconv.Itoa(config.Netclient().MTU), "-", nc.Name)
		return err
	}
	return nil
}

// RemoveWithoutWGQuick - Function for running the equivalent of "wg-quick down" for linux if wg-quick is missing
func RemoveWithoutWGQuick(ifacename string) error {
	ipExec, err := exec.LookPath("ip")
	if err != nil {
		return err
	}
	out, err := ncutils.RunCmd(ipExec+" link del "+ifacename, false)
	dontprint := strings.Contains(out, "does not exist") || strings.Contains(out, "Cannot find device")
	if err != nil && !dontprint {
		logger.Log(1, out)
	}
	return nil
}

func setKernelDevice(nc *NCIface) error {
	ipExec, err := exec.LookPath("ip")
	if err != nil {
		return err
	}
	// == best effort ==
	ncutils.RunCmd("ip link delete dev "+nc.Name, false)
	//wait for a bit
	time.Sleep(time.Millisecond * 500)
	ncutils.RunCmd(ipExec+" link add dev "+nc.Name+" type wireguard", true)
	for _, node := range config.GetNodes() {
		if !node.Connected {
			continue
		}
		if node.Address.IP != nil {
			ncutils.RunCmd(ipExec+" address add dev "+nc.Name+" "+node.Address.String(), true)
		}
		if node.Address6.IP != nil {
			ncutils.RunCmd(ipExec+" address add dev "+nc.Name+" "+node.Address6.String(), true)
		}
	}
	return nil
}
