package wireguard

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const disconnectError = "node disconnected"

// ApplyWithoutWGQuick - Function for running the equivalent of "wg-quick up" for linux if wg-quick is missing
func ApplyWithoutWGQuick(node *config.Node, ifacename, confPath string, isConnected bool) error {

	ipExec, err := exec.LookPath("ip")
	if err != nil {
		return err
	}
	wgclient, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer wgclient.Close()
	var conf wgtypes.Config
	if node.UDPHolePunch && !node.IsServer && !node.IsIngressGateway {
		conf = wgtypes.Config{
			PrivateKey: &node.PrivateKey,
		}
	} else {
		conf = wgtypes.Config{
			PrivateKey: &node.PrivateKey,
			ListenPort: &node.ListenPort,
		}
	}
	err = setKernelDevice(ifacename, node.Address, node.Address6, isConnected)
	if err != nil {
		if err.Error() == disconnectError {
			return nil
		}
	}
	_, err = wgclient.Device(ifacename)
	if err != nil {
		if !os.IsNotExist(err) {
			return errors.New("Unknown config error: " + err.Error())
		}
	}
	err = wgclient.ConfigureDevice(ifacename, conf)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Log(0, "Could not configure device: ", err.Error())
		}
	}
	if _, err := ncutils.RunCmd(ipExec+" link set down dev "+ifacename, false); err != nil {
		logger.Log(1, "attempted to remove interface before editing")
		return err
	}
	if node.PostDown != "" {
		ncutils.RunCmd(node.PostDown, false)
	}
	// set MTU of node interface
	if _, err := ncutils.RunCmd(ipExec+" link set mtu "+strconv.Itoa(node.MTU)+" up dev "+ifacename, true); err != nil {
		logger.Log(1, "failed to create interface with mtu ", strconv.Itoa(node.MTU), "-", ifacename)
		return err
	}
	if node.PostUp != "" {
		ncutils.RunCmd(node.PostUp, false)
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
	network := strings.ReplaceAll(ifacename, "nm-", "")
	node := config.Nodes[network]
	if node.PostDown != "" {
		if _, err := ncutils.RunCmd(node.PostDown, false); err != nil {
			return err
		}
	}
	return nil
}

func setKernelDevice(ifacename string, address4, address6 net.IPNet, isConnected bool) error {
	ipExec, err := exec.LookPath("ip")
	if err != nil {
		return err
	}
	// == best effort ==
	ncutils.RunCmd("ip link delete dev "+ifacename, false)
	if !isConnected {
		return fmt.Errorf(disconnectError)
	}
	ncutils.RunCmd(ipExec+" link add dev "+ifacename+" type wireguard", true)
	if address4.IP != nil {
		ncutils.RunCmd(ipExec+" address add dev "+ifacename+" "+address4.String(), true)
	}
	if address6.IP != nil {
		ncutils.RunCmd(ipExec+" address add dev "+ifacename+" "+address6.String(), true)
	}
	return nil
}
