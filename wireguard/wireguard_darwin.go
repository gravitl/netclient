package wireguard

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/gravitl/netmaker/logger"
)

// NCIface.Create - makes a new Wireguard interface for darwin users (userspace)
func (nc *NCIface) Create() error {

	return nc.createUserSpaceWG()
}

// NCIface.ApplyAddrs - applies address for darwin userspace
func (nc *NCIface) ApplyAddrs() error {

	cmd := exec.Command("ifconfig", getName(), "inet", nc.Address.IP.String(), nc.Address.IP.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		logger.Log(0, fmt.Sprintf("adding addreess command \"%v\" failed with output %s and error: ", cmd.String(), out))
		return err
	}

	if nc.Address.Network.IP != nil {
		if nc.Address.Network.IP.To4() != nil {
			cmd = exec.Command("route", "add", "-net", nc.Address.Network.String(), "-interface", getName())
			if out, err := cmd.CombinedOutput(); err != nil {
				logger.Log(0, fmt.Sprintf("failed to add route with command %s - %v", cmd.String(), out))
				return err
			}
		} else {
			cmd = exec.Command("route", "add", "-inet6", nc.Address.Network.String(), "-interface", getName())
			if out, err := cmd.CombinedOutput(); err != nil {
				logger.Log(0, fmt.Sprintf("failed to add route with command %s - %v", cmd.String(), out))
				return err
			}
		}

	}
	// set MTU for the interface
	cmd = exec.Command("ifconfig", getName(), "mtu", fmt.Sprint(nc.MTU), "up")
	if out, err := cmd.CombinedOutput(); err != nil {
		logger.Log(0, fmt.Sprintf("failed to set mtu with command %s - %v", cmd.String(), out))
		return err
	}
	return nil
}

func (nc *NCIface) Close() {
	err := nc.Iface.Close()
	if err == nil {
		sockPath := "/var/run/wireguard/" + getName() + ".sock"
		if _, statErr := os.Stat(sockPath); statErr == nil {
			os.Remove(sockPath)
		}
	}

}
