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

	for _, address := range nc.Addresses {
		if !address.AddRoute && address.IP != nil {
			if address.IP.To4() != nil {

				cmd := exec.Command("ifconfig", nc.Name, "inet", "alias", address.IP.String(), address.IP.String())
				if out, err := cmd.CombinedOutput(); err != nil {
					logger.Log(0, fmt.Sprintf("adding address command \"%v\" failed with output %s and error: ", cmd.String(), out))
					continue
				}
			} else {

				cmd := exec.Command("ifconfig", nc.Name, "inet6", "alias", address.IP.String(), address.IP.String())
				if out, err := cmd.CombinedOutput(); err != nil {
					logger.Log(0, fmt.Sprintf("adding address command \"%v\" failed with output %s and error: ", cmd.String(), out))
					continue
				}
			}

		}
		if address.Network.IP != nil {
			if address.Network.IP.To4() != nil {
				cmd := exec.Command("route", "add", "-net", "-inet", address.Network.String(), "-interface", nc.Name)
				if out, err := cmd.CombinedOutput(); err != nil {
					logger.Log(0, fmt.Sprintf("failed to add route with command %s - %v", cmd.String(), out))
					continue
				}
			} else {
				cmd := exec.Command("route", "add", "-net", "-inet6", address.Network.String(), "-interface", nc.Name)
				if out, err := cmd.CombinedOutput(); err != nil {
					logger.Log(0, fmt.Sprintf("failed to add route with command %s - %v", cmd.String(), out))
					continue
				}
			}
		}
	}

	return nil
}

func (nc *NCIface) SetMTU() error {
	// set MTU for the interface
	cmd := exec.Command("ifconfig", nc.Name, "mtu", fmt.Sprint(nc.MTU), "up")
	if out, err := cmd.CombinedOutput(); err != nil {
		logger.Log(0, fmt.Sprintf("failed to set mtu with command %s - %v", cmd.String(), out))
		return err
	}
	return nil
}

func (nc *NCIface) Close() {
	err := nc.Iface.Close()
	if err == nil {
		sockPath := "/var/run/wireguard/" + nc.Name + ".sock"
		if _, statErr := os.Stat(sockPath); statErr == nil {
			os.Remove(sockPath)
		}
	}

}
