package wireguard

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"

	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
)

const kernelModule = "/boot/modules/if_wg.ko"

// NCIface.Create - creates a linux WG interface based on a node's given config
func (nc *NCIface) Create() error {
	if _, err := os.Stat(kernelModule); err != nil {
		logger.Log(3, "using userspace wireguard")
		return nc.createUserSpaceWG()
	}
	logger.Log(3, "using kernel wireguard")
	return create(nc)
}

func create(nc *NCIface) error {
	ifconfig, err := exec.LookPath("ifconfig")
	if err != nil {
		return err
	}
	if _, err := ncutils.RunCmd(ifconfig+" "+nc.Name, false); err == nil {
		if _, err := ncutils.RunCmd(ifconfig+" "+nc.Name+" destroy", false); err != nil {
			return err
		}
	}
	if _, err := ncutils.RunCmd(ifconfig+" wg create name "+nc.Name, true); err != nil {
		return err
	}
	return nil
}

// NCIface.Close - removes wg network interface from machine
func (nc *NCIface) Close() {
	ifconfig, err := exec.LookPath("ifconfig")
	if err != nil {
		logger.Log(0, "failed to locate ifconfig", err.Error())
		return
	}
	if _, err := ncutils.RunCmd(ifconfig+" "+nc.Name+" destroy", true); err != nil {
		logger.Log(0, "error removing interface ", err.Error())
	}
}

// NCIface.ApplyAddrs - applies the assigned node addresses to given interface (netLink)
func (nc *NCIface) ApplyAddrs() error {
	ifconfig, err := exec.LookPath("ifconfig")
	if err != nil {
		logger.Log(0, "failed to locate ifconfig", err.Error())
		return fmt.Errorf("failed to locate ifconfig %w", err)
	}
	for _, address := range nc.Addresses {
		if !address.AddRoute && address.IP.To4() != nil {
			if _, err := ncutils.RunCmd(ifconfig+" "+nc.Name+" inet "+address.IP.String()+" alias", true); err != nil {
				return fmt.Errorf("error adding address to interface %w", err)
			}
		} else {
			if _, err := ncutils.RunCmd(ifconfig+" "+nc.Name+" inet6 "+address.IP.String()+" alias", true); err != nil {
				return fmt.Errorf("error adding address to interface %w", err)
			}
		}
		if address.AddRoute {
			if address.IP.To4() != nil {
				if _, err := ncutils.RunCmd(fmt.Sprintf("route add -net -inet %s -interface %s", address.Network.String(), nc.Name), true); err != nil {
					return fmt.Errorf("error adding address to interface %w", err)
				}
			} else {
				if _, err := ncutils.RunCmd(fmt.Sprintf("route add -net -inet6 %s -interface %s", address.Network.String(), nc.Name), true); err != nil {
					return fmt.Errorf("error adding address to interface %w", err)
				}
			}

		}
	}
	return nil
}

// NCIface.SetMTU - set MTU for netmaker interface
func (nc *NCIface) SetMTU() error {
	ifconfig, err := exec.LookPath("ifconfig")
	if err != nil {
		logger.Log(0, "failed to locate ifconfig", err.Error())
		return err
	}
	//set MTU
	if _, err := ncutils.RunCmd(ifconfig+" "+nc.Name+" mtu "+strconv.Itoa(nc.MTU), true); err != nil {
		return fmt.Errorf("error setting mtu %w", err)
	}
	return nil
}
