package wireguard

import (
	"fmt"
	"os/exec"
	"strconv"

	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"golang.org/x/exp/slog"
)

const kernelModule = "/boot/modules/if_wg.ko"

// NCIface.Create - creates a linux WG interface based on a node's given config
func (nc *NCIface) Create() error {
	if _, err := ncutils.RunCmd("kldstat | grep if_wg", false); err != nil {
		slog.Info("loading kernel wireguard")
		return create(nc)
	}
	slog.Info("using userspace wireguard")
	return nc.createUserSpaceWG()
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
		if address.IP.To4() != nil {
			if _, err := ncutils.RunCmd(ifconfig+" "+nc.Name+" inet "+address.IP.String()+" alias", true); err != nil {
				slog.Error("error adding address to interface", "address", address.IP.String(), "error", err.Error())
			}
		} else {
			if _, err := ncutils.RunCmd(ifconfig+" "+nc.Name+" inet6 "+address.IP.String()+" alias", true); err != nil {
				slog.Error("error adding address to interface", "address", address.IP.String(), "error", err.Error())
			}
		}

		if address.IP.To4() != nil {
			if _, err := ncutils.RunCmd(fmt.Sprintf("route add -net -inet %s %s", address.Network.String(), address.IP.String()), true); err != nil {
				slog.Error("error adding address to interface", "address", address.Network.String(), "error", err.Error())
			}
		} else {
			if _, err := ncutils.RunCmd(fmt.Sprintf("route add -net -inet6 %s %s", address.Network.String(), address.IP.String()), true); err != nil {
				slog.Error("error adding address to interface ", "address", address.Network.String(), "error", err.Error())
			}
		}
	}
	return nil
}

// SetRoutes - sets additional routes to the interface
func SetRoutes(addrs []ifaceAddress) {
	for _, addr := range addrs {
		if addr.IP == nil || addr.Network.IP == nil || addr.Network.String() == "0.0.0.0/0" ||
			addr.Network.String() == "::/0" {
			continue
		}
		if addr.Network.String() != "0.0.0.0/0" &&
			addr.Network.String() != "::/0" {
			if addr.IP.To4() != nil {
				if _, err := ncutils.RunCmd(fmt.Sprintf("route add -net -inet %s %s", addr.Network.String(), addr.IP.String()), true); err != nil {
					slog.Error("error adding address to interface", "address", addr.Network.String(), "error", err.Error())
				}
			} else {
				if _, err := ncutils.RunCmd(fmt.Sprintf("route add -net -inet6 %s %s", addr.Network.String(), addr.IP.String()), true); err != nil {
					slog.Error("error adding address to interface ", "address", addr.Network.String(), "error", err.Error())
				}
			}

		}
	}
}

// NCIface.SetMTU - set MTU for netmaker interface
func (nc *NCIface) SetMTU() error {
	slog.Debug("setting mtu for netmaker interface")
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

// DeleteOldInterface - removes named interface
func DeleteOldInterface(iface string) {
	logger.Log(3, "deleting interface", iface)
	ifconfig, err := exec.LookPath("ifconfig")
	if err != nil {
		logger.Log(0, "failed to locate ifconfig", err.Error())
	}
	if _, err := ncutils.RunCmd(ifconfig+" "+iface+" destroy", true); err != nil {
		logger.Log(0, "error removing interface", iface, err.Error())
	}
}
