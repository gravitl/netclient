package wireguard

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"golang.org/x/exp/slog"
)

// NCIface.Create - makes a new Wireguard interface for darwin users (userspace)
func (nc *NCIface) Create() error {
	return nc.createUserSpaceWG()
}

// NCIface.ApplyAddrs - applies address for darwin userspace
func (nc *NCIface) ApplyAddrs() error {

	for _, address := range nc.Addresses {
		if address.IP != nil {
			if address.IP.To4() != nil {

				cmd := exec.Command("ifconfig", nc.Name, "inet", "add", address.IP.String(), address.IP.String())
				if out, err := cmd.CombinedOutput(); err != nil {
					slog.Error("error adding address", "command", cmd.String(), "error", string(out))
					continue
				}
			} else {

				cmd := exec.Command("ifconfig", nc.Name, "inet6", address.IP.String(), "prefixlen", "64", "alias")
				if out, err := cmd.CombinedOutput(); err != nil {
					slog.Error("error adding address", "command", cmd.String(), "error", string(out))
					continue
				}
			}

		}
		if address.Network.IP.To4() != nil {
			cmd := exec.Command("route", "add", "-net", "-inet", address.Network.String(), address.IP.String())
			if out, err := cmd.CombinedOutput(); err != nil {
				slog.Error("failed to add route", "command", cmd.String(), "error", string(out))
				continue
			}
		} else {
			cmd := exec.Command("route", "add", "-net", "-inet6", address.Network.String(), address.IP.String())
			if out, err := cmd.CombinedOutput(); err != nil {
				slog.Error("failed to add route", "command", cmd.String(), "error", string(out))
				continue
			}
		}

	}

	return nil
}

// RemoveRoutes - remove routes to the interface
func RemoveRoutes(addrs []ifaceAddress) {
	var cmd *exec.Cmd
	for _, addr := range addrs {
		if (len(config.GetNodes()) > 1 && addr.IP == nil) || addr.Network.IP == nil || addr.Network.String() == IPv4Network ||
			addr.Network.String() == IPv6Network || (len(config.GetNodes()) > 1 && addr.GwIP == nil) {
			continue
		}
		if addr.Network.IP == nil {
			continue
		}
		if addr.Network.IP.To4() != nil {
			if addr.IP == nil {
				cmd = exec.Command("route", "delete", "-net", "-interface", addr.Network.String(), ncutils.GetInterfaceName())
			} else {
				cmd = exec.Command("route", "delete", "-net", "-inet", addr.Network.String(), addr.IP.String())
			}
			if out, err := cmd.CombinedOutput(); err != nil {
				slog.Error("failed to delete route with", "command", cmd.String(), "error", string(out))
				continue
			}
		} else {
			if addr.IP == nil {
				cmd = exec.Command("route", "delete", "-net", "-interface", addr.Network.String(), ncutils.GetInterfaceName())
			} else {
				cmd = exec.Command("route", "delete", "-net", "-inet6", addr.Network.String(), addr.IP.String())
			}
			if out, err := cmd.CombinedOutput(); err != nil {
				slog.Error("failed to delete route with", "command", cmd.String(), "error", string(out))
				continue
			}
		}

	}
}

// SetRoutes - sets additional routes to the interface
func SetRoutes(addrs []ifaceAddress) error {
	var cmd *exec.Cmd
	for _, addr := range addrs {
		if (len(config.GetNodes()) > 1 && addr.IP == nil) || addr.Network.IP == nil || addr.Network.String() == IPv4Network ||
			addr.Network.String() == IPv6Network || (len(config.GetNodes()) > 1 && addr.GwIP == nil) {
			continue
		}
		if addr.Network.IP == nil {
			continue
		}
		if addr.Network.IP.To4() != nil {
			if addr.IP == nil {
				cmd = exec.Command("route", "add", "-net", "-interface", addr.Network.String(), ncutils.GetInterfaceName())
			} else {
				cmd = exec.Command("route", "add", "-net", "-inet", addr.Network.String(), addr.IP.String())
			}

			if out, err := cmd.CombinedOutput(); err != nil {
				slog.Error("failed to add route with", "command", cmd.String(), "error", string(out))
				continue
			}
		} else {
			if addr.IP == nil {
				cmd = exec.Command("route", "add", "-net", "-interface", addr.Network.String(), ncutils.GetInterfaceName())
			} else {
				cmd = exec.Command("route", "add", "-net", "-inet6", addr.Network.String(), addr.IP.String())
			}
			if out, err := cmd.CombinedOutput(); err != nil {
				slog.Error("failed to add route with", "command", cmd.String(), "error", string(out))
				continue
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
	wgMutex.Lock()
	defer wgMutex.Unlock()
	err := nc.Iface.Close()
	if err == nil {
		sockPath := "/var/run/wireguard/" + nc.Name + ".sock"
		if _, statErr := os.Stat(sockPath); statErr == nil {
			os.Remove(sockPath)
		}
	}

}

// DeleteOldInterface - removes named interface
func DeleteOldInterface(iface string) {
	logger.Log(3, "deleting interface", iface)
	conf := "/Applications/Netclient/config/" + iface + ".conf"
	if _, err := ncutils.RunCmd("wg-quick down "+conf, true); err != nil {
		slog.Error("remove wireguard tunnel", "interface", iface, "error", err)
	}
}

// GetDefaultGatewayIp - get current default gateway
func GetDefaultGatewayIp() (net.IP, error) {
	out, err := exec.Command("route", "-n", "get", "default").Output()
	if err != nil {
		return nil, err
	}
	// parse out from the following format
	//	route to: default
	//	destination: default
	//	mask: default
	//	gateway: 192.168.1.1
	//	interface: en0
	//	flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
	//	recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
	// 0         0         0         0         0         0      1500         0
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "gateway") {
			fields := strings.Fields(line)
			if len(fields) > 1 {
				ip := net.ParseIP(fields[1])
				if ip != nil {
					return ip, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("could not find gateway")
}

// RestoreInternetGw - restore the old default gateway
func RestoreInternetGw() error {
	logger.Log(0, "restoring internet gateway")
	og, err := GetOriginalDefaulGw()
	if err != nil {
		return err
	}
	if og == nil {
		logger.Log(0, "no original gateway found, skipping restore")
		return nil
	}
	logger.Log(0, "deleting default gateway")
	cmd := exec.Command("route", "delete", "default")
	if out, err := cmd.CombinedOutput(); err != nil {
		logger.Log(0, "failed to delete default gateway", "error", string(out))
		// continue, as it may not exist
	}
	logger.Log(0, "adding new default gateway", "gateway", og.String())
	cmd = exec.Command("route", "add", "default", og.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to add default gateway %s: %s", og.String(), string(out))
	}
	// clear original gateway
	nc := config.Netclient()
	nc.OriginalDefaultGatewayIp = nil
	config.UpdateNetclient(*nc)
	return config.WriteNetclientConfig()
}

// SetInternetGw - set a new default gateway
func SetInternetGw(ip net.IP) error {
	og, err := GetDefaultGatewayIp()
	if err == nil {
		logger.Log(0, "saving original gateway", "gateway", og.String())
		nc := config.Netclient()
		nc.OriginalDefaultGatewayIp = og
		config.UpdateNetclient(*nc)
		if err := config.WriteNetclientConfig(); err != nil {
			logger.Log(0, "failed to save original gateway", "error", err.Error())
		}
	}
	logger.Log(0, "deleting default gateway")
	cmd := exec.Command("route", "delete", "default")
	if out, err := cmd.CombinedOutput(); err != nil {
		logger.Log(0, "failed to delete default gateway", "error", string(out))
		// continue, as it may not exist
	}
	logger.Log(0, "setting new default gateway", "ip", ip.String())
	cmd = exec.Command("route", "add", "default", ip.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to add default gateway %s: %s", ip.String(), string(out))
	}
	return nil
}
