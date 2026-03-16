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
	err := nc.createUserSpaceWG()
	if err != nil {
		return err
	}

	if !nc.IsTestIface {
		cmd := exec.Command("ifconfig", "lo0", "alias", "127.51.8.21")
		out, err := cmd.CombinedOutput()
		if err != nil {
			slog.Error("failed to add address for dns server", "command", cmd.String(), "error", string(out))
			return err
		}
	}

	return nil
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

	if !nc.IsTestIface {
		cmd := exec.Command("ifconfig", "lo0", "-alias", "127.51.8.21")
		out, err := cmd.CombinedOutput()
		if err != nil {
			slog.Error("failed to remove address for dns server", "command", cmd.String(), "error", string(out))
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
func GetDefaultGatewayIp() (ip net.IP, err error) {
	// IPv4 Check
	gwDef, errDef := getRouteGateway("default")
	gwHalf1, err1 := getRouteGateway("0.0.0.1")
	gwHalf2, err2 := getRouteGateway("128.0.0.1")

	if err1 == nil && err2 == nil && gwHalf1.Equal(gwHalf2) {
		if errDef != nil || !gwHalf1.Equal(gwDef) {
			return gwHalf1, nil
		}
	}

	// On darwin, IGW sets interface-based split routes (route add -net -inet 0.0.0.0/1 -interface <iface>)
	// which have no gateway: line in `route -n get` output. Detect this by checking if both
	// half-routes go through the netclient WireGuard interface, and return CurrGwNmIP if so.
	if err1 != nil || err2 != nil {
		ncIface := ncutils.GetInterfaceName()
		iface1, errIf1 := getRouteInterface("0.0.0.1")
		iface2, errIf2 := getRouteInterface("128.0.0.1")
		if errIf1 == nil && errIf2 == nil && iface1 == ncIface && iface2 == ncIface {
			if gwNmIP := config.Netclient().CurrGwNmIP; gwNmIP != nil {
				return gwNmIP, nil
			}
		}
	}

	// IPv6 Check
	gwHalf6_1, err6_1 := getRouteGateway("2000::1")
	gwHalf6_2, err6_2 := getRouteGateway("8000::1")
	if err6_1 == nil && err6_2 == nil && gwHalf6_1.Equal(gwHalf6_2) {
		gwDef6, errDef6 := getRouteGateway("-inet6", "default")
		if errDef6 != nil || !gwHalf6_1.Equal(gwDef6) {
			return gwHalf6_1, nil
		}
	}

	// Same interface-based route check for IPv6
	if err6_1 != nil || err6_2 != nil {
		ncIface := ncutils.GetInterfaceName()
		iface1, errIf1 := getRouteInterface("2000::1")
		iface2, errIf2 := getRouteInterface("8000::1")
		if errIf1 == nil && errIf2 == nil && iface1 == ncIface && iface2 == ncIface {
			if gwNmIP := config.Netclient().CurrGwNmIP; gwNmIP != nil {
				return gwNmIP, nil
			}
		}
	}

	if errDef == nil {
		return gwDef, nil
	}
	return nil, fmt.Errorf("default gateway not found")
}

func getRouteGateway(args ...string) (ip net.IP, err error) {
	fullArgs := append([]string{"-n", "get"}, args...)
	cmd := exec.Command("route", fullArgs...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "gateway:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				ip = net.ParseIP(parts[1])
				if ip != nil {
					return ip, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("gateway not found for %v", args)
}

// getRouteInterface extracts the interface name from `route -n get` output.
// This is needed on darwin because interface-based routes (e.g. added via
// `route add -net -inet 0.0.0.0/1 -interface utunX`) do not have a gateway:
// line, only an interface: line.
func getRouteInterface(args ...string) (string, error) {
	fullArgs := append([]string{"-n", "get"}, args...)
	cmd := exec.Command("route", fullArgs...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "interface:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return parts[1], nil
			}
		}
	}
	return "", fmt.Errorf("interface not found for %v", args)
}

// RestoreInternetGw - restore the old default gateway
func RestoreInternetGw() (err error) {
	err = resetDefaultRoutesOnHost()
	if err == nil {
		GetIGWMonitor().Stop()
	}
	return err
}

func resetDefaultRoutesOnHost() error {
	iface := ncutils.GetInterfaceName()
	exec.Command("route", "delete", "-net", "-inet", "0.0.0.0/1", "-interface", iface).Run()
	exec.Command("route", "delete", "-net", "-inet", "128.0.0.0/1", "-interface", iface).Run()
	exec.Command("route", "delete", "-net", "-inet6", "::/1", "-interface", iface).Run()
	exec.Command("route", "delete", "-net", "-inet6", "8000::/1", "-interface", iface).Run()

	gwVIP := config.Netclient().CurrGwNmIP
	if len(gwVIP) > 0 {
		peers, err := GetPeersFromDevice(iface)
		if err == nil {
			for _, peer := range peers {
				for _, allowed := range peer.AllowedIPs {
					if allowed.IP.Equal(gwVIP) {
						if peer.Endpoint != nil {
							exec.Command("route", "delete", peer.Endpoint.IP.String()).Run()
						}
						break
					}
				}
			}
		}
	}
	config.Netclient().CurrGwNmIP = nil
	config.Netclient().OriginalDefaultGatewayIp = nil
	return config.WriteNetclientConfig()
}

// SetInternetGw - set a new default gateway
func SetInternetGw(publicKey string, networkIP net.IP) (err error) {
	err = setDefaultRoutesOnHost(publicKey, networkIP)
	if err == nil {
		GetIGWMonitor().Monitor(publicKey, networkIP)
	}
	return err
}

func setDefaultRoutesOnHost(publicKey string, networkIP net.IP) error {
	gw, err := getRouteGateway("default")
	if err != nil {
		return fmt.Errorf("failed to get current gateway: %w", err)
	}
	config.Netclient().OriginalDefaultGatewayIp = gw

	peer, err := GetPeer(ncutils.GetInterfaceName(), publicKey)
	if err != nil {
		return fmt.Errorf("failed to get peer: %w", err)
	}
	if peer.Endpoint == nil {
		return fmt.Errorf("peer endpoint is nil")
	}

	if out, err := exec.Command("route", "add", peer.Endpoint.IP.String(), gw.String()).CombinedOutput(); err != nil {
		slog.Error("failed to add route to endpoint", "output", string(out), "error", err)
	}

	iface := ncutils.GetInterfaceName()
	run := func(args ...string) {
		if out, err := exec.Command("route", args...).CombinedOutput(); err != nil {
			slog.Error("failed to add route", "command", fmt.Sprint(args), "output", string(out), "error", err)
		}
	}

	run("add", "-net", "-inet", "0.0.0.0/1", "-interface", iface)
	run("add", "-net", "-inet", "128.0.0.0/1", "-interface", iface)

	run("add", "-net", "-inet6", "::/1", "-interface", iface)
	run("add", "-net", "-inet6", "8000::/1", "-interface", iface)

	config.Netclient().CurrGwNmIP = networkIP
	return config.WriteNetclientConfig()
}
