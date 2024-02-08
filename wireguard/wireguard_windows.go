package wireguard

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"golang.org/x/exp/slog"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/driver"
)

// NCIface.Create - makes a new Wireguard interface and sets given addresses
func (nc *NCIface) Create() error {
	wgMutex.Lock()
	defer wgMutex.Unlock()

	adapter, err := driver.OpenAdapter(ncutils.GetInterfaceName())
	if err != nil {
		logger.Log(3, "creating Windows tunnel")
		windowsGUID, err := windows.GenerateGUID()
		if err != nil {
			return err
		}
		adapter, err = driver.CreateAdapter(ncutils.GetInterfaceName(), "WireGuard", &windowsGUID)
		if err != nil {
			return err
		}
	} else {
		slog.Info("re-using existing adapter")
	}

	slog.Info("created Windows tunnel")
	nc.Iface = adapter
	return adapter.SetAdapterState(driver.AdapterStateUp)
}

// NCIface.ApplyAddrs - applies addresses to windows tunnel ifaces, unused currently
func (nc *NCIface) ApplyAddrs() error {
	adapter := nc.Iface
	prefixAddrs := []netip.Prefix{}
	for i := range nc.Addresses {

		maskSize, _ := nc.Addresses[i].Network.Mask.Size()
		slog.Info("appending address", "address", fmt.Sprintf("%s/%d to nm interface", nc.Addresses[i].IP.String(), maskSize))
		addr, err := netip.ParsePrefix(fmt.Sprintf("%s/%d", nc.Addresses[i].IP.String(), maskSize))
		if err == nil {
			prefixAddrs = append(prefixAddrs, addr)
		} else {
			slog.Error("failed to append ip to Netclient adapter", "error", err)
		}
	}

	return adapter.(*driver.Adapter).LUID().SetIPAddresses(prefixAddrs)
}

// SetRoutes - sets additional routes to the interface
func SetRoutes(addrs []ifaceAddress) {
	for _, addr := range addrs {
		if addr.IP == nil || addr.Network.IP == nil || addr.Network.String() == "0.0.0.0/0" ||
			addr.Network.String() == "::/0" {
			continue
		}
		if addr.Network.IP.To4() != nil {
			slog.Info("adding ipv4 route to interface", "route", fmt.Sprintf("%s -> %s", addr.IP.String(), addr.Network.String()))
			cmd := fmt.Sprintf("netsh int ipv4 add route %s interface=%s nexthop=%s store=%s",
				addr.Network.String(), ncutils.GetInterfaceName(), "0.0.0.0", "active")
			_, err := ncutils.RunCmd(cmd, false)
			if err != nil {
				slog.Error("failed to apply", "ipv4 egress range", addr.Network.String())
			}
		} else {
			slog.Info("adding ipv6 route to interface", "route", fmt.Sprintf("%s -> %s", addr.IP.String(), addr.Network.String()))
			cmd := fmt.Sprintf("netsh int ipv6 add route %s interface=%s nexthop=%s store=%s",
				addr.Network.String(), ncutils.GetInterfaceName(), "::", "active")
			_, err := ncutils.RunCmd(cmd, false)
			if err != nil {
				slog.Error("failed to apply", "ipv6 egress range", addr.Network.String())
			}
		}
	}
}

// GetDefaultGatewayIp - get current default gateway
func GetDefaultGatewayIp() (ifLink int, ip net.IP, err error) {
	//get current route
	output, err := ncutils.RunCmd("netsh int ipv4 show route", true)
	if err != nil {
		return ifLink, ip, err
	}

	//filter and get current default gateway address
	ip = net.IP(getDefaultGatewayIpFromRouteList(output))

	return 0, ip, nil
}

// SetDefaultGateway - set a new default gateway
func SetDefaultGateway(ip net.IP) (err error) {

	//add new route with metric 1 for setting to top priority
	addCmd := fmt.Sprintf("netsh int ipv4 add route 0.0.0.0/0 interface=%s nexthop=%s store=active metric=1", ncutils.GetInterfaceName(), ip.String())

	_, err = ncutils.RunCmd(addCmd, true)
	if err != nil {
		slog.Error("Failed to add route table", "error", err.Error())
		return err
	}

	return nil
}

// RestoreDefaultGatewayOnly - restore the old default gateway, Linux and Windows do have different behavior, for aligning with Linux, adding this function
func RestoreDefaultGatewayOnly(ifLink int, ip net.IP) (err error) {

	delCmd := fmt.Sprintf("netsh int ipv4 delete route 0.0.0.0/0 interface=%s nexthop=%s store=active", ncutils.GetInterfaceName(), ip.String())

	_, err = ncutils.RunCmd(delCmd, true)
	if err != nil {
		slog.Error("Failed to delete route, please delete it manually", "error", err.Error())
		return err
	}

	return nil
}

// RestoreDefaultGateway - restore the old default gateway
func RestoreDefaultGateway(ifLink int, ip net.IP) (err error) {

	delCmd := fmt.Sprintf("netsh int ipv4 delete route 0.0.0.0/0 interface=%s nexthop=%s store=active", ncutils.GetInterfaceName(), ip.String())

	_, err = ncutils.RunCmd(delCmd, true)
	if err != nil {
		slog.Error("Failed to delete route, please delete it manually", "error", err.Error())
		return err
	}

	return nil
}

// NCIface.Close - closes the managed WireGuard interface
func (nc *NCIface) Close() {
	err := nc.Iface.Close()
	if err != nil {
		logger.Log(0, "error closing netclient interface -", err.Error())
	}

	// clean up egress range routes
	for i := range nc.Addresses {
		if nc.Addresses[i].Network.String() == "0.0.0.0/0" ||
			nc.Addresses[i].Network.String() == "::/0" {
			continue
		}
		if nc.Addresses[i].AddRoute {
			maskSize, _ := nc.Addresses[i].Network.Mask.Size()
			logger.Log(1, "removing egress range", fmt.Sprintf("%s/%d from nm interface", nc.Addresses[i].IP.String(), maskSize))
			cmd := fmt.Sprintf("route delete %s", nc.Addresses[i].IP.String())
			_, err := ncutils.RunCmd(cmd, false)
			if err != nil {
				logger.Log(0, "failed to remove egress range", nc.Addresses[i].IP.String())
			}
		}
	}
}

// NCIface.SetMTU - sets the MTU of the windows WireGuard Iface adapter
func (nc *NCIface) SetMTU() error {
	// TODO figure out how to change MTU of adapter
	return nil
}

// DeleteOldInterface - removes named interface
func DeleteOldInterface(iface string) {
	logger.Log(0, "deleting interface", iface)
	if _, err := ncutils.RunCmd("wireguard.exe /uninstalltunnelservice "+iface, true); err != nil {
		logger.Log(1, err.Error())
	}
}
