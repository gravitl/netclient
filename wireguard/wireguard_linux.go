package wireguard

import (
	"fmt"
	"net"
	"os"
	"os/exec"

	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"github.com/vishvananda/netlink"
	"golang.org/x/exp/slog"
)

// NCIface.Create - creates a linux WG interface based on a node's host config
func (nc *NCIface) Create() error {
	if isKernelWireGuardPresent() {
		newLink := nc.getKernelLink()
		if newLink == nil {
			return fmt.Errorf("failed to create kernel interface")
		}
		nc.Iface = newLink
		l, err := netlink.LinkByName(nc.Name)
		if err != nil {
			switch err.(type) {
			case netlink.LinkNotFoundError:
				break
			default:
				return err
			}
		}
		if l != nil {
			err = netlink.LinkDel(newLink)
			if err != nil {
				return err
			}
		}
		if err = netlink.LinkAdd(newLink); err != nil && !os.IsExist(err) {
			return err
		}
		if err = netlink.LinkSetUp(newLink); err != nil {
			return err
		}
		return nil
	} else if isTunModuleLoaded() {
		if err := nc.createUserSpaceWG(); err != nil {
			return err
		}
	}
	return fmt.Errorf("WireGuard not detected")
}

// NCIface.SetMTU - sets the mtu for the interface
func (n *NCIface) SetMTU() error {
	l := n.getKernelLink()
	if err := netlink.LinkSetMTU(l, n.MTU); err != nil {
		return err
	}
	return nil
}

// netLink.Attrs - implements required function of NetLink package
func (l *netLink) Attrs() *netlink.LinkAttrs {
	return l.attrs
}

// netLink.Type - returns type of link i.e wireguard
func (l *netLink) Type() string {
	return "wireguard"
}

// NCIface.Close closes netmaker interface
func (n *NCIface) Close() {
	link := n.getKernelLink()
	link.Close()
}

// netLink.Close - required function to close linux interface
func (l *netLink) Close() error {
	return netlink.LinkDel(l)
}

// netLink.ApplyAddrs - applies the assigned node addresses to given interface (netLink)
func (nc *NCIface) ApplyAddrs() error {
	l, err := netlink.LinkByName(nc.Name)
	if err != nil {
		return fmt.Errorf("failed to locate link %w", err)
	}

	currentAddrs, err := netlink.AddrList(l, 0)
	if err != nil {
		return err
	}
	routes, err := netlink.RouteList(l, 0)
	if err != nil {
		return err
	}

	for i := range routes {
		err = netlink.RouteDel(&routes[i])
		if err != nil {
			return fmt.Errorf("failed to list routes %w", err)
		}
	}

	if len(currentAddrs) > 0 {
		for i := range currentAddrs {
			err = netlink.AddrDel(l, &currentAddrs[i])
			if err != nil {
				return fmt.Errorf("failed to delete route %w", err)
			}
		}
	}

	for _, addr := range nc.Addresses {
		if addr.IP != nil && addr.Network.IP != nil {
			slog.Info("adding address", "address", addr.IP.String(), "network", addr.Network.String())
			if err := netlink.AddrAdd(l, &netlink.Addr{IPNet: &net.IPNet{IP: addr.IP, Mask: addr.Network.Mask}}); err != nil {
				slog.Error("error adding addr", "error", err.Error())

			}
		}

	}
	return nil
}

// SetRoutes - sets additional routes to the interface
func SetRoutes(addrs []ifaceAddress) {
	l, err := netlink.LinkByName(ncutils.GetInterfaceName())
	if err != nil {
		slog.Error("failed to get link to interface", "error", err)
		return
	}
	for _, addr := range addrs {
		if addr.IP == nil || addr.Network.IP == nil || addr.Network.String() == "0.0.0.0/0" ||
			addr.Network.String() == "::/0" {
			continue
		}
		slog.Info("adding route to interface", "route", fmt.Sprintf("%s -> %s", addr.IP.String(), addr.Network.String()))
		if err := netlink.RouteAdd(&netlink.Route{
			LinkIndex: l.Attrs().Index,
			Gw:        addr.IP,
			Dst:       &addr.Network,
		}); err != nil {
			slog.Error("error adding route", "error", err.Error())
		}

	}
}

// GetDefaultGatewayIp - get current default gateway
func GetDefaultGatewayIp() (ifLink int, ip net.IP, err error) {
	//get current default gateway
	gwRoute, err := GetDefaultGateway()
	if err != nil {
		return ifLink, ip, err
	}

	return gwRoute.LinkIndex, gwRoute.Gw, nil
}

// GetDefaultGateway - get current default gateway
func GetDefaultGateway() (gwRoute netlink.Route, err error) {

	//get the present route list
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		slog.Error("error loading route tables", "error", err.Error())
		return gwRoute, err
	}

	//get default gateway by filtering with dst==nil
	for _, r := range routes {
		if r.Dst == nil {
			gwRoute = r
			break
		}
	}

	return gwRoute, nil
}

// SetInternetGw - set a new default gateway and the route to Internet Gw's public ip address
func SetInternetGw(gwIp net.IP, endpointNet *net.IPNet) (err error) {

	//get the link for interface netmaker
	link, err := netlink.LinkByName(ncutils.GetInterfaceName())
	if err != nil {
		slog.Error("failed to get link to interface", "error", err.Error())
		return err
	}

	//build the new default gateway route
	gwRoute := netlink.Route{LinkIndex: link.Attrs().Index, Src: net.ParseIP("0.0.0.0"), Dst: nil, Gw: gwIp}

	//get current default gateway
	oldGwRoute, err := GetDefaultGateway()
	if err != nil {
		return err
	}

	//build the route to Internet Gw's public ip
	epRoute := netlink.Route{LinkIndex: oldGwRoute.ILinkIndex, Src: net.ParseIP("0.0.0.0"), Dst: endpointNet, Gw: oldGwRoute.Gw}

	if oldGwRoute.Gw.String() != "<nil>" {
		//delete old default gateway at first
		if err := netlink.RouteDel(&oldGwRoute); err != nil {
			slog.Error("remove old default gateway failed", "error", err.Error())
			return err
		}
	}

	//set new default gateway
	if gwRoute.Gw.String() != oldGwRoute.Gw.String() {
		if err := netlink.RouteAdd(&gwRoute); err != nil {
			slog.Error("add new default gateway failed, it will need to restore the old default gateway", err.Error())
			if oldGwRoute.Gw.String() != "<nil>" && gwRoute.Gw.String() != oldGwRoute.Gw.String() {
				if err := netlink.RouteAdd(&oldGwRoute); err != nil {
					slog.Error("restore old default gateway failed, please add the route back manually", err.Error())
					slog.Error("old default gateway info: ", oldGwRoute)
				}
			}
			return err
		}
	}

	//add new route to Internet Gw's public ip
	if err := netlink.RouteAdd(&epRoute); err != nil {
		slog.Error("add route to endpoint failed, it will need to restore the old default gateway", err.Error())
		RestoreInternetGw(oldGwRoute.ILinkIndex, oldGwRoute.Gw, endpointNet)
		return err
	}

	return nil
}

// RestoreInternetGw - restore the old default gateway and delte the route to the Internet Gw's public ip address
func RestoreInternetGw(ifLink int, ip net.IP, endpointNet *net.IPNet) (err error) {
	//get current default gateway
	gwRoute, err := GetDefaultGateway()
	if err != nil {
		return err
	}

	//build the old default gateway route
	oldGwRoute := netlink.Route{LinkIndex: ifLink, Dst: nil, Gw: ip}

	if gwRoute.Gw.String() != "<nil>" {
		//delete new default gateway at first
		if err := netlink.RouteDel(&gwRoute); err != nil {
			slog.Error("remove current default gateway failed", "error", err.Error())
			slog.Error("please remove the current gateway and restore the old gateway back manually")
			slog.Error("current gateway: ", gwRoute)
			slog.Error("old gateway: ", oldGwRoute)
			return err
		}
	}

	//set old default gateway back
	if gwRoute.Gw.String() != oldGwRoute.Gw.String() {
		if err := netlink.RouteAdd(&oldGwRoute); err != nil {
			slog.Error("add old default gateway back failed, please add it back manually", err.Error())
			slog.Error("old gateway: ", oldGwRoute)
			return err
		}
	}

	//build the route to Internet Gw's public ip
	epRoute := netlink.Route{LinkIndex: oldGwRoute.ILinkIndex, Src: net.ParseIP("0.0.0.0"), Dst: endpointNet, Gw: oldGwRoute.Gw}

	//delete endpointIp Net's route
	if err := netlink.RouteDel(&epRoute); err != nil {
		slog.Error("delete route to endpoint failed, please delete it manually", err.Error())
		slog.Error("endpoint Ip Net Route: ", epRoute)
	}

	return nil
}

// == private ==

type netLink struct {
	attrs *netlink.LinkAttrs
}

func (nc *NCIface) getKernelLink() *netLink {
	link := getNewLink(nc.Name)
	return link
}

func getNewLink(name string) *netLink {
	linkAttrs := netlink.NewLinkAttrs()
	linkAttrs.Name = name
	return &netLink{
		attrs: &linkAttrs,
	}
}

// DeleteOldInterface - removes named interface
func DeleteOldInterface(iface string) {
	logger.Log(3, "deleting interface", iface)
	ip, err := exec.LookPath("ip")
	if err != nil {
		logger.Log(0, "failed to locate if", err.Error())
	}
	if _, err := ncutils.RunCmd(ip+" link del "+iface, true); err != nil {
		logger.Log(0, "error removing interface", iface, err.Error())
	}
}
