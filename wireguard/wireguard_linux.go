package wireguard

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/gravitl/netclient/config"
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
func GetDefaultGatewayIp() (ip net.IP, err error) {
	//get current default gateway
	gwRoute, err := GetDefaultGateway()
	if err != nil {
		return ip, err
	}

	return gwRoute.Gw, nil
}

// GetDefaultGateway - get current default gateway
func GetDefaultGateway() (gwRoute netlink.Route, err error) {

	//get the present route list
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		slog.Error("error loading route tables", "error", err.Error())
		return gwRoute, err
	}

	gwRoutes := []netlink.Route{}

	//get default gateway by filtering with dst==nil
	for _, r := range routes {
		if r.Dst == nil {
			gwRoutes = append(gwRoutes, r)
		}
	}

	//in case that multiple default gateway in the route table, return the one with higher priority
	if len(gwRoutes) == 0 {
		return gwRoute, errors.New("no default gateway found, please run command route -n to check in the route table")
	} else if len(gwRoutes) == 1 {
		return gwRoutes[0], nil
	} else {
		gwRoute = gwRoutes[0]
		for _, r := range gwRoutes {
			if r.Priority < gwRoute.Priority {
				gwRoute = r
			}
		}
	}

	return gwRoute, nil
}

func resetCurrGwMetric(gwRoute *netlink.Route) error {

	//delete the gw entry at first
	if err := netlink.RouteDel(gwRoute); err != nil {
		slog.Error("error removing old default gateway route", "error", err.Error())
		return err
	}

	//add the gw back with lower metric
	gwRoute.Priority = 100
	if err := netlink.RouteAdd(gwRoute); err != nil {
		slog.Error("error changing old default gateway route metric, please add it back manually", "error", err.Error())
		slog.Error("gateway route: ", "error", gwRoute)
	}

	return nil
}

// SetInternetGw - set a new default gateway and the route to Internet Gw's public ip address
func SetInternetGw(gwIp net.IP, endpointNet *net.IPNet) (err error) {

	//get the current default gateway
	currGw, err := GetDefaultGateway()
	if err != nil {
		slog.Error("error loading current default gateway", "error", err.Error())
	} else {
		if currGw.Priority <= 1 {
			err = resetCurrGwMetric(&currGw)
			if err != nil {
				slog.Error("error changing current default gateway metric", "error", err.Error())
				return err
			}
		}
	}

	if config.Netclient().CurrGwNmEndpoint.IP != nil {
		//build the route to Internet Gw's public ip
		epRoute := netlink.Route{Src: net.ParseIP("0.0.0.0"), Dst: &config.Netclient().CurrGwNmEndpoint, Gw: config.Netclient().OriginalDefaultGatewayIp}
		//del existing route to Internet Gw's public ip
		if !IsConflictedWithServerAddr(config.Netclient().CurrGwNmEndpoint) {
			if err := netlink.RouteDel(&epRoute); err != nil {
				slog.Error("add route to endpoint failed, it will need to restore the old default gateway", "error", err.Error())
			}
		}
	}

	gwRoute := netlink.Route{Src: net.ParseIP("0.0.0.0"), Dst: nil, Gw: gwIp, Priority: 1}

	//set new default gateway
	if err := netlink.RouteAdd(&gwRoute); err != nil && !strings.Contains(err.Error(), "file exists") {
		slog.Error("add new default gateway failed, it will need to restore the old default gateway", err.Error())
		RestoreInternetGw()
		return err
	}

	//build the route to Internet Gw's public ip
	epRoute := netlink.Route{Src: net.ParseIP("0.0.0.0"), Dst: endpointNet, Gw: config.Netclient().OriginalDefaultGatewayIp}
	//add new route to Internet Gw's public ip
	if err := netlink.RouteAdd(&epRoute); err != nil && !strings.Contains(err.Error(), "file exists") {
		slog.Error("add route to endpoint failed, it will need to restore the old default gateway", err.Error())
		RestoreInternetGw()
		return err
	}
	config.Netclient().CurrGwNmEndpoint = *endpointNet
	config.Netclient().CurrGwNmIP = gwIp
	return nil
}

// RestoreInternetGw - restore the old default gateway and delte the route to the Internet Gw's public ip address
func RestoreInternetGw() (err error) {
	//build the old default gateway route
	gwRoute := netlink.Route{Src: net.ParseIP("0.0.0.0"), Dst: nil, Gw: config.Netclient().CurrGwNmIP, Priority: 1}

	//delete new default gateway at first
	if err := netlink.RouteDel(&gwRoute); err != nil {
		slog.Error("remove current default gateway failed", "error", err.Error())
		slog.Error("please remove the current gateway manually")
		slog.Error("current gateway: ", gwRoute)
		return err
	}

	//build the route to Internet Gw's public ip
	epRoute := netlink.Route{Src: net.ParseIP("0.0.0.0"), Dst: &config.Netclient().CurrGwNmEndpoint, Gw: config.Netclient().OriginalDefaultGatewayIp}

	//delete endpointIp Net's route
	if err := netlink.RouteDel(&epRoute); err != nil {
		slog.Error("delete route to endpoint failed, please delete it manually", err.Error())
		slog.Error("endpoint Ip Net Route: ", epRoute)
	}

	config.Netclient().CurrGwNmEndpoint = net.IPNet{}
	config.Netclient().CurrGwNmIP = net.ParseIP("")
	return config.WriteNetclientConfig()
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

func SetNmServerRoutes(addrs []net.IPNet) error {
	gwIP, err := GetOriginalDefaulGw()
	if err != nil {
		return err
	}
	for i := range addrs {
		addr := addrs[i]
		if addr.IP == nil {
			continue
		}
		if addr.IP.IsPrivate() {
			continue
		}
		if err = netlink.RouteAdd(&netlink.Route{
			Dst: &addr,
			Gw:  gwIP,
		}); err != nil && !strings.Contains(err.Error(), "file exists") {
			logger.Log(2, "failed to set route", addr.String(), "to gw", gwIP.String())
			continue
		}
		logger.Log(0, "added server route for interface")
	}
	return nil
}

func RemoveNmServerRoutes(addrs []net.IPNet) error {
	gwIP, err := GetOriginalDefaulGw()
	if err != nil {
		return err
	}
	for i := range addrs {
		addr := addrs[i]
		if addr.IP == nil {
			continue
		}
		if addr.IP.IsPrivate() {
			continue
		}
		if err = netlink.RouteDel(&netlink.Route{
			Dst: &addr,
			Gw:  gwIP,
		}); err != nil && !strings.Contains(err.Error(), "file exists") {
			logger.Log(2, "failed to set route", addr.String(), "to gw", gwIP.String())
			continue
		}
		logger.Log(0, "added server route for interface")
	}
	return nil
}
