package wireguard

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"github.com/vishvananda/netlink"
	"golang.org/x/exp/slog"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	RouteTableName    = 111
	EgressRouteMetric = 256
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
		slog.Info("Kernel WireGuard not detected. Proceeding with userspace WireGuard for iface creation.")
		if err := nc.createUserSpaceWG(); err != nil {
			return err
		}
		newLink := nc.getKernelLink()
		if newLink == nil {
			return fmt.Errorf("failed to create userspace interface")
		}
		if err := netlink.LinkAdd(newLink); err != nil && !os.IsExist(err) {
			return err
		}
		if err := netlink.LinkSetUp(newLink); err != nil {
			return err
		}
		return nil
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
	if isKernelWireGuardPresent() {
		link := n.getKernelLink()
		link.Close()
	} else if isTunModuleLoaded() {
		n.closeUserspaceWg()
	}
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
				slog.Warn("error adding addr", "error", err.Error())
			}
		}

	}
	return nil
}

// RemoveRoutes - Remove routes to the interface
func RemoveRoutes(addrs []ifaceAddress) {
	l, err := netlink.LinkByName(ncutils.GetInterfaceName())
	if err != nil {
		slog.Error("failed to get link to interface", "error", err)
		return
	}

	for _, addr := range addrs {
		if (len(config.GetNodes()) > 1 && addr.IP == nil) || addr.Network.IP == nil || addr.Network.String() == IPv4Network ||
			addr.Network.String() == IPv6Network || (len(config.GetNodes()) > 1 && addr.GwIP == nil) {
			continue
		}
		slog.Info("removing route to interface", "route", fmt.Sprintf("%s -> %s ->%s", addr.IP.String(), addr.Network.String(), addr.GwIP.String()))
		if err := netlink.RouteDel(&netlink.Route{
			LinkIndex: l.Attrs().Index,
			Gw:        addr.GwIP,
			Src:       addr.IP,
			Dst:       &addr.Network,
			Priority:  int(addr.Metric),
		}); err != nil {
			slog.Warn("error removing route", "error", err.Error())
		}
	}
}

// SetRoutes - sets additional routes to the interface
func SetRoutes(addrs []ifaceAddress) error {
	l, err := netlink.LinkByName(ncutils.GetInterfaceName())
	if err != nil {
		slog.Error("failed to get link to interface", "error", err)
		return err
	}

	for _, addr := range addrs {
		if (len(config.GetNodes()) > 1 && addr.IP == nil) || addr.Network.IP == nil || addr.Network.String() == IPv4Network ||
			addr.Network.String() == IPv6Network || (len(config.GetNodes()) > 1 && addr.GwIP == nil) {
			continue
		}
		slog.Info("adding route to interface", "route", fmt.Sprintf("%s -> %s ->%s", addr.IP.String(), addr.Network.String(), addr.GwIP.String()))
		metric := EgressRouteMetric
		if addr.Metric > 0 && addr.Metric < 999 {
			metric = int(addr.Metric)
		}
		if err := netlink.RouteAdd(&netlink.Route{
			LinkIndex: l.Attrs().Index,
			Gw:        addr.GwIP,
			Src:       addr.IP,
			Dst:       &addr.Network,
			Priority:  metric,
		}); err != nil && !strings.Contains(err.Error(), "file exists") {
			slog.Warn("error adding route", "error", err.Error())
		}
	}
	return nil
}

// GetDefaultGatewayIp - get current default gateway
func GetDefaultGatewayIp() (ip net.IP, err error) {
	//if table ROUTE_TABLE_NAME existed, return the gateway ip from table ROUTE_TABLE_NAME
	//build the gateway route, with Table ROUTE_TABLE_NAME, metric 1
	tRoute := netlink.Route{Dst: nil, Table: RouteTableName}
	//Check if table ROUTE_TABLE_NAME existed
	routes, _ := netlink.RouteListFiltered(netlink.FAMILY_ALL, &tRoute, netlink.RT_FILTER_TABLE)
	if len(routes) == 1 {
		return routes[0].Gw, nil
	} else if len(routes) > 1 {
		for _, r := range routes {
			if r.Dst == nil {
				return r.Gw, nil
			}
		}
	}

	//if table ROUTE_TABLE_NAME is not existed, get the gateway from main table
	//get current default gateway
	gwRoute, err := GetDefaultGateway()
	if err != nil {
		return ip, err
	}

	return gwRoute.Gw, nil
}

// GetDefaultGatewayV6 - get current default gateway ipv6
func GetDefaultGatewayV6() (gwRoute netlink.Route, err error) {
	// get the present route list
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V6)
	if err != nil {
		slog.Error("error loading route tables", "error", err.Error())
		return gwRoute, err
	}

	gwRoutes := []netlink.Route{}

	// get default gateway by filtering with dst==nil
	for _, r := range routes {
		if r.Dst == nil {
			gwRoutes = append(gwRoutes, r)
		}
	}

	// in case that multiple default gateway in the route table, return the one with higher priority
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

// GetDefaultGateway - get current default gateway
func GetDefaultGateway() (gwRoute netlink.Route, err error) {

	//get the present route list
	routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		slog.Error("error loading route tables", "error", err.Error())
		return gwRoute, err
	}

	gwRoutes := []netlink.Route{}

	//get default gateway by filtering with dst==nil
	for _, r := range routes {
		if r.Dst == nil || r.Dst.IP.Equal(net.ParseIP("0.0.0.0")) || r.Dst.IP.Equal(net.ParseIP("::")) {
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

// getLocalIpByDefaultInterfaceName - get local ip address by default interface name in config file
func getLocalIpByDefaultInterfaceName() (ip net.IP, err error) {
	family := netlink.FAMILY_V4
	if ipv4 := config.Netclient().OriginalDefaultGatewayIp.To4(); ipv4 != nil {
		family = netlink.FAMILY_V4
	} else {
		family = netlink.FAMILY_V6
	}

	dLink, err := netlink.LinkByName(config.Netclient().Host.DefaultInterface)
	if err == nil && dLink != nil {
		addrList, err := netlink.AddrList(dLink, family)
		if err == nil && len(addrList) > 0 {
			return addrList[0].IP, nil
		}
	}
	return ip, errors.New("could not get local ip by default interface name")
}

func getSourceIpv6(gw net.IP) (src net.IP) {
	for _, v := range config.Nodes {
		if v.NetworkRange6.Contains(gw) {
			return v.Address6.IP
		}
	}
	return src
}

// SetInternetGw - set a new default gateway and add rules to activate it
func SetInternetGw(igwPeerCfg wgtypes.PeerConfig, peerNetworkIP net.IP) (err error) {
	defer func() {
		startIGWMonitor(igwPeerCfg, peerNetworkIP)
	}()

	return setDefaultRoutesOnHost(peerNetworkIP)
}

func setDefaultRoutesOnHost(peerNetworkIP net.IP) error {
	if ipv4 := peerNetworkIP.To4(); ipv4 != nil {
		return setInternetGwV4(peerNetworkIP)
	} else {
		return setInternetGwV6(peerNetworkIP)
	}
}

// setInternetGwV6 - set a new default gateway and add rules to activate it
func setInternetGwV6(gwIp net.IP) (err error) {
	if ipv4 := config.Netclient().OriginalDefaultGatewayIp.To4(); ipv4 != nil {
		ipv6, err := GetDefaultGatewayV6()
		if err == nil && ipv6.Gw != nil {
			config.Netclient().OriginalDefaultGatewayIp = ipv6.Gw
		}
	}

	srcIp := getSourceIpv6(gwIp)
	//build the gateway route, with Table ROUTE_TABLE_NAME, metric 1
	gwRoute := netlink.Route{Src: srcIp, Dst: nil, Gw: gwIp, Table: RouteTableName, Priority: 1}

	//Check if table ROUTE_TABLE_NAME existed
	routes, _ := netlink.RouteListFiltered(netlink.FAMILY_V6, &gwRoute, netlink.RT_FILTER_TABLE)
	if len(routes) > 0 {
		err = resetDefaultRoutesOnHost()
		if err != nil {
			slog.Error("remove table "+fmt.Sprintf("%d", RouteTableName)+" failed", "error", err.Error())
			return err
		}
	}

	//set new default gateway
	if err := netlink.RouteAdd(&gwRoute); err != nil {
		slog.Error("add new default gateway failed", "error", err.Error())
		return err
	}

	//add rules
	_, ipnet, err := net.ParseCIDR(IPv6Network)
	if err != nil {
		return err
	}
	//first rule :ip rule add from all table ROUTE_TABLE_NAME
	tRule := netlink.NewRule()
	tRule.Family = syscall.AF_INET6
	tRule.Src = ipnet
	tRule.Table = RouteTableName
	tRule.Priority = 3000
	if err := netlink.RuleAdd(tRule); err != nil {
		slog.Error("add new rule failed", "rule", tRule.String(), "error", err.Error())
		resetDefaultRoutesOnHost()
		return err
	}
	//second rule :ip rule add table main suppress_prefixlength 0
	sRule := netlink.NewRule()
	sRule.Family = syscall.AF_INET6
	sRule.Src = ipnet
	sRule.Table = unix.RT_TABLE_MAIN
	sRule.SuppressPrefixlen = 0
	sRule.Priority = 2500
	if err := netlink.RuleAdd(sRule); err != nil {
		slog.Error("add new rule failed", "mRule: ", sRule.String(), "error", err.Error())
		resetDefaultRoutesOnHost()
		return err
	}
	//third rule :ip rule add from 68.183.79.137 table main
	lIp := config.Netclient().Host.EndpointIPv6

	_, ipnet, err = net.ParseCIDR(lIp.String() + "/128")
	if err != nil {
		return err
	}
	mRule := netlink.NewRule()
	mRule.Family = syscall.AF_INET6
	mRule.Src = ipnet
	mRule.Table = unix.RT_TABLE_MAIN
	mRule.Priority = 2000
	if err := netlink.RuleAdd(mRule); err != nil {
		slog.Error("add new rule failed", "mRule: ", mRule.String(), "error", err.Error())
		resetDefaultRoutesOnHost()
		return err
	}
	config.Netclient().CurrGwNmIP = gwIp

	return config.WriteNetclientConfig()
}

// setInternetGwV4 - set a new default gateway and add rules to activate it
func setInternetGwV4(gwIp net.IP) (err error) {

	//build the gateway route, with Table ROUTE_TABLE_NAME, metric 1
	gwRoute := netlink.Route{Src: net.ParseIP("0.0.0.0"), Dst: nil, Gw: gwIp, Table: RouteTableName, Priority: 1}

	//Check if table ROUTE_TABLE_NAME existed
	routes, _ := netlink.RouteListFiltered(netlink.FAMILY_V4, &gwRoute, netlink.RT_FILTER_TABLE)
	if len(routes) > 0 {
		err = resetDefaultRoutesOnHost()
		if err != nil {
			slog.Error("remove table "+fmt.Sprintf("%d", RouteTableName)+" failed", "error", err.Error())
			return err
		}
	}

	//set new default gateway
	if err := netlink.RouteAdd(&gwRoute); err != nil {
		slog.Error("add new default gateway failed", "error", err.Error())
		return err
	}

	//add rules
	_, ipnet, err := net.ParseCIDR(IPv4Network)
	if err != nil {
		return err
	}
	//first rule :ip rule add from all table ROUTE_TABLE_NAME
	tRule := netlink.NewRule()
	tRule.Src = ipnet
	tRule.Table = RouteTableName
	tRule.Priority = 3000
	if err := netlink.RuleAdd(tRule); err != nil {
		slog.Error("add new rule failed", "rule", tRule.String(), "error", err.Error())
		resetDefaultRoutesOnHost()
		return err
	}
	//second rule :ip rule add table main suppress_prefixlength 0
	sRule := netlink.NewRule()
	sRule.Src = ipnet
	sRule.Table = unix.RT_TABLE_MAIN
	sRule.SuppressPrefixlen = 0
	sRule.Priority = 2500
	if err := netlink.RuleAdd(sRule); err != nil {
		slog.Error("add new rule failed", "mRule: ", sRule.String(), "error", err.Error())
		resetDefaultRoutesOnHost()
		return err
	}
	//third rule :ip rule add from 68.183.79.137 table main
	lIp, err := getLocalIpByDefaultInterfaceName()
	if err != nil {
		lIp = config.Netclient().Host.EndpointIP
	}

	_, ipnet, err = net.ParseCIDR(lIp.String() + "/32")
	if err != nil {
		return err
	}
	mRule := netlink.NewRule()
	mRule.Src = ipnet
	mRule.Table = unix.RT_TABLE_MAIN
	mRule.Priority = 2000
	if err := netlink.RuleAdd(mRule); err != nil {
		slog.Error("add new rule failed", "mRule: ", mRule.String(), "error", err.Error())
		resetDefaultRoutesOnHost()
		return err
	}
	config.Netclient().CurrGwNmIP = gwIp
	return config.WriteNetclientConfig()
}

// RestoreInternetGw - delete the route in table ROUTE_TABLE_NAME and delet the rules
func RestoreInternetGw() (err error) {
	defer func() {
		stopIGWMonitor()
	}()

	return resetDefaultRoutesOnHost()
}

func resetDefaultRoutesOnHost() error {
	if ipv4 := config.Netclient().CurrGwNmIP.To4(); ipv4 != nil {
		return restoreInternetGwV4()
	} else {
		return restoreInternetGwV6()
	}
}

// restoreInternetGwV6 - delete the route in table ROUTE_TABLE_NAME and delet the rules
func restoreInternetGwV6() (err error) {

	srcIp := getSourceIpv6(config.Netclient().CurrGwNmIP)
	//build the default gateway route
	gwRoute := netlink.Route{Src: srcIp, Dst: nil, Gw: config.Netclient().CurrGwNmIP, Table: RouteTableName, Priority: 1}

	//delete default gateway at first
	if err := netlink.RouteDel(&gwRoute); err != nil {
		slog.Warn("remove default gateway failed", "error", err.Error())
		slog.Warn("please remove the gateway route manually")
		slog.Warn("gateway route: ", gwRoute.String())
	}

	//delete rules
	_, ipnet, err := net.ParseCIDR(IPv6Network)
	if err != nil {
		return err
	}
	//first rule :ip rule add from all table ROUTE_TABLE_NAME
	tRule := netlink.NewRule()
	tRule.Family = syscall.AF_INET6
	tRule.Src = ipnet
	tRule.Table = RouteTableName
	tRule.Priority = 3000
	if err := netlink.RuleDel(tRule); err != nil {
		slog.Warn("delete rule failed", "error", err.Error())
		slog.Warn("please remove the rule manually")
		slog.Warn("rule: ", tRule.String())
	}
	//second rule :ip rule add table main suppress_prefixlength 0
	sRule := netlink.NewRule()
	sRule.Family = syscall.AF_INET6
	sRule.Src = ipnet
	sRule.Table = unix.RT_TABLE_MAIN
	sRule.SuppressPrefixlen = 0
	sRule.Priority = 2500
	if err := netlink.RuleDel(sRule); err != nil {
		slog.Warn("delete rule failed", "error", err.Error())
		slog.Warn("please remove the rule manually", "rule: ", sRule.String())
	}
	//third rule :ip rule add from 68.183.79.137 table main
	lIp := config.Netclient().Host.EndpointIPv6

	_, ipnet, err = net.ParseCIDR(lIp.String() + "/128")
	if err != nil {
		return err
	}
	mRule := netlink.NewRule()
	mRule.Family = syscall.AF_INET6
	mRule.Src = ipnet
	mRule.Table = unix.RT_TABLE_MAIN
	mRule.Priority = 2000
	if err := netlink.RuleDel(mRule); err != nil {
		slog.Warn("delete rule failed", "error", err.Error())
		slog.Warn("please remove the rule manually", "rule: ", mRule.String())

	}

	config.Netclient().CurrGwNmIP = net.ParseIP("")
	if ipv6 := config.Netclient().OriginalDefaultGatewayIp.To4(); ipv6 == nil {
		ipv4, err := GetDefaultGateway()
		if err == nil && ipv4.Gw != nil {
			config.Netclient().OriginalDefaultGatewayIp = ipv4.Gw
		}
	}

	return config.WriteNetclientConfig()
}

// restoreInternetGwV4 - delete the route in table ROUTE_TABLE_NAME and delet the rules
func restoreInternetGwV4() (err error) {
	//build the default gateway route
	gwRoute := netlink.Route{Src: net.ParseIP("0.0.0.0"), Dst: nil, Gw: config.Netclient().CurrGwNmIP, Table: RouteTableName, Priority: 1}

	//delete default gateway at first
	if err := netlink.RouteDel(&gwRoute); err != nil && !strings.Contains(err.Error(), "no such process") {
		slog.Warn("remove default gateway failed", "error", err.Error())
		slog.Warn("please remove the gateway route manually")
		slog.Warn("gateway route: ", gwRoute.String())
	}

	//delete rules
	_, ipnet, err := net.ParseCIDR(IPv4Network)
	if err != nil {
		return err
	}
	//first rule :ip rule add from all table ROUTE_TABLE_NAME
	tRule := netlink.NewRule()
	tRule.Src = ipnet
	tRule.Table = RouteTableName
	tRule.Priority = 3000
	if err := netlink.RuleDel(tRule); err != nil {
		slog.Warn("delete rule failed", "error", err.Error())
		slog.Warn("please remove the rule manually")
		slog.Warn("rule: ", tRule.String())
	}
	//second rule :ip rule add table main suppress_prefixlength 0
	sRule := netlink.NewRule()
	sRule.Src = ipnet
	sRule.Table = unix.RT_TABLE_MAIN
	sRule.SuppressPrefixlen = 0
	sRule.Priority = 2500
	if err := netlink.RuleDel(sRule); err != nil {
		slog.Warn("delete rule failed", "error", err.Error())
		slog.Warn("please remove the rule manually", "rule: ", sRule.String())
	}
	//third rule :ip rule add from 68.183.79.137 table main
	lIp, err := getLocalIpByDefaultInterfaceName()
	if err != nil {
		lIp = config.Netclient().Host.EndpointIP
	}

	_, ipnet, err = net.ParseCIDR(lIp.String() + "/32")
	if err != nil {
		return err
	}
	mRule := netlink.NewRule()
	mRule.Src = ipnet
	mRule.Table = unix.RT_TABLE_MAIN
	mRule.Priority = 2000
	if err := netlink.RuleDel(mRule); err != nil {
		slog.Warn("delete rule failed", "error", err.Error())
		slog.Warn("please remove the rule manually", "rule: ", mRule.String())

	}

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
