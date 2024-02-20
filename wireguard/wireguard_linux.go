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
	"golang.org/x/sys/unix"
)

const (
	ROUTE_TABLE_NAME = 111
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
	//if table ROUTE_TABLE_NAME existed, return the gateway ip from table ROUTE_TABLE_NAME
	//build the gateway route, with Table ROUTE_TABLE_NAME, metric 1
	tRoute := netlink.Route{Src: net.ParseIP("0.0.0.0"), Dst: nil, Table: ROUTE_TABLE_NAME}
	//Check if table ROUTE_TABLE_NAME existed
	routes, _ := netlink.RouteListFiltered(netlink.FAMILY_V4, &tRoute, netlink.RT_FILTER_TABLE)
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

// getLocalIpByDefaultInterfaceName - get local ip address by default interface name in config file
func getLocalIpByDefaultInterfaceName() (ip net.IP, err error) {
	dLink, err := netlink.LinkByName(config.Netclient().Host.DefaultInterface)
	if err == nil && dLink != nil {
		addrList, err := netlink.AddrList(dLink, netlink.FAMILY_V4)
		if err == nil && len(addrList) > 0 {
			return addrList[0].IP, nil
		}
	}
	return ip, errors.New("could not get local ip by default interface name")
}

// SetInternetGw - set a new default gateway and add rules to activate it
func SetInternetGw(gwIp net.IP) (err error) {

	//build the gateway route, with Table ROUTE_TABLE_NAME, metric 1
	gwRoute := netlink.Route{Src: net.ParseIP("0.0.0.0"), Dst: nil, Gw: gwIp, Table: ROUTE_TABLE_NAME, Priority: 1}

	//Check if table ROUTE_TABLE_NAME existed
	routes, _ := netlink.RouteListFiltered(netlink.FAMILY_V4, &gwRoute, netlink.RT_FILTER_TABLE)
	if len(routes) > 0 {
		err = RestoreInternetGw()
		if err != nil {
			slog.Error("remove table "+fmt.Sprintf("%d", ROUTE_TABLE_NAME)+" failed", "error", err.Error())
			return err
		}
	}

	//set new default gateway
	if err := netlink.RouteAdd(&gwRoute); err != nil {
		slog.Error("add new default gateway failed", "error", err.Error())
		return err
	}

	//add rules
	_, ipnet, err := net.ParseCIDR("0.0.0.0/0")
	if err != nil {
		return err
	}
	//first rule :ip rule add from all table ROUTE_TABLE_NAME
	tRule := netlink.NewRule()
	tRule.Src = ipnet
	tRule.Table = ROUTE_TABLE_NAME
	tRule.Priority = 3000
	if err := netlink.RuleAdd(tRule); err != nil {
		slog.Error("add new rule failed", "error", err.Error())
		slog.Error("rule: ", tRule.String())
		RestoreInternetGw()
		return err
	}
	//second rule :ip rule add from 68.183.79.137 table main
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
		slog.Error("add new rule failed", "error", err.Error())
		slog.Error("mRule: ", tRule.String())
		RestoreInternetGw()
		return err
	}

	config.Netclient().CurrGwNmIP = gwIp
	return nil
}

// RestoreInternetGw - delete the route in table ROUTE_TABLE_NAME and delet the rules
func RestoreInternetGw() (err error) {
	//build the default gateway route
	gwRoute := netlink.Route{Src: net.ParseIP("0.0.0.0"), Dst: nil, Gw: config.Netclient().CurrGwNmIP, Table: ROUTE_TABLE_NAME, Priority: 1}

	//delete default gateway at first
	if err := netlink.RouteDel(&gwRoute); err != nil {
		slog.Error("remove default gateway failed", "error", err.Error())
		slog.Error("please remove the gateway route manually")
		slog.Error("gateway route: ", gwRoute.String())
	}

	//delete rules
	_, ipnet, err := net.ParseCIDR("0.0.0.0/0")
	if err != nil {
		return err
	}
	//first rule :ip rule add from all table ROUTE_TABLE_NAME
	tRule := netlink.NewRule()
	tRule.Src = ipnet
	tRule.Table = ROUTE_TABLE_NAME
	tRule.Priority = 3000
	if err := netlink.RuleDel(tRule); err != nil {
		slog.Error("delete new rule failed", "error", err.Error())
		slog.Error("please remove the rule manually")
		slog.Error("rule: ", tRule.String())
	}
	//second rule :ip rule add from 68.183.79.137 table main
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
		slog.Error("delete new rule failed", "error", err.Error())
		slog.Error("please remove the rule manually")
		slog.Error("rule: ", mRule.String())
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
