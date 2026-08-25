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
)

const (
	RouteTableName    = 111
	EgressRouteMetric = 256
)

// useKernelWireGuard prefers kernel WG unless TCP uplink needs userspace conn.Bind.
func useKernelWireGuard() bool {
	return isKernelWireGuardPresent() && !relayTCPUserspaceNeeded()
}

// NCIface.Create - creates a linux WG interface based on a node's host config
func (nc *NCIface) Create() error {
	if !relayTCPUserspaceNeeded() {
		hostTcp := false
		if h := config.Netclient(); h != nil {
			hostTcp = h.TcpProxyEnabled
		}
		for netName, n := range config.GetNodes() {
			if n.UseTcpUplink || n.TcpProxyEnabled || hostTcp {
				slog.Warn("TCP uplink flags set but userspace bind not marked; prepareTCPUplinkWireGuard should run before Create",
					"network", netName,
					"use_tcp_uplink", n.UseTcpUplink,
					"tcp_proxy_enabled", n.TcpProxyEnabled,
					"host_tcp_proxy_enabled", hostTcp,
					"node", n.ID.String())
				break
			}
		}
	}
	if useKernelWireGuard() {
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
		if relayTCPUserspaceNeeded() {
			slog.Info("TCP uplink enabled: using userspace WireGuard for conn.Bind integration.")
		} else {
			slog.Info("Kernel WireGuard not detected. Proceeding with userspace WireGuard for iface creation.")
		}
		// Remove any existing iface (often a leftover kernel wireguard device) so
		// CreateTUN can own the name. Do not LinkAdd a kernel "wireguard" device
		// afterward — that conflicts with the TUN and returns EINVAL.
		if l, err := netlink.LinkByName(nc.Name); err == nil && l != nil {
			if err := netlink.LinkDel(l); err != nil {
				return fmt.Errorf("failed to remove existing interface %s: %w", nc.Name, err)
			}
		}
		if err := nc.createUserSpaceWG(); err != nil {
			return err
		}
		l, err := netlink.LinkByName(nc.Name)
		if err != nil {
			return fmt.Errorf("userspace tun %s missing after create: %w", nc.Name, err)
		}
		if err := netlink.LinkSetUp(l); err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf("WireGuard not detected")
}

// NCIface.SetMTU - sets the mtu for the interface
func (n *NCIface) SetMTU() error {
	l, err := netlink.LinkByName(n.Name)
	if err != nil {
		return err
	}
	return netlink.LinkSetMTU(l, n.MTU)
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
	// Tear down the iface that is actually running — not the *desired* mode.
	// prepareTCPUplinkWireGuard may already have flipped needTCPUplinkBind before
	// SIGHUP; consulting useKernelWireGuard() here skips LinkDel and leaves the
	// kernel UDP listen port busy (GetFreePort then bumps 51821→51822).
	if UserspaceWGActive() {
		fmt.Println("[listen-port-debug] Close: userspace path")
		n.closeUserspaceWg()
		// Best-effort remove leftover TUN/link name so kernel WG can recreate it.
		if l, err := netlink.LinkByName(n.Name); err == nil && l != nil {
			_ = netlink.LinkDel(l)
		}
		return
	}
	if l, err := netlink.LinkByName(n.Name); err == nil && l != nil {
		fmt.Println("[listen-port-debug] Close: deleting netlink iface",
			"name=", n.Name, "type=", l.Type(),
			"desiredUserspace=", relayTCPUserspaceNeeded())
		if err := netlink.LinkDel(l); err != nil {
			slog.Warn("failed to delete netmaker link on Close", "error", err)
		}
		return
	}
	fmt.Println("[listen-port-debug] Close: no userspace device and no netlink iface",
		"name=", n.Name, "desiredUserspace=", relayTCPUserspaceNeeded())
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
		removeSpecificRouteFromIGWTable(l, addr)
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
		addSpecificRouteToIGWTable(l, addr, metric)
	}
	return nil
}

// addSpecificRouteToIGWTable installs a more-specific egress CIDR in table 111 so
// it wins over the IGW default (0.0.0.0/0) when policy routing looks up that table.
func addSpecificRouteToIGWTable(l netlink.Link, addr ifaceAddress, metric int) {
	if l == nil || !igwRoutingActive() || addr.Network.IP == nil {
		return
	}
	dst := addr.Network
	r := netlink.Route{
		LinkIndex: l.Attrs().Index,
		Dst:       &dst,
		Table:     RouteTableName,
		Priority:  metric,
	}
	if err := netlink.RouteAdd(&r); err != nil && !strings.Contains(err.Error(), "file exists") {
		slog.Warn("error adding IGW-table egress route", "network", addr.Network.String(), "error", err.Error())
	}
}

func removeSpecificRouteFromIGWTable(l netlink.Link, addr ifaceAddress) {
	if l == nil || addr.Network.IP == nil {
		return
	}
	dst := addr.Network
	r := netlink.Route{
		LinkIndex: l.Attrs().Index,
		Dst:       &dst,
		Table:     RouteTableName,
	}
	if err := netlink.RouteDel(&r); err != nil && !strings.Contains(err.Error(), "no such process") {
		slog.Debug("remove IGW-table egress route", "network", addr.Network.String(), "error", err.Error())
	}
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
		// Prefer IPv4 nexthop when dual-stack IGW routes are present.
		var v6 net.IP
		for _, r := range routes {
			if r.Dst != nil && !r.Dst.IP.Equal(net.ParseIP("0.0.0.0")) && !r.Dst.IP.Equal(net.ParseIP("::")) {
				continue
			}
			if r.Gw == nil {
				continue
			}
			if r.Gw.To4() != nil {
				return r.Gw, nil
			}
			if v6 == nil {
				v6 = r.Gw
			}
		}
		if v6 != nil {
			return v6, nil
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
	currGw6 := config.Netclient().CurrGwNmIP6

	// Default v6 routes may have Dst == nil or Dst == ::/0 (same as GetDefaultGateway).
	// Skip our IGW table and current netmaker nexthop so we capture the real underlay GW.
	for _, r := range routes {
		if r.Table == RouteTableName {
			continue
		}
		isDefault := r.Dst == nil || (r.Dst != nil && (r.Dst.IP.Equal(net.ParseIP("::")) || r.Dst.String() == "::/0"))
		if !isDefault {
			continue
		}
		if len(currGw6) > 0 && r.Gw != nil && r.Gw.Equal(currGw6) {
			continue
		}
		gwRoutes = append(gwRoutes, r)
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

// GetDefaultGatewayIp6 - get current default gateway IPv6 address
func GetDefaultGatewayIp6() (ip net.IP, err error) {
	gwRoute, err := GetDefaultGatewayV6()
	if err != nil {
		return nil, err
	}
	return gwRoute.Gw, nil
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

// SetInternetGw - set a new default gateway and add rules to activate it.
// Installs IPv4 and/or IPv6 OS default routes when the corresponding nexthop is present.
func SetInternetGw(publicKey string, gw4, gw6 net.IP) (err error) {
	if IsZeroWGPublicKey(publicKey) {
		return fmt.Errorf("internet gateway peer public key is empty")
	}
	err = setDefaultRoutesOnHost(publicKey, gw4, gw6)
	if len(config.Netclient().CurrGwNmIP) > 0 || len(config.Netclient().CurrGwNmIP6) > 0 {
		GetIGWMonitor().Monitor(publicKey, gw4, gw6)
		if err != nil {
			slog.Warn("internet gateway partially configured", "error", err.Error())
		}
		return nil
	}
	return err
}

func setDefaultRoutesOnHost(publicKey string, gw4, gw6 net.IP) error {
	var firstErr error
	if len(gw4) > 0 {
		if err := setInternetGwV4(publicKey, gw4); err != nil {
			slog.Error("failed to set IPv4 internet gateway", "error", err.Error())
			firstErr = err
		}
	}
	if len(gw6) > 0 {
		if err := setInternetGwV6(publicKey, gw6); err != nil {
			slog.Error("failed to set IPv6 internet gateway", "error", err.Error())
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	reapplyCachedEgressRoutes()
	return firstErr
}

// setInternetGwV6 - set a new default gateway and add rules to activate it
func setInternetGwV6(publicKey string, networkIP net.IP) (err error) {
	// Preserve original IPv4 gateway; track IPv6 original separately.
	if len(config.Netclient().OriginalDefaultGatewayIp6) == 0 {
		if ipv6, err := GetDefaultGatewayV6(); err == nil && ipv6.Gw != nil && ipv6.Gw.To4() == nil {
			// Never store the netmaker overlay nexthop as the "original" underlay gateway.
			if !ipv6.Gw.Equal(networkIP) {
				config.Netclient().OriginalDefaultGatewayIp6 = ipv6.Gw
			}
		}
	}

	srcIp := getSourceIpv6(networkIP)
	//build the gateway route, with Table ROUTE_TABLE_NAME, metric 1
	gwRoute := netlink.Route{Src: srcIp, Dst: nil, Gw: networkIP, Table: RouteTableName, Priority: 1}

	//Check if table ROUTE_TABLE_NAME existed
	routes, _ := netlink.RouteListFiltered(netlink.FAMILY_V6, &gwRoute, netlink.RT_FILTER_TABLE)
	if len(routes) > 0 {
		// Only clear existing IPv6 IGW state; do not wipe a just-installed IPv4 IGW.
		_ = restoreInternetGwV6()
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
		_ = restoreInternetGwV6()
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
		_ = restoreInternetGwV6()
		return err
	}
	//third rule : keep traffic from the host's public IPv6 endpoint on the main table.
	// Skip when the client has no IPv6 endpoint (IPv4-only WAN) — still allow tunneled IPv6.
	if lIp := config.Netclient().Host.EndpointIPv6; len(lIp) > 0 {
		_, srcNet, parseErr := net.ParseCIDR(lIp.String() + "/128")
		if parseErr != nil {
			slog.Warn("skip IPv6 local-endpoint rule", "error", parseErr.Error())
		} else {
			mRule := netlink.NewRule()
			mRule.Family = syscall.AF_INET6
			mRule.Src = srcNet
			mRule.Table = unix.RT_TABLE_MAIN
			mRule.Priority = 2000
			if err := netlink.RuleAdd(mRule); err != nil {
				slog.Warn("add IPv6 local-endpoint rule failed", "mRule: ", mRule.String(), "error", err.Error())
			}
		}
	}

	igwHostIPs := IGWUnderlayPinIPs(publicKey)
	for _, hostIP := range igwHostIPs {
		if hostIP.To4() != nil {
			continue
		}
		destinationIP, destination, err := net.ParseCIDR(hostIP.String() + "/128")
		if err != nil {
			slog.Warn("skip IPv6 peer-endpoint rule", "ip", hostIP, "error", err)
			continue
		}
		destination.IP = destinationIP
		gwRule := netlink.NewRule()
		gwRule.Family = syscall.AF_INET6
		gwRule.Dst = destination
		gwRule.Table = unix.RT_TABLE_MAIN
		gwRule.Priority = 2999
		if err := netlink.RuleAdd(gwRule); err != nil {
			slog.Warn("add IPv6 peer-endpoint rule failed", "gwRule: ", gwRule.String(), "error", err.Error())
		} else {
			slog.Info("pinning exit-node IPv6 underlay via main table", "dst", destination.String())
		}
	}

	config.Netclient().CurrGwNmIP6 = networkIP
	// Keep CurrGwNmIP populated for single-stack IPv6 clients (DNS / legacy checks).
	if len(config.Netclient().CurrGwNmIP) == 0 {
		config.Netclient().CurrGwNmIP = networkIP
	}
	return config.WriteNetclientConfig()
}

// setInternetGwV4 - set a new default gateway and add rules to activate it
func setInternetGwV4(publicKey string, networkIP net.IP) (err error) {
	// Pin underlay IPs BEFORE table-500 / "from all lookup IGW" rules. Otherwise
	// handshake UDP to the exit public IP is selected into the IGW table and
	// never leaves the host — no handshake. TCP uplink masks this by dialing
	// TLS while the LAN default route still works (reconcile before SetInternetGw).
	hostIPs := InternetGwHostIPs(publicKey)
	var v4Pins []*net.IPNet
	for _, hostIP := range hostIPs {
		if hostIP.To4() == nil {
			continue
		}
		destinationIP, destination, parseErr := net.ParseCIDR(hostIP.String() + "/32")
		if parseErr != nil {
			slog.Warn("skip IPv4 peer-endpoint rule", "ip", hostIP, "error", parseErr)
			continue
		}
		destination.IP = destinationIP
		v4Pins = append(v4Pins, destination)
	}
	if len(v4Pins) == 0 {
		slog.Error("no underlay IP for exit peer; refusing IGW setup (would blackhole WireGuard UDP handshake)",
			"public_key_prefix", publicKey[:min(8, len(publicKey))])
		return errors.New("no underlay endpoint for internet gateway peer")
	}

	//build the gateway route, with Table ROUTE_TABLE_NAME, metric 1
	defaultRoute := netlink.Route{Src: net.ParseIP("0.0.0.0"), Dst: nil, Gw: networkIP, Table: RouteTableName, Priority: 1}

	//Check if table ROUTE_TABLE_NAME existed
	routes, _ := netlink.RouteListFiltered(netlink.FAMILY_V4, &defaultRoute, netlink.RT_FILTER_TABLE)
	if len(routes) > 0 {
		// Only clear existing IPv4 IGW state; do not wipe a just-installed/existing IPv6 IGW.
		if err := restoreInternetGwV4(); err != nil {
			slog.Error("remove IPv4 IGW routes failed", "error", err.Error())
			return err
		}
	}

	// Pin exit underlay to main first (priority 2999 beats 3000 IGW table lookup).
	for _, destination := range v4Pins {
		gwRule := netlink.NewRule()
		gwRule.Dst = destination
		gwRule.Table = unix.RT_TABLE_MAIN
		gwRule.Priority = 2999
		if err := netlink.RuleAdd(gwRule); err != nil {
			slog.Error("add new rule failed", "gwRule: ", gwRule.String(), "error", err.Error())
			_ = restoreInternetGwV4()
			return err
		}
		slog.Info("pinning exit-node underlay via main table", "dst", destination.String())
	}
	// Site-egress (and other direct) peer underlays must also stay on main;
	// otherwise UDP to those hosts matches table-111 0.0.0.0/0 and trombones.
	pinInternetGwHostRoutes(publicKey)

	//set new default gateway
	if err := netlink.RouteAdd(&defaultRoute); err != nil {
		slog.Error("add new default gateway failed", "error", err.Error())
		_ = restoreInternetGwV4()
		return err
	}

	//add rules
	_, ipnet, err := net.ParseCIDR(IPv4Network)
	if err != nil {
		_ = restoreInternetGwV4()
		return err
	}
	//first rule :ip rule add from all table ROUTE_TABLE_NAME
	tRule := netlink.NewRule()
	tRule.Src = ipnet
	tRule.Table = RouteTableName
	tRule.Priority = 3000
	if err := netlink.RuleAdd(tRule); err != nil {
		slog.Error("add new rule failed", "rule", tRule.String(), "error", err.Error())
		_ = restoreInternetGwV4()
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
		_ = restoreInternetGwV4()
		return err
	}
	//third rule :ip rule add from 68.183.79.137 table main
	lIp, err := getLocalIpByDefaultInterfaceName()
	if err != nil {
		lIp = config.Netclient().Host.EndpointIP
	}

	_, ipnet, err = net.ParseCIDR(lIp.String() + "/32")
	if err != nil {
		_ = restoreInternetGwV4()
		return err
	}
	mRule := netlink.NewRule()
	mRule.Src = ipnet
	mRule.Table = unix.RT_TABLE_MAIN
	mRule.Priority = 2000
	if err := netlink.RuleAdd(mRule); err != nil {
		slog.Error("add new rule failed", "mRule: ", mRule.String(), "error", err.Error())
		_ = restoreInternetGwV4()
		return err
	}

	config.Netclient().CurrGwNmIP = networkIP
	return config.WriteNetclientConfig()
}

// RestoreInternetGw - delete the route in table ROUTE_TABLE_NAME and delet the rules
func RestoreInternetGw() (err error) {
	err = resetDefaultRoutesOnHost()
	if err == nil {
		GetIGWMonitor().Stop()
	}

	return err
}

func resetDefaultRoutesOnHost() error {
	var firstErr error
	curr := config.Netclient().CurrGwNmIP
	curr6 := config.Netclient().CurrGwNmIP6
	needV4 := len(curr) > 0 && curr.To4() != nil
	needV6 := len(curr6) > 0 || (len(curr) > 0 && curr.To4() == nil)
	if needV4 {
		if err := restoreInternetGwV4(); err != nil {
			firstErr = err
		}
	}
	if needV6 {
		if err := restoreInternetGwV6(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// restoreInternetGwV6 - delete the route in table ROUTE_TABLE_NAME and delet the rules
func restoreInternetGwV6() (err error) {
	gwIP := config.Netclient().CurrGwNmIP6
	if len(gwIP) == 0 {
		gwIP = config.Netclient().CurrGwNmIP // legacy single-stack IPv6
	}
	srcIp := getSourceIpv6(gwIP)
	//build the default gateway route
	gwRoute := netlink.Route{Src: srcIp, Dst: nil, Gw: gwIP, Table: RouteTableName, Priority: 1}

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
	//third rule :ip rule add from local endpoint table main
	lIp := config.Netclient().Host.EndpointIPv6
	if len(lIp) > 0 {
		if _, ipnet, err = net.ParseCIDR(lIp.String() + "/128"); err == nil {
			mRule := netlink.NewRule()
			mRule.Family = syscall.AF_INET6
			mRule.Src = ipnet
			mRule.Table = unix.RT_TABLE_MAIN
			mRule.Priority = 2000
			if err := netlink.RuleDel(mRule); err != nil {
				slog.Warn("delete rule failed", "error", err.Error())
				slog.Warn("please remove the rule manually", "rule: ", mRule.String())
			}
		}
	}

	if rules, listErr := netlink.RuleList(netlink.FAMILY_V6); listErr == nil {
		for _, r := range rules {
			if r.Priority != 2999 || r.Table != unix.RT_TABLE_MAIN {
				continue
			}
			rule := r
			if err := netlink.RuleDel(&rule); err != nil {
				slog.Warn("delete rule failed", "error", err.Error(), "rule", rule.String())
			}
		}
	} else {
		gwRule := netlink.NewRule()
		gwRule.Family = syscall.AF_INET6
		gwRule.Table = unix.RT_TABLE_MAIN
		gwRule.Priority = 2999
		if err := netlink.RuleDel(gwRule); err != nil {
			slog.Warn("delete rule failed", "error", err.Error())
			slog.Warn("please remove the rule manually", "rule: ", gwRule.String())
		}
	}

	config.Netclient().CurrGwNmIP6 = net.ParseIP("")
	// Only clear CurrGwNmIP when it was the IPv6 nexthop (single-stack v6).
	if curr := config.Netclient().CurrGwNmIP; curr != nil && curr.To4() == nil {
		config.Netclient().CurrGwNmIP = net.ParseIP("")
	}
	// Do not clobber OriginalDefaultGatewayIp (IPv4); clear only the v6 original if needed by callers.

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

	// Delete all priority-2999 underlay pins (may be more than one host IP).
	if rules, listErr := netlink.RuleList(netlink.FAMILY_V4); listErr == nil {
		for _, r := range rules {
			if r.Priority != 2999 || r.Table != unix.RT_TABLE_MAIN {
				continue
			}
			rule := r
			if err := netlink.RuleDel(&rule); err != nil {
				slog.Warn("delete rule failed", "error", err.Error(), "rule", rule.String())
			}
		}
	} else {
		gwRule := netlink.NewRule()
		gwRule.Table = unix.RT_TABLE_MAIN
		gwRule.Priority = 2999
		if err := netlink.RuleDel(gwRule); err != nil {
			slog.Warn("delete rule failed", "error", err.Error())
			slog.Warn("please remove the rule manually", "rule: ", gwRule.String())
		}
	}

	config.Netclient().CurrGwNmIP = net.ParseIP("")
	return config.WriteNetclientConfig()
}

// pinInternetGwHostRoutes adds main-table rules for exit and non-exit peer
// underlay IPs without changing the IGW table default. Safe when exit routing
// is already active.
func pinInternetGwHostRoutes(publicKey string) {
	for _, hostIP := range IGWUnderlayPinIPs(publicKey) {
		var cidr string
		family := netlink.FAMILY_V4
		if hostIP.To4() != nil {
			cidr = hostIP.String() + "/32"
		} else {
			cidr = hostIP.String() + "/128"
			family = netlink.FAMILY_V6
		}
		destinationIP, destination, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		destination.IP = destinationIP
		gwRule := netlink.NewRule()
		gwRule.Dst = destination
		gwRule.Table = unix.RT_TABLE_MAIN
		gwRule.Priority = 2999
		if family == netlink.FAMILY_V6 {
			gwRule.Family = syscall.AF_INET6
		}
		if err := netlink.RuleAdd(gwRule); err != nil {
			// Rule may already exist from SetInternetGw.
			continue
		}
		slog.Info("pinning exit-node underlay via main table", "dst", destination.String())
	}
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
