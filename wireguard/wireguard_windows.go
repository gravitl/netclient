package wireguard

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"golang.org/x/exp/slog"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/driver"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// TODO: update from netsh to a more programmatic approach.

// NCIface.Create - makes a new Wireguard interface and sets given addresses
func (nc *NCIface) Create() error {
	// TCP uplink needs userspace wireguard-go + relayTCPBind (Wintun). WireGuardNT
	// cannot host a custom conn.Bind, so divert traffic over TCP when required.
	if relayTCPUserspaceNeeded() {
		slog.Info("TCP uplink enabled: using userspace WireGuard (Wintun) for conn.Bind integration")
		// Measured before the adapter exists, as in the WireGuardNT path below, so
		// netmaker itself can never be the interface that resolves.
		var ifaceMetric uint32
		if !nc.IsTestIface {
			ifaceMetric, _ = cachedResolvingInterfaceMetric()
		}
		if err := nc.createUserSpaceWG(); err != nil {
			return err
		}
		if err := nc.setInterfaceMetric(ifaceMetric); err != nil {
			slog.Warn("failed to set userspace interface metric", "error", err)
		}
		return nil
	}

	wgMutex.Lock()
	defer wgMutex.Unlock()

	var ifaceMetric uint32
	if !nc.IsTestIface {
		ifaceMetric, _ = cachedResolvingInterfaceMetric()
	}

	adapter, err := driver.OpenAdapter(nc.Name)
	if err != nil {
		slog.Info("creating Windows tunnel")
		idString := config.Netclient().Host.ID.String()
		if idString == "" {
			idString = config.DefaultHostID
		}
		if nc.IsTestIface {
			idString = uuid.NewString()
		}
		windowsGUID, err := windows.GUIDFromString("{" + idString + "}")
		if err != nil {
			slog.Error("generating guid error: ", "error", err)
			return err
		}
		adapter, err = driver.CreateAdapter(nc.Name, "WireGuard", &windowsGUID)
		if err != nil {
			// Check if adapter already exists - try to open it again
			if strings.Contains(err.Error(), "already exists") || strings.Contains(err.Error(), "Cannot create a file when that file already exists") {
				slog.Info("adapter already exists, attempting to open it")
				// Retry opening the adapter - it might have been created by another process
				var openErr error
				adapter, openErr = driver.OpenAdapter(nc.Name)
				if openErr != nil {
					slog.Error("creating adapter error (adapter exists but cannot be opened): ", "error", err, "openError", openErr)
					return fmt.Errorf("adapter exists but cannot be opened: %w (original error: %v)", openErr, err)
				}
				slog.Info("successfully opened existing adapter")
				err = nil // Clear the error since we successfully opened the adapter
			} else {
				slog.Error("creating adapter error: ", "error", err)
				return err
			}
		}
	} else {
		slog.Info("re-using existing adapter")
	}

	slog.Info("created Windows tunnel")
	nc.Iface = adapter
	err = adapter.SetAdapterState(driver.AdapterStateUp)
	if err != nil {
		return err
	}

	return nc.setInterfaceMetric(ifaceMetric)
}

// setInterfaceMetric puts the netmaker interface one step behind the interface
// that resolves DNS, so Windows keeps preferring that one for resolution.
func (nc *NCIface) setInterfaceMetric(resolvingMetric uint32) error {
	if resolvingMetric == 0 {
		return nil
	}
	_, err := runPSCommand(fmt.Sprintf("Set-NetIPInterface -InterfaceAlias '%s' -InterfaceMetric %d", nc.Name, resolvingMetric+1))
	return err
}

// NCIface.ApplyAddrs - applies addresses to windows tunnel ifaces, unused currently
func (nc *NCIface) ApplyAddrs() error {
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

	if UserspaceWGActive() {
		iface, err := net.InterfaceByName(nc.Name)
		if err != nil {
			return fmt.Errorf("userspace iface %s: %w", nc.Name, err)
		}
		luid, err := winipcfg.LUIDFromIndex(uint32(iface.Index))
		if err != nil {
			return fmt.Errorf("userspace LUID: %w", err)
		}
		return luid.SetIPAddresses(prefixAddrs)
	}

	adapter := nc.Iface
	return adapter.(*driver.Adapter).LUID().SetIPAddresses(prefixAddrs)
}

// RemoveRoutes - remove routes to the interface
func RemoveRoutes(addrs []ifaceAddress) {
	for _, addr := range addrs {
		if (len(config.GetNodes()) > 1 && addr.IP == nil) || addr.Network.IP == nil || addr.Network.String() == IPv4Network ||
			addr.Network.String() == IPv6Network || (len(config.GetNodes()) > 1 && addr.GwIP == nil) {
			continue
		}
		if addr.Network.IP.To4() != nil {
			slog.Info("removing ipv4 route to interface", "route", fmt.Sprintf("%s -> %s", addr.IP.String(), addr.Network.String()))
			cmd := fmt.Sprintf("netsh int ipv4 delete route %s interface=%s store=%s metric=%d",
				addr.Network.String(), ncutils.GetInterfaceName(), "active", addr.Metric)
			_, err := ncutils.RunCmd(cmd, false)
			if err != nil {
				slog.Error("failed to apply", "ipv4 egress range", addr.Network.String(), err.Error())
			}
		} else {
			slog.Info("removing ipv6 route to interface", "route", fmt.Sprintf("%s -> %s", addr.IP.String(), addr.Network.String()))
			cmd := fmt.Sprintf("netsh int ipv6 delete route %s interface=%s store=%s metric=%d",
				addr.Network.String(), ncutils.GetInterfaceName(), "active", addr.Metric)
			_, err := ncutils.RunCmd(cmd, false)
			if err != nil {
				slog.Error("failed to apply", "ipv6 egress range", addr.Network.String(), err.Error())
			}
		}
	}
}

// SetRoutes - sets additional routes to the interface.
// Routes are on-link: an overlay nexthop would sit in Probe state forever
// because the WireGuard adapter never answers neighbour discovery.
func SetRoutes(addrs []ifaceAddress) error {
	for _, addr := range addrs {
		if (len(config.GetNodes()) > 1 && addr.IP == nil) || addr.Network.IP == nil || addr.Network.String() == IPv4Network ||
			addr.Network.String() == IPv6Network || (len(config.GetNodes()) > 1 && addr.GwIP == nil) {
			continue
		}
		if addr.Network.IP.To4() != nil {
			slog.Info("adding ipv4 route to interface", "route", fmt.Sprintf("%s -> %s", addr.IP.String(), addr.Network.String()))
			cmd := fmt.Sprintf("netsh int ipv4 add route %s interface=%s store=%s metric=%d",
				addr.Network.String(), ncutils.GetInterfaceName(), "active", addr.Metric)
			out, err := ncutils.RunCmd(cmd, false)
			if err != nil && !strings.Contains(out, "already exists") {
				slog.Error("failed to apply", "ipv4 egress range", addr.Network.String(), err.Error())
			}
		} else {
			slog.Info("adding ipv6 route to interface", "route", fmt.Sprintf("%s -> %s", addr.IP.String(), addr.Network.String()))
			cmd := fmt.Sprintf("netsh int ipv6 add route %s interface=%s store=%s metric=%d",
				addr.Network.String(), ncutils.GetInterfaceName(), "active", addr.Metric)
			out, err := ncutils.RunCmd(cmd, false)
			if err != nil && !strings.Contains(out, "already exists") {
				slog.Error("failed to apply", "ipv6 egress range", addr.Network.String(), err.Error())
			}
		}
	}
	return nil
}

func getInterfaceInfo() (iList []string, err error) {
	//get current interfaces
	output, err := ncutils.RunCmd("netsh int ipv4 show interfaces", true)
	if err != nil {
		return iList, err
	}

	if strings.Contains(output, "\r") {
		iList = strings.Split(output, "\r")
	} else if strings.Contains(output, "\n") {
		iList = strings.Split(output, "\n")
	}

	return iList, nil
}

// getDefaultGateway - returns the highest-priority default gateway route for the given IP family ("v4" or "v6").
func getDefaultGateway(family string) (output []string, err error) {
	var cmd, network string
	switch family {
	case "v6":
		cmd = "netsh int ipv6 show route"
		network = IPv6Network
	default:
		cmd = "netsh int ipv4 show route"
		network = IPv4Network
	}

	input, err := ncutils.RunCmd(cmd, true)
	if err != nil {
		return []string{}, err
	}

	var rList []string
	if strings.Contains(input, "\r") {
		rList = strings.Split(input, "\r")
	} else if strings.Contains(input, "\n") {
		rList = strings.Split(input, "\n")
	}

	rLines := []string{}
	for _, l := range rList {
		if strings.Contains(l, network) {
			rLines = append(rLines, l)
		}
	}

	//in case that multiple default gateway in the route table, return the one with higher priority
	if len(rLines) == 0 {
		return []string{}, nil
	} else if len(rLines) == 1 {
		output = strings.Fields(rLines[0])
	} else {
		metric := 10000
		iList, err := getInterfaceInfo()
		if err != nil {
			iList = []string{}
		} else {
			//remove the empty and title lines
			iList = iList[3:]
		}
		for _, r := range rLines {
			//on Windows, when "Automatic Metric" is enabled on interface, there is a default metric for each route entry
			//So the overall metric will be "default metric"+"route entry metric"
			dMetric := 0
			rArray := strings.Fields(r)

			//get the default metric value,  dMetric, by matching the interface Idx
			if len(iList) > 0 {
				for _, if1 := range iList {
					iArray := strings.Fields(if1)

					//match with Idx, first column in interface info,  last second column in route info
					if strings.TrimSpace(rArray[len(rArray)-2]) == strings.TrimSpace(iArray[0]) {
						//default metric in in the second column in inteface info
						j, err := strconv.Atoi(iArray[1])
						if err == nil && j >= 0 {
							dMetric = j
							break
						}
					}
				}
			}

			//get the gateway ip with lowest metric
			i, err := strconv.Atoi(rArray[2])
			if err == nil && i+dMetric <= metric {
				metric = i
				output = rArray
			}
		}
	}

	if len(output) == 0 {
		output = strings.Fields(rLines[0])
	}
	return output, nil
}

// GetDefaultGatewayIp - get current default gateway ip
func GetDefaultGatewayIp() (ip net.IP, err error) {

	//filter and get current default gateway route
	gwRoute, err := getDefaultGateway("v4")
	if err != nil || len(gwRoute) == 0 {
		return ip, errors.New("no default gateway found, please run command route -n to check in the route table")
	}

	//get the ip address from the last column
	ipString := strings.TrimSpace(gwRoute[len(gwRoute)-1])
	ip = net.ParseIP(ipString)

	return ip, nil
}

// GetDefaultGatewayIp6 - get current default gateway IPv6 address when present.
func GetDefaultGatewayIp6() (ip net.IP, err error) {
	if len(config.Netclient().OriginalDefaultGatewayIp6) > 0 {
		return config.Netclient().OriginalDefaultGatewayIp6, nil
	}
	gwRoute, err := getDefaultGateway("v6")
	if err != nil || len(gwRoute) == 0 {
		return nil, errors.New("no IPv6 default gateway found")
	}
	ipString := strings.TrimSpace(gwRoute[len(gwRoute)-1])
	ip = net.ParseIP(ipString)
	if ip == nil || ip.To4() != nil {
		return nil, errors.New("no IPv6 default gateway found")
	}
	return ip, nil
}

// SetInternetGw - set a new default gateway and the route to Internet Gw's ip address.
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
	// Reinstall more-specific egress CIDRs so they win over on-link 0.0.0.0/0
	// after IGW install or monitor recovery.
	reapplyCachedEgressRoutes()
	return firstErr
}

// setInternetGwV6 - set a new default gateway and the route to Internet Gw's ip address
func setInternetGwV6(publicKey string, networkIP net.IP) (err error) {
	// Capture original IPv6 default gateway without clobbering the IPv4 original.
	if len(config.Netclient().OriginalDefaultGatewayIp6) == 0 {
		if gwRoute, err := getDefaultGateway("v6"); err == nil && len(gwRoute) > 0 {
			ipString := strings.TrimSpace(gwRoute[len(gwRoute)-1])
			if ip := net.ParseIP(ipString); ip != nil && ip.To4() == nil {
				config.Netclient().OriginalDefaultGatewayIp6 = ip
			}
		}
	}

	//get current default gateway route
	gwRoute, err := getDefaultGateway("v6")
	if err != nil || len(gwRoute) == 0 {
		if err != nil {
			slog.Error("no default gateway found, please run command route -n to check in the route table", "error", errString(err))
		}
	} else {
		//if default gateway metric is 0, then reset it to 50
		ipString := strings.TrimSpace(gwRoute[len(gwRoute)-1])
		metric := strings.TrimSpace(gwRoute[2])
		if metric == "0" && ipString != networkIP.String() {
			parsed := net.ParseIP(ipString)
			if parsed != nil && parsed.To4() == nil {
				if len(config.Netclient().OriginalDefaultGatewayIp6) == 0 {
					config.Netclient().OriginalDefaultGatewayIp6 = parsed
				}
				//set the original gateway metric to 50
				setGwCmd := fmt.Sprintf("netsh int ipv6 set route %s interface=%s nexthop=%s store=active metric=50", IPv6Network, strings.TrimSpace(gwRoute[len(gwRoute)-2]), ipString)

				_, err = ncutils.RunCmd(setGwCmd, true)
				if err != nil {
					slog.Error("Failed to set original gateway route metric", "error", err.Error())
					slog.Error("please change the metric to 50 manaull to avoid issue", "error")
					slog.Error("netsh int ipv6 set route ::/0 interface=<Idx> nexthop=<ipv6 address> store=active metric=50", "error")
				}
			}
		}

		igwHostIPs := IGWUnderlayPinIPs(publicKey)
		for _, hostIP := range igwHostIPs {
			if hostIP.To4() != nil {
				continue
			}
			destination := hostIP.String() + "/128"
			gwRouteCmd := fmt.Sprintf("netsh int ipv6 add route %s interface=%s nexthop=%s store=active metric=1", destination, strings.TrimSpace(gwRoute[len(gwRoute)-2]), ipString)
			_, err = ncutils.RunCmd(gwRouteCmd, true)
			if err != nil {
				slog.Error("Failed to add route to gateway", "error", err.Error())
			}
		}
	}

	//add new gateway route with metric 0 for setting to top priority, on-link so
	//Windows does not wait for neighbour discovery on the overlay nexthop
	addGwCmd := fmt.Sprintf("netsh int ipv6 add route %s interface=%s store=active metric=0", IPv6Network, ncutils.GetInterfaceName())

	out, err := ncutils.RunCmd(addGwCmd, false)
	if err != nil && !isNetshAlreadyExists(out) {
		slog.Error("Failed to add route table", "error", err.Error(), "out", strings.TrimSpace(out))
		return err
	}

	config.Netclient().CurrGwNmIP6 = networkIP
	if len(config.Netclient().CurrGwNmIP) == 0 {
		config.Netclient().CurrGwNmIP = networkIP
	}
	return config.WriteNetclientConfig()
}

// setInternetGwV4 - set a new default gateway and the route to Internet Gw's ip address.
// Underlay pinning is best-effort: only failing to install 0.0.0.0/0 itself is
// treated as an error, so a pin problem can never leave the host without exit
// routing.
func setInternetGwV4(publicKey string, networkIP net.IP) error {
	if lan, ok := lanDefaultRouteV4(networkIP); ok {
		if len(config.Netclient().OriginalDefaultGatewayIp) == 0 {
			config.Netclient().OriginalDefaultGatewayIp = lan.gw
		}
		if lan.metric == "0" {
			setGwCmd := fmt.Sprintf("netsh int ipv4 set route %s interface=%s nexthop=%s store=active metric=50", IPv4Network, lan.ifaceIdx, lan.gw)
			if _, err := ncutils.RunCmd(setGwCmd, false); err != nil {
				slog.Error("Failed to set original gateway route metric", "error", err.Error())
			}
		}
		pinHostIPsViaLanV4(IGWUnderlayPinIPs(publicKey), lan)
	} else {
		slog.Warn("no LAN default gateway found; exit-node underlay cannot be pinned",
			"public_key_prefix", publicKey[:min(8, len(publicKey))])
	}

	// On-link (no nexthop), like WireGuard for Windows installs its AllowedIPs
	// routes. An overlay nexthop puts the route in Probe state forever — the
	// WireGuard adapter never answers neighbour discovery — and Windows then
	// ignores the route and keeps using the LAN default no matter its metric.
	addGwCmd := fmt.Sprintf("netsh int ipv4 add route %s interface=%s store=active metric=0", IPv4Network, ncutils.GetInterfaceName())
	out, err := ncutils.RunCmd(addGwCmd, false)
	if err != nil && !isNetshAlreadyExists(out) {
		slog.Error("Failed to add route table", "error", err.Error(), "out", strings.TrimSpace(out))
		return err
	}

	config.Netclient().CurrGwNmIP = networkIP
	return config.WriteNetclientConfig()
}

// lanRouteV4 describes the pre-exit (underlay) IPv4 default route.
type lanRouteV4 struct {
	ifaceIdx string
	gw       net.IP
	metric   string
}

// pinHostIPsViaLanV4 adds /32 routes for exit underlay IPs via the LAN gateway.
func pinHostIPsViaLanV4(hostIPs []net.IP, lan lanRouteV4) {
	pinned := 0
	for _, hostIP := range hostIPs {
		if hostIP.To4() == nil {
			continue
		}
		destination := hostIP.String() + "/32"
		gwRouteCmd := fmt.Sprintf("netsh int ipv4 add route %s interface=%s nexthop=%s store=active metric=1", destination, lan.ifaceIdx, lan.gw)
		out, err := ncutils.RunCmd(gwRouteCmd, false)
		if err != nil && !isNetshAlreadyExists(out) {
			slog.Error("Failed to pin exit-node underlay route", "destination", destination,
				"error", err.Error(), "out", strings.TrimSpace(out))
			continue
		}
		slog.Info("pinning exit-node underlay via LAN gateway", "cmd", gwRouteCmd)
		pinned++
	}
	if pinned == 0 {
		slog.Warn("no exit-node underlay host route pinned; WireGuard/TCP underlay may be blackholed",
			"candidates", len(hostIPs))
	}
}

// pinInternetGwHostRoutes adds LAN /32 routes for exit underlay IPs without
// changing 0.0.0.0/0. Safe to call when exit routing is already installed.
func pinInternetGwHostRoutes(publicKey string) {
	lan, ok := lanDefaultRouteV4(config.Netclient().CurrGwNmIP)
	if !ok {
		slog.Debug("skip exit-node host pin refresh; LAN gateway not found")
		return
	}
	pinHostIPsViaLanV4(IGWUnderlayPinIPs(publicKey), lan)
}

// lanDefaultRouteV4 returns the underlay IPv4 default route, ignoring any
// 0.0.0.0/0 row that belongs to the netmaker interface or points at the overlay
// nexthop. Needed because once exit routing is installed the netmaker row has
// the lowest metric and would otherwise be picked as the "LAN" gateway.
func lanDefaultRouteV4(overlayGw net.IP) (lanRouteV4, bool) {
	var best lanRouteV4
	var bestMetric = math.MaxInt32
	nmIdx := -1
	if iface, err := net.InterfaceByName(ncutils.GetInterfaceName()); err == nil {
		nmIdx = iface.Index
	}
	orig := config.Netclient().OriginalDefaultGatewayIp

	input, err := ncutils.RunCmd("netsh int ipv4 show route", false)
	if err != nil {
		return best, false
	}
	lines := strings.FieldsFunc(input, func(r rune) bool { return r == '\r' || r == '\n' })
	for _, l := range lines {
		if !strings.Contains(l, IPv4Network) {
			continue
		}
		fields := strings.Fields(l)
		if len(fields) < 5 {
			continue
		}
		gw := net.ParseIP(strings.TrimSpace(fields[len(fields)-1]))
		// On-link rows carry an interface name here, not a usable nexthop.
		if gw == nil || gw.To4() == nil {
			continue
		}
		idx := strings.TrimSpace(fields[len(fields)-2])
		if nmIdx >= 0 && idx == strconv.Itoa(nmIdx) {
			continue
		}
		if len(overlayGw) > 0 && gw.Equal(overlayGw) {
			continue
		}
		metric, convErr := strconv.Atoi(strings.TrimSpace(fields[2]))
		if convErr != nil {
			metric = math.MaxInt32 - 1
		}
		// The remembered original gateway always wins over metric ordering.
		if len(orig) > 0 && gw.Equal(orig) {
			return lanRouteV4{ifaceIdx: idx, gw: gw, metric: strings.TrimSpace(fields[2])}, true
		}
		if metric < bestMetric {
			bestMetric = metric
			best = lanRouteV4{ifaceIdx: idx, gw: gw, metric: strings.TrimSpace(fields[2])}
		}
	}
	return best, best.gw != nil
}

// RestoreInternetGw - restore the old default gateway and delte the route to the Internet Gw's ip address
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
	needV4 := curr != nil && len(curr) > 0 && curr.To4() != nil
	needV6 := (curr6 != nil && len(curr6) > 0) || (curr != nil && len(curr) > 0 && curr.To4() == nil)
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

// restoreInternetGwV6 - restore the old default gateway and delte the route to the Internet Gw's ip address
func restoreInternetGwV6() (err error) {

	delCmd := fmt.Sprintf("netsh int ipv6 delete route %s interface=%s store=active", IPv6Network, ncutils.GetInterfaceName())

	_, err = ncutils.RunCmd(delCmd, true)
	if err != nil {
		slog.Error("Failed to delete route, please delete it manually", "error", err.Error())
		return err
	}

	var destinations []string
	seen := map[string]struct{}{}
	for _, ip := range CollectUnderlayPinIPs() {
		if ip.To4() != nil {
			continue
		}
		d := ip.String() + "/128"
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		destinations = append(destinations, d)
	}

	//get current default gateway route
	gwRoute, err := getDefaultGateway("v6")
	if err != nil || len(gwRoute) == 0 {
		slog.Error("no default gateway found, please run command route -n to check in the route table", "error", errString(err))
	} else {
		//if default gateway metric is 0, then reset it to 50
		ipString := strings.TrimSpace(gwRoute[len(gwRoute)-1])
		metric := strings.TrimSpace(gwRoute[2])
		if metric == "50" {
			//set the original gateway metric to 50
			setGwCmd := fmt.Sprintf("netsh int ipv6 set route %s interface=%s nexthop=%s store=active metric=0", IPv6Network, strings.TrimSpace(gwRoute[len(gwRoute)-2]), ipString)

			_, err = ncutils.RunCmd(setGwCmd, true)
			if err != nil {
				slog.Error("Failed to set original gateway route metric", "error", err.Error())
				slog.Error("please change the metric to 0 manually to avoid issue", "error")
				slog.Error("netsh int ipv6 set route ::/0 interface=<Idx> nexthop=<ipv6 address> store=active metric=0", "error")
			}
		}
	}

	for _, destination := range destinations {
		delCmd := fmt.Sprintf("netsh int ipv6 delete route %s store=active", destination)
		out, delErr := ncutils.RunCmd(delCmd, false)
		if delErr != nil && !isNetshNotFound(delErr, out) {
			slog.Warn("Failed to delete exit-node host route", "destination", destination,
				"error", delErr, "out", strings.TrimSpace(out))
		}
	}

	config.Netclient().CurrGwNmIP6 = net.ParseIP("")
	if curr := config.Netclient().CurrGwNmIP; curr != nil && curr.To4() == nil {
		config.Netclient().CurrGwNmIP = net.ParseIP("")
	}
	return config.WriteNetclientConfig()
}

// restoreInternetGwV4 - restore the old default gateway and delte the route to the Internet Gw's ip address
func restoreInternetGwV4() (err error) {

	delCmd := fmt.Sprintf("netsh int ipv4 delete route %s interface=%s store=active", IPv4Network, ncutils.GetInterfaceName())

	out, err := ncutils.RunCmd(delCmd, false)
	if err != nil && !isNetshNotFound(err, out) {
		slog.Error("Failed to delete route, please delete it manually", "error", err.Error(), "out", strings.TrimSpace(out))
		return err
	}

	var destinations []string
	seen := map[string]struct{}{}
	for _, ip := range CollectUnderlayPinIPs() {
		if ip.To4() == nil {
			continue
		}
		d := ip.String() + "/32"
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		destinations = append(destinations, d)
	}

	// Restore the LAN default route to metric 0 (exit setup demoted it to 50).
	if lan, ok := lanDefaultRouteV4(config.Netclient().CurrGwNmIP); ok && lan.metric != "0" {
		setGwCmd := fmt.Sprintf("netsh int ipv4 set route %s interface=%s nexthop=%s store=active metric=0", IPv4Network, lan.ifaceIdx, lan.gw)
		if _, setErr := ncutils.RunCmd(setGwCmd, false); setErr != nil {
			slog.Error("Failed to restore original gateway route metric", "error", setErr.Error())
			slog.Error("please change the metric to 0 manually to avoid issue", "cmd", setGwCmd)
		}
	}

	// Delete pins without an interface filter: once 0.0.0.0/0 is on netmaker,
	// getDefaultGateway returns the netmaker row, so an interface-scoped delete
	// silently misses the pins and the next add fails with "already exists".
	for _, destination := range destinations {
		delCmd := fmt.Sprintf("netsh int ipv4 delete route %s store=active", destination)
		out, delErr := ncutils.RunCmd(delCmd, false)
		if delErr != nil && !isNetshNotFound(delErr, out) {
			slog.Warn("Failed to delete exit-node host route", "destination", destination,
				"error", delErr, "out", strings.TrimSpace(out))
		}
	}

	config.Netclient().CurrGwNmIP = net.ParseIP("")
	return config.WriteNetclientConfig()
}

// NCIface.Close - closes the managed WireGuard interface
func (nc *NCIface) Close() {
	// Tear down the iface that is actually running — not the *desired* mode.
	// prepareTCPUplinkWireGuard may flip needTCPUplinkBind before SIGHUP.
	if UserspaceWGActive() {
		_ = nc.closeUserspaceWg()
	} else {
		wgMutex.Lock()
		if nc.Iface != nil {
			if err := nc.Iface.Close(); err != nil {
				logger.Log(0, "error closing netclient interface -", err.Error())
			}
		}
		wgMutex.Unlock()
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
	if !UserspaceWGActive() || nc.MTU <= 0 {
		// TODO figure out how to change MTU of WireGuardNT adapter
		return nil
	}
	for _, family := range []string{"ipv4", "ipv6"} {
		cmd := fmt.Sprintf(`netsh interface %s set subinterface "%s" mtu=%d store=active`, family, nc.Name, nc.MTU)
		if _, err := ncutils.RunCmd(cmd, false); err != nil {
			slog.Warn("failed to set userspace iface MTU", "family", family, "error", err)
		}
	}
	return nil
}

// DeleteOldInterface - removes named interface
func DeleteOldInterface(iface string) {
	logger.Log(0, "deleting interface", iface)
	if _, err := ncutils.RunCmd("wireguard.exe /uninstalltunnelservice "+iface, true); err != nil {
		logger.Log(1, err.Error())
	}
}

func isEconnRefused(err error) bool {
	if err == nil {
		return false
	}
	var winerrno windows.Errno
	if errors.As(err, &winerrno) && errors.Is(winerrno, windows.WSAECONNREFUSED) {
		return true
	}
	// net.DialTimeout on Windows often wraps the errno so errors.As misses it.
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "connection refused") || strings.Contains(msg, "actively refused")
}

func isNetshElementNotFound(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "element not found") || strings.Contains(msg, "cannot find")
}

// isNetshNotFound reports whether netsh failed only because the route was absent.
// RunCmd often returns err="exit status 1" with the real text only in stdout/stderr.
func isNetshNotFound(err error, out string) bool {
	if isNetshElementNotFound(err) {
		return true
	}
	msg := strings.ToLower(out)
	return strings.Contains(msg, "element not found") || strings.Contains(msg, "cannot find the file")
}

// isNetshAlreadyExists reports whether an add failed only because the route was
// already present, which is equivalent to success for our purposes.
func isNetshAlreadyExists(out string) bool {
	return strings.Contains(strings.ToLower(out), "already exists")
}

// errString renders an error for logging without panicking on nil.
func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// resolvingMetricTTL bounds how long a probed metric is reused. The probe spawns
// a PowerShell process per DNS server and resolves through each one, which costs
// tens of seconds on some hosts — far too long to repeat for every iface rebuild.
const resolvingMetricTTL = 5 * time.Minute

var resolvingMetric struct {
	sync.Mutex
	value uint32
	at    time.Time
}

func cachedResolvingInterfaceMetric() (uint32, error) {
	resolvingMetric.Lock()
	defer resolvingMetric.Unlock()
	if resolvingMetric.value != 0 && time.Since(resolvingMetric.at) < resolvingMetricTTL {
		return resolvingMetric.value, nil
	}
	metric, err := getResolvingInterfaceMetric()
	if err != nil {
		return 0, err
	}
	resolvingMetric.value = metric
	resolvingMetric.at = time.Now()
	return metric, nil
}

func getResolvingInterfaceMetric() (uint32, error) {
	testDomain := "netmaker.io"

	output, err := runPSCommand("Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object InterfaceIndex, ServerAddresses | ConvertTo-Json")
	if err != nil {
		return 0, err
	}

	type dnsEntry struct {
		InterfaceIndex  int      `json:"InterfaceIndex"`
		ServerAddresses []string `json:"ServerAddresses"`
	}

	var entries []dnsEntry
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &entries); err != nil {
		return 0, err
	}

	var lowest uint32 = math.MaxUint32
	for _, entry := range entries {
		for _, dnsServer := range entry.ServerAddresses {
			resolveOut, err := runPSCommand(fmt.Sprintf(
				"Resolve-DnsName '%s' -Server '%s' -Type A -ErrorAction SilentlyContinue",
				testDomain, dnsServer))
			if err == nil && strings.Contains(resolveOut, testDomain) {
				metricOut, err := runPSCommand(fmt.Sprintf(
					"(Get-NetIPInterface -InterfaceIndex %d -AddressFamily IPv4).InterfaceMetric",
					entry.InterfaceIndex))
				if err != nil {
					return 0, err
				}

				metric, err := strconv.ParseUint(strings.TrimSpace(metricOut), 10, 32)
				if err != nil {
					return 0, err
				}

				if lowest > uint32(metric) {
					lowest = uint32(metric)
				}
			}
		}
	}

	if lowest == math.MaxUint32 {
		return 0, fmt.Errorf("no interface found that could resolve %s", testDomain)
	}

	return lowest, nil
}

func runPSCommand(command string) (string, error) {
	cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command)
	out, err := cmd.Output()
	return string(out), err
}
