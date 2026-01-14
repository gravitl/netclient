package wireguard

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"golang.org/x/exp/slog"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.zx2c4.com/wireguard/windows/driver"
)

// TODO: update from netsh to a more programmatic approach.

// NCIface.Create - makes a new Wireguard interface and sets given addresses
func (nc *NCIface) Create() error {
	wgMutex.Lock()
	defer wgMutex.Unlock()

	adapter, err := driver.OpenAdapter(ncutils.GetInterfaceName())
	if err != nil {
		slog.Info("creating Windows tunnel")
		idString := config.Netclient().Host.ID.String()
		if idString == "" {
			idString = config.DefaultHostID
		}
		windowsGUID, err := windows.GUIDFromString("{" + idString + "}")
		if err != nil {
			slog.Error("generating guid error: ", "error", err)
			return err
		}
		adapter, err = driver.CreateAdapter(ncutils.GetInterfaceName(), "WireGuard", &windowsGUID)
		if err != nil {
			slog.Error("creating adapter error: ", "error", err)
			return err
		}
	} else {
		slog.Info("re-using existing adapter")
	}

	slog.Info("created Windows tunnel")
	nc.Iface = adapter

	// Configure DNS and interface settings BEFORE bringing adapter up
	// This ensures NLA sees DNS configuration immediately when evaluating the interface
	if err := configureInterfaceForNLA(ncutils.GetInterfaceName()); err != nil {
		slog.Warn("failed to configure interface for NLA, continuing anyway", "error", err)
	}

	// Bring adapter up
	if err := adapter.SetAdapterState(driver.AdapterStateUp); err != nil {
		return err
	}

	// Configure DNS immediately after adapter comes up (before NLA evaluates)
	// This is critical - DNS must be available when NLA runs
	if err := configureInterfaceForNLA(ncutils.GetInterfaceName()); err != nil {
		slog.Warn("failed to configure interface for NLA after adapter up", "error", err)
	}

	// Trigger domain authentication traffic immediately after interface comes up
	// This helps NLA classify the interface as Intranet
	go func() {
		// Small delay to ensure interface is fully up
		time.Sleep(500 * time.Millisecond)
		triggerDomainAuthTraffic()

		// After triggering traffic, try to force set network profile
		time.Sleep(2 * time.Second)
		forceSetNetworkProfile(ncutils.GetInterfaceName())
	}()

	return nil
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

// RemoveRoutes - remove routes to the interface
func RemoveRoutes(addrs []ifaceAddress) {
	for _, addr := range addrs {
		if (len(config.GetNodes()) > 1 && addr.IP == nil) || addr.Network.IP == nil || addr.Network.String() == IPv4Network ||
			addr.Network.String() == IPv6Network || (len(config.GetNodes()) > 1 && addr.GwIP == nil) {
			continue
		}
		if addr.Network.IP.To4() != nil {
			slog.Info("removing ipv4 route to interface", "route", fmt.Sprintf("%s -> %s ->%s", addr.IP.String(), addr.Network.String(), addr.GwIP.String()))
			cmd := fmt.Sprintf("netsh int ipv4 delete route %s interface=%s nexthop=%s store=%s metric=%d",
				addr.Network.String(), ncutils.GetInterfaceName(), addr.GwIP.String(), "active", addr.Metric)
			_, err := ncutils.RunCmd(cmd, false)
			if err != nil {
				slog.Error("failed to apply", "ipv4 egress range", addr.Network.String(), err.Error())
			}
		} else {
			slog.Info("removing ipv6 route to interface", "route", fmt.Sprintf("%s -> %s ->%s", addr.IP.String(), addr.Network.String(), addr.GwIP.String()))
			cmd := fmt.Sprintf("netsh int ipv6 delete route %s interface=%s nexthop=%s store=%s metric=%d",
				addr.Network.String(), ncutils.GetInterfaceName(), addr.GwIP.String(), "active", addr.Metric)
			_, err := ncutils.RunCmd(cmd, false)
			if err != nil {
				slog.Error("failed to apply", "ipv6 egress range", addr.Network.String(), err.Error())
			}
		}
	}
}

// SetRoutes - sets additional routes to the interface
func SetRoutes(addrs []ifaceAddress) error {
	for _, addr := range addrs {
		if (len(config.GetNodes()) > 1 && addr.IP == nil) || addr.Network.IP == nil || addr.Network.String() == IPv4Network ||
			addr.Network.String() == IPv6Network || (len(config.GetNodes()) > 1 && addr.GwIP == nil) {
			continue
		}
		if addr.Network.IP.To4() != nil {
			slog.Info("adding ipv4 route to interface", "route", fmt.Sprintf("%s -> %s ->%s", addr.IP.String(), addr.Network.String(), addr.GwIP.String()))
			cmd := fmt.Sprintf("netsh int ipv4 add route %s interface=%s nexthop=%s store=%s metric=%d",
				addr.Network.String(), ncutils.GetInterfaceName(), addr.GwIP.String(), "active", addr.Metric)
			out, err := ncutils.RunCmd(cmd, false)
			if err != nil && !strings.Contains(out, "already exists") {
				slog.Error("failed to apply", "ipv4 egress range", addr.Network.String(), err.Error())
			}
		} else {
			slog.Info("adding ipv6 route to interface", "route", fmt.Sprintf("%s -> %s ->%s", addr.IP.String(), addr.Network.String(), addr.GwIP.String()))
			cmd := fmt.Sprintf("netsh int ipv6 add route %s interface=%s nexthop=%s store=%s metric=%d",
				addr.Network.String(), ncutils.GetInterfaceName(), addr.GwIP.String(), "active", addr.Metric)
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

// getDefaultGateway - an internal function to get the default gateway route entry
func getDefaultGateway() (output []string, err error) {

	//get current ipv4 route
	input, err := ncutils.RunCmd("netsh int ipv4 show route", true)
	if err != nil {
		return []string{}, err
	}

	//split the output to multiple lines
	var rList []string
	if strings.Contains(input, "\r") {
		rList = strings.Split(input, "\r")
	} else if strings.Contains(input, "\n") {
		rList = strings.Split(input, "\n")
	}

	//get the lines with gateway route
	rLines := []string{}
	for _, l := range rList {
		if strings.Contains(l, IPv4Network) {
			rLines = append(rLines, l)
		}
	}

	if len(rLines) == 0 {
		//get current ipv6 route
		input, err := ncutils.RunCmd("netsh int ipv6 show route", true)
		if err != nil {
			return []string{}, err
		}

		//split the output to multiple lines
		var rList []string
		if strings.Contains(input, "\r") {
			rList = strings.Split(input, "\r")
		} else if strings.Contains(input, "\n") {
			rList = strings.Split(input, "\n")
		}

		//get the lines with gateway route
		for _, l := range rList {
			if strings.Contains(l, IPv6Network) {
				rLines = append(rLines, l)
			}
		}
	}

	//in case that multiple default gateway in the route table, return the one with higher priority
	if len(rLines) == 0 {
		output = []string{}
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
	gwRoute, err := getDefaultGateway()
	if err != nil || len(gwRoute) == 0 {
		return ip, errors.New("no default gateway found, please run command route -n to check in the route table")
	}

	//get the ip address from the last column
	ipString := strings.TrimSpace(gwRoute[len(gwRoute)-1])
	ip = net.ParseIP(ipString)

	return ip, nil
}

// SetInternetGw - set a new default gateway and the route to Internet Gw's ip address
func SetInternetGw(publicKey string, networkIP net.IP) (err error) {
	err = setDefaultRoutesOnHost(publicKey, networkIP)
	if err == nil {
		GetIGWMonitor().Monitor(publicKey, networkIP)
	}

	return err
}

func setDefaultRoutesOnHost(publicKey string, networkIP net.IP) error {
	if ipv4 := networkIP.To4(); ipv4 != nil {
		return setInternetGwV4(publicKey, networkIP)
	} else {
		return setInternetGwV6(publicKey, networkIP)
	}
}

// setInternetGwV6 - set a new default gateway and the route to Internet Gw's ip address
func setInternetGwV6(publicKey string, networkIP net.IP) (err error) {

	//get current default gateway route
	gwRoute, err := getDefaultGateway()
	if err != nil || len(gwRoute) == 0 {
		slog.Error("no default gateway found, please run command route -n to check in the route table", "error", err.Error())
	} else {
		//if default gateway metric is 0, then reset it to 50
		ipString := strings.TrimSpace(gwRoute[len(gwRoute)-1])
		metric := strings.TrimSpace(gwRoute[2])
		if metric == "0" && ipString != networkIP.String() {
			//set the original gateway metric to 50
			setGwCmd := fmt.Sprintf("netsh int ipv6 set route %s interface=%s nexthop=%s store=active metric=50", IPv6Network, strings.TrimSpace(gwRoute[len(gwRoute)-2]), ipString)

			_, err = ncutils.RunCmd(setGwCmd, true)
			if err != nil {
				slog.Error("Failed to set original gateway route metric", "error", err.Error())
				slog.Error("please change the metric to 50 manaull to avoid issue", "error")
				slog.Error("netsh int ipv6 set route ::/0 interface=<Idx> nexthop=<ipv6 address> store=active metric=50", "error")
			}
		}

		igw, err := GetPeer(ncutils.GetInterfaceName(), publicKey)
		if err == nil {
			destination := igw.Endpoint.IP.String() + "/128"
			gwRouteCmd := fmt.Sprintf("netsh int ipv6 add route %s interface=%s nexthop=%s store=active metric=1", destination, strings.TrimSpace(gwRoute[len(gwRoute)-2]), ipString)
			_, err = ncutils.RunCmd(gwRouteCmd, true)
			if err != nil {
				slog.Error("Failed to add route to gateway", "error", err.Error())
			}
		}
	}

	//add new gateway route with metric 0 for setting to top priority
	addGwCmd := fmt.Sprintf("netsh int ipv6 add route %s interface=%s nexthop=%s store=active metric=0", IPv6Network, ncutils.GetInterfaceName(), networkIP.String())

	_, err = ncutils.RunCmd(addGwCmd, true)
	if err != nil {
		slog.Error("Failed to add route table", "error", err.Error())
		return err
	}

	config.Netclient().CurrGwNmIP = networkIP
	return nil
}

// setInternetGwV4 - set a new default gateway and the route to Internet Gw's ip address
func setInternetGwV4(publicKey string, networkIP net.IP) (err error) {

	//get current default gateway route
	gwRoute, err := getDefaultGateway()
	if err != nil || len(gwRoute) == 0 {
		slog.Error("no default gateway found, please run command route -n to check in the route table", "error", err.Error())
	} else {
		//if default gateway metric is 0, then reset it to 50
		ipString := strings.TrimSpace(gwRoute[len(gwRoute)-1])
		metric := strings.TrimSpace(gwRoute[2])
		if metric == "0" && ipString != networkIP.String() {
			//set the original gateway metric to 50
			setGwCmd := fmt.Sprintf("netsh int ipv4 set route %s interface=%s nexthop=%s store=active metric=50", IPv4Network, strings.TrimSpace(gwRoute[len(gwRoute)-2]), ipString)

			_, err = ncutils.RunCmd(setGwCmd, true)
			if err != nil {
				slog.Error("Failed to set original gateway route metric", "error", err.Error())
				slog.Error("please change the metric to 50 manaull to avoid issue", "error")
				slog.Error("netsh int ipv4 set route 0.0.0.0/0 interface=<Idx> nexthop=<192.168.1.1> store=active metric=50", "error")
			}
		}

		igw, err := GetPeer(ncutils.GetInterfaceName(), publicKey)
		if err == nil {
			destination := igw.Endpoint.IP.String() + "/32"
			gwRouteCmd := fmt.Sprintf("netsh int ipv4 add route %s interface=%s nexthop=%s store=active metric=1", destination, strings.TrimSpace(gwRoute[len(gwRoute)-2]), ipString)
			slog.Info(gwRouteCmd)
			_, err = ncutils.RunCmd(gwRouteCmd, true)
			if err != nil {
				slog.Error("Failed to add route to gateway", "error", err.Error())
			}
		}
	}

	//add new gateway route with metric 0 for setting to top priority
	addGwCmd := fmt.Sprintf("netsh int ipv4 add route %s interface=%s nexthop=%s store=active metric=0", IPv4Network, ncutils.GetInterfaceName(), networkIP.String())

	_, err = ncutils.RunCmd(addGwCmd, true)
	if err != nil {
		slog.Error("Failed to add route table", "error", err.Error())
		return err
	}

	config.Netclient().CurrGwNmIP = networkIP

	return nil
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
	if ipv4 := config.Netclient().OriginalDefaultGatewayIp.To4(); ipv4 != nil {
		return restoreInternetGwV4()
	} else {
		return restoreInternetGwV6()
	}
}

// restoreInternetGwV6 - restore the old default gateway and delte the route to the Internet Gw's ip address
func restoreInternetGwV6() (err error) {

	delCmd := fmt.Sprintf("netsh int ipv6 delete route %s interface=%s store=active", IPv6Network, ncutils.GetInterfaceName())

	_, err = ncutils.RunCmd(delCmd, true)
	if err != nil {
		slog.Error("Failed to delete route, please delete it manually", "error", err.Error())
		return err
	}

	var destination string
	for _, peer := range config.Netclient().HostPeers {
		for _, allowedIP := range peer.AllowedIPs {
			if allowedIP.String() == IPv6Network {
				destination = peer.Endpoint.IP.String() + "/128"
			}
		}
	}

	//get current default gateway route
	gwRoute, err := getDefaultGateway()
	if err != nil || len(gwRoute) == 0 {
		slog.Error("no default gateway found, please run command route -n to check in the route table", "error", err.Error())
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

		if destination != "" {
			delCmd := fmt.Sprintf("netsh int ipv6 delete route %s %s store=active", destination, strings.TrimSpace(gwRoute[len(gwRoute)-2]))
			_, err = ncutils.RunCmd(delCmd, true)
			if err != nil {
				slog.Error("Failed to delete route, please delete it manually", "error", err.Error())
				return err
			}
		}
	}

	config.Netclient().CurrGwNmIP = net.ParseIP("")
	return config.WriteNetclientConfig()
}

// restoreInternetGwV4 - restore the old default gateway and delte the route to the Internet Gw's ip address
func restoreInternetGwV4() (err error) {

	delCmd := fmt.Sprintf("netsh int ipv4 delete route %s interface=%s store=active", IPv4Network, ncutils.GetInterfaceName())

	_, err = ncutils.RunCmd(delCmd, true)
	if err != nil {
		slog.Error("Failed to delete route, please delete it manually", "error", err.Error())
		return err
	}

	var destination string
	for _, peer := range config.Netclient().HostPeers {
		for _, allowedIP := range peer.AllowedIPs {
			if allowedIP.String() == IPv4Network {
				destination = peer.Endpoint.IP.String() + "/32"
			}
		}
	}

	//get current default gateway route
	gwRoute, err := getDefaultGateway()
	if err != nil || len(gwRoute) == 0 {
		slog.Error("no default gateway found, please run command route -n to check in the route table", "error", err.Error())
	} else {
		//if default gateway metric is 0, then reset it to 50
		ipString := strings.TrimSpace(gwRoute[len(gwRoute)-1])
		metric := strings.TrimSpace(gwRoute[2])
		if metric == "50" {
			//set the original gateway metric to 50
			setGwCmd := fmt.Sprintf("netsh int ipv4 set route %s interface=%s nexthop=%s store=active metric=0", IPv4Network, strings.TrimSpace(gwRoute[len(gwRoute)-2]), ipString)

			_, err = ncutils.RunCmd(setGwCmd, true)
			if err != nil {
				slog.Error("Failed to set original gateway route metric", "error", err.Error())
				slog.Error("please change the metric to 0 manually to avoid issue", "error")
				slog.Error("netsh int ipv4 set route 0.0.0.0/0 interface=<Idx> nexthop=<192.168.1.1> store=active metric=0", "error")
			}
		}

		if destination != "" {
			delCmd := fmt.Sprintf("netsh int ipv4 delete route %s %s store=active", destination, strings.TrimSpace(gwRoute[len(gwRoute)-2]))
			_, err = ncutils.RunCmd(delCmd, true)
			if err != nil {
				slog.Error("Failed to delete route, please delete it manually", "error", err.Error())
				return err
			}
		}
	}

	config.Netclient().CurrGwNmIP = net.ParseIP("")
	return config.WriteNetclientConfig()
}

// NCIface.Close - closes the managed WireGuard interface
func (nc *NCIface) Close() {
	wgMutex.Lock()
	defer wgMutex.Unlock()
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

func isEconnRefused(err error) bool {
	var winerrno windows.Errno
	return errors.As(err, &winerrno) && errors.Is(winerrno, windows.WSAECONNREFUSED)
}

// configureInterfaceForNLA configures the interface to help Windows NLA classify it as Intranet
// This should be called BEFORE setting adapter state to UP, or immediately after
func configureInterfaceForNLA(ifaceName string) error {
	// Set low interface metric to make Windows prefer this interface for NLA checks
	// Lower metric = higher priority
	if err := setInterfaceMetric(ifaceName, 1); err != nil {
		slog.Warn("failed to set interface metric", "error", err)
	}

	// Configure DNS directly on the interface using netsh
	// This ensures DNS is available immediately when NLA evaluates the interface
	dnsIP, err := getDNSIPForInterface()
	if err != nil {
		slog.Debug("no DNS IP available yet for interface configuration", "error", err)
		return nil // Not a fatal error, DNS will be configured later
	}

	// Set DNS servers directly on the interface
	if err := setInterfaceDNS(ifaceName, dnsIP); err != nil {
		slog.Warn("failed to set interface DNS", "error", err)
	}

	// Set DNS suffix if available
	server := config.GetServer(config.CurrServer)
	if server != nil && server.DefaultDomain != "" {
		domain := strings.TrimSuffix(strings.TrimPrefix(server.DefaultDomain, "."), ".")
		if err := setInterfaceDNSSuffix(ifaceName, domain); err != nil {
			slog.Warn("failed to set interface DNS suffix", "error", err)
		}
	}

	return nil
}

// setInterfaceMetric sets a low metric on the interface to make Windows prefer it
func setInterfaceMetric(ifaceName string, metric int) error {
	// Set IPv4 interface metric
	cmd := fmt.Sprintf("netsh interface ipv4 set interface \"%s\" metric=%d", ifaceName, metric)
	_, err := ncutils.RunCmd(cmd, true)
	if err != nil {
		return fmt.Errorf("failed to set IPv4 metric: %w", err)
	}

	// Set IPv6 interface metric
	cmd = fmt.Sprintf("netsh interface ipv6 set interface \"%s\" metric=%d", ifaceName, metric)
	_, err = ncutils.RunCmd(cmd, true)
	if err != nil {
		return fmt.Errorf("failed to set IPv6 metric: %w", err)
	}

	slog.Info("set interface metric for NLA", "interface", ifaceName, "metric", metric)
	return nil
}

// setInterfaceDNS sets DNS servers directly on the interface using netsh
func setInterfaceDNS(ifaceName, dnsIP string) error {
	// Set IPv4 DNS server
	cmd := fmt.Sprintf("netsh interface ipv4 set dns \"%s\" static %s", ifaceName, dnsIP)
	_, err := ncutils.RunCmd(cmd, true)
	if err != nil {
		return fmt.Errorf("failed to set IPv4 DNS: %w", err)
	}

	// Try IPv6 DNS if the IP is IPv6
	if strings.Contains(dnsIP, ":") {
		cmd = fmt.Sprintf("netsh interface ipv6 set dns \"%s\" static %s", ifaceName, dnsIP)
		_, err = ncutils.RunCmd(cmd, true)
		if err != nil {
			slog.Debug("failed to set IPv6 DNS (may not be IPv6)", "error", err)
		}
	}

	slog.Info("set interface DNS for NLA", "interface", ifaceName, "dns", dnsIP)
	return nil
}

// setInterfaceDNSSuffix sets DNS suffix on the interface
func setInterfaceDNSSuffix(ifaceName, suffix string) error {
	// Set DNS suffix via registry for the interface
	guid := config.Netclient().Host.ID.String()
	if guid == "" {
		guid = config.DefaultHostID
	}

	// Set on IPv4 interface registry key
	ipv4KeyPath := fmt.Sprintf(`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{%s}`, guid)
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, ipv4KeyPath, registry.ALL_ACCESS)
	if err == nil {
		defer key.Close()
		err = key.SetStringValue("Domain", suffix)
		if err == nil {
			err = key.SetStringValue("DhcpDomain", "")
		}
	}

	if err != nil {
		slog.Debug("failed to set DNS suffix via registry", "error", err)
	}

	slog.Info("set interface DNS suffix for NLA", "interface", ifaceName, "suffix", suffix)
	return nil
}

// getDNSIPForInterface gets the DNS IP that should be configured on the interface
func getDNSIPForInterface() (string, error) {
	// Try to get DNS from the DNS server instance
	// This may not be available yet if called very early, so we handle that gracefully
	dnsIP := ""

	// Try to get from config - this might be available even if DNS server isn't running yet
	server := config.GetServer(config.CurrServer)
	if server != nil && len(server.DnsNameservers) > 0 {
		for _, ns := range server.DnsNameservers {
			if !ns.IsFallback && len(ns.IPs) > 0 {
				// Use the first IP from the nameserver (IPs is a slice of strings)
				dnsIP = ns.IPs[0]
				break
			}
		}
	}

	if dnsIP == "" {
		return "", errors.New("no DNS IP available")
	}

	return dnsIP, nil
}

// triggerDomainAuthTraffic triggers domain authentication traffic to help NLA classify interface as Intranet
// This should be called immediately after the interface comes up, during the NLA evaluation window
func triggerDomainAuthTraffic() {
	ifaceName := ncutils.GetInterfaceName()

	// Get the computer's domain/workgroup name
	domainName, err := getComputerDomain()
	if err != nil || domainName == "" {
		slog.Debug("not domain-joined or domain name unavailable, skipping domain auth traffic", "error", err)
		return
	}

	slog.Info("triggering domain authentication traffic for NLA", "interface", ifaceName, "domain", domainName)

	// Try to resolve domain controller name - this triggers DNS lookup
	dcName := fmt.Sprintf("_ldap._tcp.dc._msdcs.%s", domainName)
	_, err = ncutils.RunCmd(fmt.Sprintf("nslookup %s", dcName), false)
	if err != nil {
		slog.Debug("domain controller lookup failed (expected on non-domain-joined)", "error", err)
	}

	// Try SMB connection to domain controller (if available)
	// This generates authentication traffic that NLA can observe
	go func() {
		// Use net use command to trigger SMB authentication
		// This will fail gracefully if not domain-joined, but generates traffic
		_, _ = ncutils.RunCmd(fmt.Sprintf("net use \\\\%s\\IPC$ /user:guest", domainName), false)
	}()

	// Try LDAP lookup - generates LDAP/Kerberos traffic
	go func() {
		_, _ = ncutils.RunCmd(fmt.Sprintf("nltest /dclist:%s", domainName), false)
	}()

	// Flush DNS cache to force fresh lookups on the new interface
	_, _ = ncutils.RunCmd("ipconfig /flushdns", false)
}

// getComputerDomain gets the computer's domain or workgroup name
func getComputerDomain() (string, error) {
	// Try to get domain/workgroup name
	output, err := ncutils.RunCmd("net config workstation", true)
	if err != nil {
		return "", err
	}

	// Parse output to find domain name
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "domain") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				domain := strings.TrimSpace(parts[1])
				if domain != "" && domain != "WORKGROUP" {
					return domain, nil
				}
			}
		}
	}

	return "", errors.New("domain not found")
}

// forceSetNetworkProfile attempts to force set the network profile to DomainAuthenticated
// This uses PowerShell to directly set the NetworkCategory
func forceSetNetworkProfile(ifaceName string) {
	// Method 1: Try to set via PowerShell Set-NetConnectionProfile
	// This requires admin privileges but can force the profile
	psCmd := fmt.Sprintf("powershell -Command \"$profile = Get-NetConnectionProfile -InterfaceAlias '%s' -ErrorAction SilentlyContinue; if ($profile) { Set-NetConnectionProfile -InterfaceAlias '%s' -NetworkCategory DomainAuthenticated -ErrorAction SilentlyContinue }\"", ifaceName, ifaceName)
	output, err := ncutils.RunCmd(psCmd, true)
	if err == nil {
		slog.Info("attempted to force set network profile to DomainAuthenticated", "interface", ifaceName, "output", strings.TrimSpace(output))
	} else {
		slog.Debug("failed to force set network profile via PowerShell", "interface", ifaceName, "error", err)
	}

	// Method 2: Set DomainAuthenticationKind in registry
	// This tells Windows the interface can authenticate to domain
	guid := config.Netclient().Host.ID.String()
	if guid == "" {
		guid = config.DefaultHostID
	}

	ipv4KeyPath := fmt.Sprintf(`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{%s}`, guid)
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, ipv4KeyPath, registry.ALL_ACCESS)
	if err == nil {
		defer key.Close()
		// Set DomainAuthenticationKind to 1 (DomainAuthenticated)
		// 0 = None, 1 = DomainAuthenticated
		err = key.SetDWordValue("DomainAuthenticationKind", 1)
		if err == nil {
			slog.Info("set DomainAuthenticationKind in registry", "interface", ifaceName)
		} else {
			slog.Debug("failed to set DomainAuthenticationKind", "error", err)
		}
	}

	// Method 3: Trigger NLA re-evaluation by toggling interface
	// This is more aggressive but can help
	go func() {
		time.Sleep(1 * time.Second)
		// Disable and re-enable the interface to force NLA re-evaluation
		// This is done in a goroutine to avoid blocking
		cmd := fmt.Sprintf("netsh interface set interface \"%s\" admin=disable", ifaceName)
		_, _ = ncutils.RunCmd(cmd, true)
		time.Sleep(500 * time.Millisecond)
		cmd = fmt.Sprintf("netsh interface set interface \"%s\" admin=enable", ifaceName)
		_, _ = ncutils.RunCmd(cmd, true)
		slog.Info("triggered interface toggle to force NLA re-evaluation", "interface", ifaceName)
	}()
}
