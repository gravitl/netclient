package wireguard

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
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
	idString := config.Netclient().Host.ID.String()
	if idString == "" {
		idString = config.DefaultHostID
	}

	if err != nil {
		slog.Info("creating Windows tunnel")
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

	// Mark interface as corporate/domain-connected for Intranet classification
	// This enables RDP Gateway bypass for destinations over VPN
	if err := markInterfaceAsCorporate(idString); err != nil {
		slog.Warn("failed to mark interface as corporate (RDP Gateway bypass may not work)", "error", err)
	}

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

// markInterfaceAsCorporate marks the WireGuard interface as corporate/domain-connected
// This enables Windows to classify destinations over VPN as "Intranet", which allows
// RDP client to bypass RD Gateway and connect directly over VPN (like Pritunl does)
// This function may need to be called multiple times as the registry key might not
// exist immediately after interface creation
func markInterfaceAsCorporate(interfaceGUID string) error {
	// Network adapter registry path
	// {4D36E972-E325-11CE-BFC1-08002BE10318} is the GUID for network adapters
	adapterPath := fmt.Sprintf(`SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{%s}\Connection`, strings.ToUpper(interfaceGUID))

	key, err := registry.OpenKey(registry.LOCAL_MACHINE, adapterPath, registry.ALL_ACCESS)
	if err != nil {
		// If the key doesn't exist yet, the interface might not be fully registered
		// This is expected immediately after creation - caller should retry
		return fmt.Errorf("interface registry key not found (interface may not be fully registered yet): %w", err)
	}
	defer key.Close()

	// Set Type = 6 (Corporate/Enterprise network)
	// This tells Windows NLA (Network Location Awareness) to treat this as corporate/intranet
	// Type values: 0=Public, 1=Private, 6=Domain/Corporate
	// NOTE: NetworkCategory can show "Public" but Type=6 enables Intranet classification for RDP Gateway bypass
	// This is what Pritunl does - it works even with NetworkCategory: Public because Type=6 is set
	err = key.SetDWordValue("Type", 6)
	if err != nil {
		return fmt.Errorf("failed to set Type: %w", err)
	}

	// Set MediaSubType = 2 (Domain authenticated network)
	// This further reinforces corporate/domain classification
	err = key.SetDWordValue("MediaSubType", 2)
	if err != nil {
		// MediaSubType might not exist on all Windows versions, that's okay
		slog.Debug("MediaSubType not set (may not be supported)", "error", err)
	}

	// Set DomainType = 1 (Domain network)
	// This explicitly marks it as domain-connected for NLA
	err = key.SetDWordValue("DomainType", 1)
	if err != nil {
		// DomainType might not exist on all Windows versions, that's okay
		slog.Debug("DomainType not set (may not be supported)", "error", err)
	}

	// Verify the registry values were set correctly
	typeVal, _, _ := key.GetIntegerValue("Type")
	if typeVal == 6 {
		slog.Info("registry Type=6 set successfully (enables Intranet classification for RDP Gateway bypass)")
	} else {
		slog.Warn("registry Type verification failed", "expected", 6, "actual", typeVal)
	}

	// Set NetworkCategory to Private - Netmaker requires Private for RDP Gateway bypass to work
	// (Pritunl works with Public, but Netmaker needs Private + registry Type=6)
	interfaceName := ncutils.GetInterfaceName()
	if interfaceName != "" {
		// Set network profile to Private - this is required for Netmaker RDP Gateway bypass
		// Registry Type=6 + NetworkCategory Private enables Intranet classification
		// Use -Name parameter (this is what works: Set-NetConnectionProfile -Name netmaker -NetworkCategory Private)
		psCmd := fmt.Sprintf(`powershell -Command "$ErrorActionPreference = 'Stop'; try { $profile = Get-NetConnectionProfile -Name '%s' -ErrorAction SilentlyContinue; if (-not $profile) { $profile = Get-NetConnectionProfile -InterfaceAlias '%s' -ErrorAction SilentlyContinue } if ($profile) { if ($profile.NetworkCategory -ne 'Private') { Set-NetConnectionProfile -Name '%s' -NetworkCategory Private -ErrorAction Stop; Start-Sleep -Milliseconds 300; $updated = Get-NetConnectionProfile -Name '%s' -ErrorAction SilentlyContinue; if ($updated.NetworkCategory -eq 'Private') { Write-Host ('Success: NetworkCategory set to Private') } else { Write-Host ('Warning: NetworkCategory is ' + $updated.NetworkCategory) } } else { Write-Host ('NetworkCategory already Private') } } else { Write-Host ('Profile not found for ' + '%s') } } catch { Write-Host ('Error: ' + $_.Exception.Message); exit 1 }"`, interfaceName, interfaceName, interfaceName, interfaceName, interfaceName)
		out, err := ncutils.RunCmd(psCmd, false)
		if err != nil {
			slog.Warn("failed to set NetworkCategory to Private (RDP Gateway bypass may not work)", "error", err, "output", out)
		} else {
			outputStr := strings.TrimSpace(out)
			if strings.Contains(outputStr, "Success") || strings.Contains(outputStr, "already Private") {
				slog.Info("NetworkCategory set to Private (required for Netmaker RDP Gateway bypass)", "output", outputStr)
			} else {
				slog.Info("NetworkCategory setting attempted", "output", outputStr)
			}
		}

		// Restart NLA service to force Windows to re-evaluate network classification
		// This helps Windows pick up the registry changes (Type=6, DomainType=1)
		// NetworkCategory Private + registry Type=6 enables Intranet classification for Netmaker
		nlaRestartCmd := `powershell -Command "try { Restart-Service -Name NlaSvc -ErrorAction Stop; Write-Host 'NLA service restarted' } catch { Write-Host ('NLA restart: ' + $_.Exception.Message) }"`
		nlaOut, nlaErr := ncutils.RunCmd(nlaRestartCmd, false)
		if nlaErr != nil {
			slog.Debug("NLA service restart attempted (may require admin privileges)", "output", nlaOut)
		} else {
			slog.Info("restarted NLA service to refresh network classification")
		}

		// Trigger network change notification
		refreshCmd := `powershell -Command "[System.Net.NetworkInformation.NetworkChange]::NetworkAddressChanged; Start-Sleep -Milliseconds 500"`
		_, _ = ncutils.RunCmd(refreshCmd, false)
	}

	slog.Info("marked WireGuard interface as corporate/domain-connected for Intranet classification (RDP Gateway bypass enabled)")
	return nil
}

// MarkInterfaceAsCorporateWithRetry attempts to mark the interface as corporate with retries
// This is needed because the registry key may not exist immediately after interface creation
func MarkInterfaceAsCorporateWithRetry() {
	if runtime.GOOS != "windows" {
		return
	}

	idString := config.Netclient().Host.ID.String()
	if idString == "" {
		idString = config.DefaultHostID
	}

	// Retry up to 5 times with increasing delays
	for i := 0; i < 5; i++ {
		if i > 0 {
			// Exponential backoff: 1s, 2s, 4s, 8s
			delay := time.Duration(1<<(i-1)) * time.Second
			slog.Debug("retrying interface corporate marking", "attempt", i+1, "delay", delay)
			time.Sleep(delay)
		}

		err := markInterfaceAsCorporate(idString)
		if err == nil {
			return // Success
		}

		if i < 4 {
			slog.Debug("interface corporate marking failed, will retry", "attempt", i+1, "error", err)
		} else {
			slog.Warn("failed to mark interface as corporate after retries (RDP Gateway bypass may not work)", "error", err)
		}
	}
}
