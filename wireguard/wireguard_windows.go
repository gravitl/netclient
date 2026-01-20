package wireguard

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
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

// SetInterfaceProfileName - sets the Windows network profile name for the interface
func SetInterfaceProfileName(ifaceName string, profileName string) error {
	if profileName == "" {
		return nil
	}

	// Wait a bit for Windows to create the network profile after interface creation
	// Retry up to 10 times with 1 second delay
	maxRetries := 10
	for i := 0; i < maxRetries; i++ {
		if i > 0 {
			time.Sleep(1 * time.Second)
		}

		// Try registry method first (more reliable than PowerShell for profile name)
		err := setInterfaceProfileNameViaRegistry(ifaceName, profileName)
		if err == nil {
			slog.Info("set interface profile name via registry", "interface", ifaceName, "profileName", profileName)
			return nil
		}

		// Fallback to PowerShell if registry fails
		// Escape single quotes in profile name for PowerShell
		escapedProfileName := strings.ReplaceAll(profileName, "'", "''")
		// Use pipeline syntax which is more reliable
		psCmd := fmt.Sprintf("$profile = Get-NetConnectionProfile -InterfaceAlias '%s' -ErrorAction SilentlyContinue; if ($profile) { $profile | Set-NetConnectionProfile -Name '%s' -ErrorAction Stop; Start-Sleep -Milliseconds 500; $updated = Get-NetConnectionProfile -InterfaceAlias '%s'; if ($updated) { Write-Output $updated.Name } else { Write-Output 'Failed' } } else { Write-Output 'ProfileNotFound' }", ifaceName, escapedProfileName, ifaceName)
		cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", psCmd)
		output, err := cmd.Output()
		outputStr := strings.TrimSpace(string(output))

		// Check if the output matches our desired profile name (case-insensitive)
		if err == nil && outputStr != "" && outputStr != "ProfileNotFound" && outputStr != "Failed" {
			if strings.EqualFold(outputStr, profileName) {
				slog.Info("set interface profile name via PowerShell", "interface", ifaceName, "profileName", profileName, "actualName", outputStr)
				return nil
			}
			// If we got a name but it's not what we want, log and continue retrying
			slog.Debug("profile name set but doesn't match expected", "expected", profileName, "got", outputStr, "attempt", i+1)
		}

		if outputStr == "ProfileNotFound" || outputStr == "Failed" {
			slog.Debug("profile not found or failed, retrying", "interface", ifaceName, "attempt", i+1, "output", outputStr)
			continue
		}

		if err != nil {
			slog.Debug("PowerShell command failed, retrying", "interface", ifaceName, "attempt", i+1, "error", err, "output", outputStr)
		}

		if i == maxRetries-1 {
			slog.Warn("failed to set interface profile name via PowerShell after retries", "interface", ifaceName, "error", err, "output", outputStr)
			// Fallback: Set via registry if PowerShell fails
			return setInterfaceProfileNameViaRegistry(ifaceName, profileName)
		}
	}

	return fmt.Errorf("failed to set profile name after %d attempts", maxRetries)
}

// setInterfaceProfileNameViaRegistry - fallback method to set profile name via registry
func setInterfaceProfileNameViaRegistry(ifaceName string, profileName string) error {
	// Retry getting the profile GUID with delays
	maxRetries := 5
	var profileGUID string
	var err error

	for i := 0; i < maxRetries; i++ {
		if i > 0 {
			time.Sleep(1 * time.Second)
		}

		// First, get the profile GUID for the interface using PowerShell
		psCmd := fmt.Sprintf("$profile = Get-NetConnectionProfile -InterfaceAlias '%s' -ErrorAction SilentlyContinue; if ($profile) { $profile.InstanceID } else { Write-Output '' }", ifaceName)
		cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", psCmd)
		output, err := cmd.Output()
		if err != nil {
			slog.Debug("failed to get profile GUID, retrying", "attempt", i+1, "error", err)
			continue
		}

		profileGUID = strings.TrimSpace(string(output))
		if profileGUID != "" {
			break
		}
	}

	if profileGUID == "" {
		return fmt.Errorf("profile GUID not found for interface %s after %d attempts", ifaceName, maxRetries)
	}

	// Remove braces if present
	profileGUID = strings.Trim(profileGUID, "{}")
	profileGUID = strings.TrimSpace(profileGUID)

	// Retry opening the registry key with delays
	var key registry.Key
	for i := 0; i < maxRetries; i++ {
		if i > 0 {
			time.Sleep(500 * time.Millisecond)
		}

		keyPath := fmt.Sprintf(`SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{%s}`, profileGUID)
		// Try to open existing key first
		key, err = registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.SET_VALUE)
		if err != nil {
			// If key doesn't exist, try to create it
			if errors.Is(err, registry.ErrNotExist) {
				parentPath := `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles`
				parentKey, parentErr := registry.OpenKey(registry.LOCAL_MACHINE, parentPath, registry.ALL_ACCESS)
				if parentErr == nil {
					createdKey, _, createErr := registry.CreateKey(parentKey, "{"+profileGUID+"}", registry.ALL_ACCESS)
					parentKey.Close()
					if createErr == nil {
						key = createdKey
						err = nil
					} else {
						slog.Debug("failed to create registry key, retrying", "path", keyPath, "attempt", i+1, "error", createErr)
					}
				}
			} else {
				slog.Debug("failed to open registry key, retrying", "path", keyPath, "attempt", i+1, "error", err)
			}
		}

		if err == nil {
			break
		}
	}

	if err != nil {
		return fmt.Errorf("failed to open/create profile registry key after %d attempts: %w", maxRetries, err)
	}
	defer key.Close()

	err = key.SetStringValue("ProfileName", profileName)
	if err != nil {
		return fmt.Errorf("failed to set profile name: %w", err)
	}

	// Also set Description to match (some Windows tools use Description)
	err = key.SetStringValue("Description", profileName)
	if err != nil {
		slog.Debug("failed to set Description, continuing", "error", err)
	}

	slog.Info("set interface profile name via registry", "interface", ifaceName, "profileName", profileName, "guid", profileGUID)
	return nil
}

// SetInterfacePrivateProfile - sets the Windows network interface profile to Private
func SetInterfacePrivateProfile(ifaceName string) error {
	// Use PowerShell to set the network profile to Private
	psCmd := fmt.Sprintf("Set-NetConnectionProfile -InterfaceAlias '%s' -NetworkCategory Private -ErrorAction SilentlyContinue", ifaceName)
	cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", psCmd)
	output, err := cmd.Output()
	if err != nil {
		// Try alternative approach if the first one fails
		psCmd2 := fmt.Sprintf("$profile = Get-NetConnectionProfile -InterfaceAlias '%s' -ErrorAction SilentlyContinue; if ($profile) { Set-NetConnectionProfile -InterfaceAlias '%s' -NetworkCategory Private -ErrorAction Stop }", ifaceName, ifaceName)
		cmd2 := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", psCmd2)
		output, err = cmd2.Output()
		if err != nil {
			slog.Error("failed to set interface profile to Private", "interface", ifaceName, "error", err, "output", string(output))
			return fmt.Errorf("failed to set interface profile: %w", err)
		}
	}
	slog.Info("set interface profile to Private", "interface", ifaceName)
	return nil
}

// NCIface.Create - makes a new Wireguard interface and sets given addresses
func (nc *NCIface) Create() error {
	wgMutex.Lock()
	defer wgMutex.Unlock()

	// Flush network caches before creating interface to ensure clean state
	FlushWindowsNetworkCaches()

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
	if err := adapter.SetAdapterState(driver.AdapterStateUp); err != nil {
		return err
	}

	// Set network profile settings asynchronously (non-blocking)
	go func() {
		ifaceName := ncutils.GetInterfaceName()

		// Wait a moment for Windows to create the network profile after bringing interface up
		time.Sleep(2 * time.Second)

		// Set network profile to Private if force flag is set
		if config.Netclient().ForcePrivateProfile {
			if err := SetInterfacePrivateProfile(ifaceName); err != nil {
				slog.Warn("failed to set interface profile to Private", "error", err)
			}
		}

		// Set interface profile name if configured
		if config.Netclient().InterfaceProfileName != "" {
			if err := SetInterfaceProfileName(ifaceName, config.Netclient().InterfaceProfileName); err != nil {
				slog.Warn("failed to set interface profile name", "error", err)
			}
		}
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

// FlushWindowsNetworkCaches - flushes Windows network caches (route, ARP, NetBIOS, DNS)
func FlushWindowsNetworkCaches() {
	// Clear route destination cache
	_, _ = ncutils.RunCmd("netsh interface ip delete destinationcache", false)

	// Clear ARP cache
	_, _ = ncutils.RunCmd("arp -d *", false)

	// Clear NetBIOS cache
	_, _ = ncutils.RunCmd("nbtstat -R", false)
	_, _ = ncutils.RunCmd("nbtstat -RR", false)

	// Flush DNS cache
	_, _ = ncutils.RunCmd("ipconfig /flushdns", false)

	// Re-register DNS
	_, _ = ncutils.RunCmd("ipconfig /registerdns", false)

	slog.Info("flushed Windows network caches")
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

	// Flush network caches when closing interface
	FlushWindowsNetworkCaches()
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
