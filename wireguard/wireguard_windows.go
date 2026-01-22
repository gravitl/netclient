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
	// Retry up to 8 times with shorter delays (starts with 500ms, then 1s)
	maxRetries := 8
	var lastErr error
	for i := 0; i < maxRetries; i++ {
		if i > 0 {
			// Use shorter delay on first retry, then standard 1 second
			delay := 1 * time.Second
			if i == 1 {
				delay = 500 * time.Millisecond
			}
			time.Sleep(delay)
		}

		// Use registry method (most reliable for profile name)
		err := setInterfaceProfileNameViaRegistry(ifaceName, profileName)
		if err == nil {
			slog.Info("set interface profile name via registry", "interface", ifaceName, "profileName", profileName)
			return nil
		}
		lastErr = err
	}

	return fmt.Errorf("failed to set profile name after %d attempts: %w", maxRetries, lastErr)
}

// setInterfaceProfileNameViaRegistry - sets profile name by enumerating registry profiles
func setInterfaceProfileNameViaRegistry(ifaceName string, profileName string) error {
	// Retry finding and updating the profile with delays
	maxRetries := 5
	var err error

	for i := 0; i < maxRetries; i++ {
		if i > 0 {
			// Use shorter delay on first retry
			delay := 1 * time.Second
			if i == 1 {
				delay = 500 * time.Millisecond
			}
			time.Sleep(delay)
		}

		// Enumerate registry to find and update the profile
		err = findAndUpdateProfileName(ifaceName, profileName)
		if err == nil {
			slog.Info("set interface profile name via registry", "interface", ifaceName, "profileName", profileName)
			return nil
		}
		slog.Debug("failed to find/update profile in registry, retrying", "attempt", i+1, "error", err)
	}

	return fmt.Errorf("failed to set profile name after %d attempts: %w", maxRetries, err)
}

// findAndUpdateProfileName - enumerates registry profiles to find one matching interface name and update it
func findAndUpdateProfileName(ifaceName string, profileName string) error {
	parentPath := `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles`
	parentKey, err := registry.OpenKey(registry.LOCAL_MACHINE, parentPath, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return fmt.Errorf("failed to open profiles registry key: %w", err)
	}
	defer parentKey.Close()

	// First, try to find a profile where ProfileName matches the interface name
	// If not found, fall back to the most recently created profile (within last 30 seconds)
	var matchingGUID string
	var latestGUID string
	keepLooking := true

	for keepLooking {
		subKeyNames, err := parentKey.ReadSubKeyNames(10)
		if err != nil {
			if err == registry.ErrNotExist || err.Error() == "EOF" {
				keepLooking = false
			} else {
				return fmt.Errorf("failed to read subkeys: %w", err)
			}
		}
		if len(subKeyNames) == 0 {
			keepLooking = false
			continue
		}

		for _, guid := range subKeyNames {
			subKey, err := registry.OpenKey(parentKey, guid, registry.QUERY_VALUE)
			if err != nil {
				continue
			}

			// Check if ProfileName matches the interface name
			currentProfileName, _, err := subKey.GetStringValue("ProfileName")
			if err == nil && currentProfileName == ifaceName {
				// Found a profile matching the interface name
				matchingGUID = strings.Trim(guid, "{}")
				subKey.Close()
				break
			}
			subKey.Close()
		}

		// If we found a matching profile, stop searching
		if matchingGUID != "" {
			keepLooking = false
		}
	}

	// Use matching profile if found, otherwise use the most recent one
	selectedGUID := matchingGUID
	if selectedGUID == "" {
		selectedGUID = latestGUID
	}

	if selectedGUID == "" {
		return fmt.Errorf("no profile found in registry for interface %s", ifaceName)
	}

	// Update the profile name
	profilePath := parentPath + `\` + "{" + selectedGUID + "}"
	profileKey, err := registry.OpenKey(registry.LOCAL_MACHINE, profilePath, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("failed to open profile key: %w", err)
	}
	defer profileKey.Close()

	err = profileKey.SetStringValue("ProfileName", profileName)
	if err != nil {
		return fmt.Errorf("failed to set profile name: %w", err)
	}

	// Also set Description to match
	err = profileKey.SetStringValue("Description", profileName)
	if err != nil {
		slog.Debug("failed to set Description, continuing", "error", err)
	}

	if matchingGUID != "" {
		slog.Debug("updated profile name in registry (matched by interface name)", "interface", ifaceName, "profileGUID", selectedGUID, "profileName", profileName)
	} else {
		slog.Debug("updated profile name in registry (using most recent profile)", "interface", ifaceName, "profileGUID", selectedGUID, "profileName", profileName)
	}
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
			// Check if adapter already exists - try to open it again
			if strings.Contains(err.Error(), "already exists") || strings.Contains(err.Error(), "Cannot create a file when that file already exists") {
				slog.Info("adapter already exists, attempting to open it")
				// Retry opening the adapter - it might have been created by another process
				var openErr error
				adapter, openErr = driver.OpenAdapter(ncutils.GetInterfaceName())
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
	if err := adapter.SetAdapterState(driver.AdapterStateUp); err != nil {
		return err
	}

	// Set network profile settings asynchronously (non-blocking)
	go func() {
		ifaceName := ncutils.GetInterfaceName()

		// Wait for Windows to create and register the network profile in the registry
		// Use a shorter initial wait, then check if interface exists
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
