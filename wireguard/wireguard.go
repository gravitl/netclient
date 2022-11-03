package wireguard

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/local"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"github.com/kr/pretty"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"gopkg.in/ini.v1"
)

const (
	section_interface = "Interface"
	section_peers     = "Peer"
)

// ApplyConf - applys a conf on disk to WireGuard interface
func ApplyConf(node *config.Node, confPath string) {
	os := runtime.GOOS
	if ncutils.IsLinux() && !ncutils.HasWgQuick() {
		os = "nowgquick"
	}
	switch os {
	case "windows":
		ApplyWindowsConf(confPath, node.Interface, node.Connected)
	case "nowgquick":
		ApplyWithoutWGQuick(node, node.Interface, confPath, node.Connected)
	default:
		ApplyWGQuickConf(confPath, node.Interface, node.Connected)
	}

	if !node.IsServer {
		if node.NetworkRange.IP != nil {
			local.SetCIDRRoute(node.Interface, &node.NetworkRange)
		}
		if node.NetworkRange6.IP != nil {
			local.SetCIDRRoute(node.Interface, &node.NetworkRange6)
		}
	}
}

// ApplyWGQuickConf - applies wg-quick commands if os supports
func ApplyWGQuickConf(confPath, ifacename string, isConnected bool) error {
	_, err := os.Stat(confPath)
	if err != nil {
		logger.Log(0, confPath+" does not exist "+err.Error())
		return err
	}
	if IfaceExists(ifacename) {
		ncutils.RunCmd("wg-quick down "+confPath, true)
	}
	if !isConnected {
		return nil
	}
	_, err = ncutils.RunCmd("wg-quick up "+confPath, true)

	return err
}

// RemoveConfGraceful - Run remove conf and wait for it to actually be gone before proceeding
func RemoveConfGraceful(ifacename string) {
	// ensure you clear any existing interface first
	wgclient, err := wgctrl.New()
	if err != nil {
		logger.Log(0, "could not create wgclient")
		return
	}
	defer wgclient.Close()
	d, _ := wgclient.Device(ifacename)
	startTime := time.Now()
	for d != nil && d.Name == ifacename {
		if err = RemoveConf(ifacename, false); err != nil { // remove interface first
			if strings.Contains(err.Error(), "does not exist") {
				err = nil
				break
			}
		}
		time.Sleep(time.Second >> 2)
		d, _ = wgclient.Device(ifacename)
		if time.Now().After(startTime.Add(time.Second << 4)) {
			break
		}
	}
	time.Sleep(time.Second << 1)
}

// RemoveConf - removes a configuration for a given WireGuard interface
func RemoveConf(iface string, printlog bool) error {
	os := runtime.GOOS
	if ncutils.IsLinux() && !ncutils.HasWgQuick() {
		os = "nowgquick"
	}
	var err error
	switch os {
	case "nowgquick":
		err = RemoveWithoutWGQuick(iface)
	case "windows":
		err = RemoveWindowsConf(iface, printlog)
	default:
		confPath := config.GetNetclientInterfacePath() + iface + ".conf"
		err = RemoveWGQuickConf(confPath, printlog)
	}
	return err
}

// RemoveWGQuickConf - calls wg-quick down
func RemoveWGQuickConf(confPath string, printlog bool) error {
	_, err := ncutils.RunCmd(fmt.Sprintf("wg-quick down %s", confPath), printlog)
	return err
}

// SetWGConfig - sets the WireGuard Config of a given network and checks if it needs a peer update
func SetWGConfig(network string, peerupdate bool, peers []wgtypes.PeerConfig) error {
	node := config.Nodes[network]
	var err error
	if peerupdate && !ncutils.IsFreeBSD() && !(ncutils.IsLinux() && !ncutils.IsKernel()) {
		var iface string
		iface = node.Interface
		if ncutils.IsMac() {
			iface, err = local.GetMacIface(node.PrimaryAddress().IP.String())
			if err != nil {
				return err
			}
		}
		err = SetPeers(iface, &node, peers)
	} else {
		err = InitWireguard(&node, peers)
	}
	return err
}

// Initializes a WireGuard interface
func InitWireguard(node *config.Node, peers []wgtypes.PeerConfig) error {
	wgclient, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer wgclient.Close()
	//nodecfg := modcfg.Node
	var ifacename string
	if node.Interface != "" {
		ifacename = node.Interface
	} else {
		return fmt.Errorf("no interface to configure")
	}
	if node.PrimaryAddress().IP == nil {
		pretty.Println(node.PrimaryAddress(), node.Address, node.Address6)
		return fmt.Errorf("no address to configure")
	}
	if err := WriteWgConfig(node, peers); err != nil {
		logger.Log(1, "error writing wg conf file: ", err.Error())
		return err
	}
	// spin up userspace / windows interface + apply the conf file
	confPath := config.GetNetclientInterfacePath() + ifacename + ".conf"
	var deviceiface = ifacename
	var mErr error
	if ncutils.IsMac() { // if node is Mac (Darwin) get the tunnel name first
		deviceiface, mErr = local.GetMacIface(node.PrimaryAddress().IP.String())
		if mErr != nil || deviceiface == "" {
			deviceiface = ifacename
		}
	}
	// ensure you clear any existing interface first
	//RemoveConfGraceful(deviceiface)
	ApplyConf(node, confPath)                 // Apply initially
	logger.Log(1, "waiting for interface...") // ensure interface is created
	output, _ := ncutils.RunCmd("wg", false)
	starttime := time.Now()
	ifaceReady := strings.Contains(output, deviceiface)
	for !ifaceReady && !(time.Now().After(starttime.Add(time.Second << 4))) {
		if ncutils.IsMac() { // if node is Mac (Darwin) get the tunnel name first
			deviceiface, mErr = local.GetMacIface(node.PrimaryAddress().IP.String())
			if mErr != nil || deviceiface == "" {
				deviceiface = ifacename
			}
		}
		output, _ = ncutils.RunCmd("wg", false)
		ApplyConf(node, confPath)
		time.Sleep(time.Second)
		ifaceReady = strings.Contains(output, deviceiface)
	}
	//wgclient does not work well on freebsd
	if node.OS == "freebsd" {
		if !ifaceReady {
			return fmt.Errorf("could not reliably create interface, please check wg installation and retry")
		}
	} else {
		_, devErr := wgclient.Device(deviceiface)
		if !ifaceReady || devErr != nil {
			fmt.Printf("%v\n", devErr)
			return fmt.Errorf("could not reliably create interface, please check wg installation and retry")
		}
	}
	logger.Log(1, "interface ready - netclient.. ENGAGE")

	if !ncutils.HasWgQuick() && ncutils.IsLinux() {
		err = SetPeers(ifacename, node, peers)
		if err != nil {
			logger.Log(1, "error setting peers: ", err.Error())
		}

		time.Sleep(time.Second)
	}
	//ipv4
	if node.Address.IP != nil {
		local.SetCIDRRoute(ifacename, &node.Address)
	}
	//ipv6
	if node.Address6.IP != nil {
		local.SetCIDRRoute(ifacename, &node.Address6)
	}
	local.SetCurrentPeerRoutes(node.Interface, peers)
	return err
}

// SetPeers - sets peers on a given WireGuard interface
func SetPeers(iface string, node *config.Node, peers []wgtypes.PeerConfig) error {
	var devicePeers []wgtypes.Peer
	var keepalive = node.PersistentKeepalive
	var oldPeerAllowedIps = make(map[string]bool, len(peers))
	var err error
	devicePeers, err = GetDevicePeers(iface)
	if err != nil {
		return err
	}

	if len(devicePeers) > 1 && len(peers) == 0 {
		logger.Log(1, "no peers pulled")
		return err
	}
	for _, peer := range peers {
		// make sure peer has AllowedIP's before comparison
		hasPeerIP := len(peer.AllowedIPs) > 0
		for _, currentPeer := range devicePeers {
			// make sure currenPeer has AllowedIP's before comparison
			hascurrentPeerIP := len(currentPeer.AllowedIPs) > 0

			if hasPeerIP && hascurrentPeerIP &&
				currentPeer.AllowedIPs[0].String() == peer.AllowedIPs[0].String() &&
				currentPeer.PublicKey.String() != peer.PublicKey.String() {
				_, err := ncutils.RunCmd("wg set "+iface+" peer "+currentPeer.PublicKey.String()+" remove", true)
				if err != nil {
					logger.Log(0, "error removing peer", peer.Endpoint.String())
				}
			}
		}
		udpendpoint := peer.Endpoint.String()
		var allowedips string
		var iparr []string
		for _, ipaddr := range peer.AllowedIPs {
			if hasPeerIP {
				iparr = append(iparr, ipaddr.String())
			}
		}
		if len(iparr) > 0 {
			allowedips = strings.Join(iparr, ",")
		}
		keepAliveString := strconv.Itoa(int(keepalive))
		if keepAliveString == "0" {
			keepAliveString = "15"
		}
		if node.IsServer || peer.Endpoint == nil {
			_, err = ncutils.RunCmd("wg set "+iface+" peer "+peer.PublicKey.String()+
				" persistent-keepalive "+keepAliveString+
				" allowed-ips "+allowedips, true)
		} else {
			_, err = ncutils.RunCmd("wg set "+iface+" peer "+peer.PublicKey.String()+
				" endpoint "+udpendpoint+
				" persistent-keepalive "+keepAliveString+
				" allowed-ips "+allowedips, true)
		}
		if err != nil {
			logger.Log(0, "error setting peer", peer.PublicKey.String())
		}
	}
	if len(devicePeers) > 0 {
		for _, currentPeer := range devicePeers {
			shouldDelete := true
			if len(peers) > 0 {
				for _, peer := range peers {

					if len(peer.AllowedIPs) > 0 && len(currentPeer.AllowedIPs) > 0 &&
						peer.AllowedIPs[0].String() == currentPeer.AllowedIPs[0].String() {
						shouldDelete = false
					}
					// re-check this if logic is not working, added in case of allowedips not working
					if peer.PublicKey.String() == currentPeer.PublicKey.String() {
						shouldDelete = false
					}
				}
				if shouldDelete {
					output, err := ncutils.RunCmd("wg set "+iface+" peer "+currentPeer.PublicKey.String()+" remove", true)
					if err != nil {
						logger.Log(0, output, "error removing peer", currentPeer.PublicKey.String())
					}
				}
				for _, ip := range currentPeer.AllowedIPs {
					oldPeerAllowedIps[ip.String()] = true
				}
			}
		}
	}

	// if routes are wrong, come back to this, but should work...I would think. Or we should get it working.
	if len(peers) > 0 {
		local.SetPeerRoutes(iface, oldPeerAllowedIps, peers)
	}

	return nil
}

// GetDevicePeers - gets the current device's peers
func GetDevicePeers(iface string) ([]wgtypes.Peer, error) {
	if ncutils.IsFreeBSD() {
		if devicePeers, err := GetPeers(iface); err != nil {
			return nil, err
		} else {
			return devicePeers, nil
		}
	} else {
		client, err := wgctrl.New()
		if err != nil {
			logger.Log(0, "failed to start wgctrl")
			return nil, err
		}
		defer client.Close()
		device, err := client.Device(iface)
		if err != nil {
			logger.Log(0, "failed to parse interface", iface)
			return nil, err
		}
		return device.Peers, nil
	}
}

// GetPeers - gets the peers from a given WireGuard interface
func GetPeers(iface string) ([]wgtypes.Peer, error) {

	var peers []wgtypes.Peer
	output, err := ncutils.RunCmd("wg show "+iface+" dump", true)
	if err != nil {
		return peers, err
	}
	for i, line := range strings.Split(strings.TrimSuffix(output, "\n"), "\n") {
		if i == 0 {
			continue
		}
		var allowedIPs []net.IPNet
		fields := strings.Fields(line)
		if len(fields) < 4 {
			logger.Log(0, "error parsing peer: "+line)
			continue
		}
		pubkeystring := fields[0]
		endpointstring := fields[2]
		allowedipstring := fields[3]
		var pkeepalivestring string
		if len(fields) > 7 {
			pkeepalivestring = fields[7]
		}
		// AllowedIPs = private IP + defined networks

		pubkey, err := wgtypes.ParseKey(pubkeystring)
		if err != nil {
			logger.Log(0, "error parsing peer key "+pubkeystring)
			continue
		}
		ipstrings := strings.Split(allowedipstring, ",")
		for _, ipstring := range ipstrings {
			var netip net.IP
			if netip = net.ParseIP(strings.Split(ipstring, "/")[0]); netip != nil {
				allowedIPs = append(
					allowedIPs,
					net.IPNet{
						IP:   netip,
						Mask: netip.DefaultMask(),
					},
				)
			}
		}
		if len(allowedIPs) == 0 {
			logger.Log(0, "error parsing peer "+pubkeystring+", no allowedips found")
			continue
		}
		var endpointarr []string
		var endpointip net.IP
		if endpointarr = strings.Split(endpointstring, ":"); len(endpointarr) != 2 {
			logger.Log(0, "error parsing peer "+pubkeystring+", could not parse endpoint: "+endpointstring)
			continue
		}
		if endpointip = net.ParseIP(endpointarr[0]); endpointip == nil {
			logger.Log(0, "error parsing peer "+pubkeystring+", could not parse endpoint: "+endpointarr[0])
			continue
		}
		var port int
		if port, err = strconv.Atoi(endpointarr[1]); err != nil {
			logger.Log(0, "error parsing peer "+pubkeystring+", could not parse port: "+err.Error())
			continue
		}
		var endpoint = net.UDPAddr{
			IP:   endpointip,
			Port: port,
		}
		var dur time.Duration
		if pkeepalivestring != "" {
			if dur, err = time.ParseDuration(pkeepalivestring + "s"); err != nil {
				logger.Log(0, "error parsing peer "+pubkeystring+", could not parse keepalive: "+err.Error())
			}
		}

		peers = append(peers, wgtypes.Peer{
			PublicKey:                   pubkey,
			Endpoint:                    &endpoint,
			AllowedIPs:                  allowedIPs,
			PersistentKeepaliveInterval: dur,
		})
	}

	return peers, err
}

// WriteWgConfig - creates a wireguard config file
func WriteWgConfig(node *config.Node, peers []wgtypes.PeerConfig) error {
	options := ini.LoadOptions{
		AllowNonUniqueSections: true,
		AllowShadows:           true,
	}
	wireguard := ini.Empty(options)
	wireguard.Section(section_interface).Key("PrivateKey").SetValue(node.PrivateKey.String())
	if node.ListenPort > 0 && !node.UDPHolePunch {
		wireguard.Section(section_interface).Key("ListenPort").SetValue(strconv.Itoa(node.ListenPort))
	}
	addrString := node.Address.String()
	if node.Address6.IP != nil {
		if addrString != "" {
			addrString += ","
		}
		addrString += node.Address6.String()
	}
	wireguard.Section(section_interface).Key("Address").SetValue(addrString)
	// need to figure out DNS
	//if node.DNSOn == "yes" {
	//	wireguard.Section(section_interface).Key("DNS").SetValue(cfg.Server.CoreDNSAddr)
	//}
	//need to split postup/postdown because ini lib adds a ` and the ` breaks freebsd
	//works fine on others
	if node.PostUp != "" {
		if node.OS == "freebsd" {
			parts := strings.Split(node.PostUp, " ; ")
			for i, part := range parts {
				if i == 0 {
					wireguard.Section(section_interface).Key("PostUp").SetValue(part)
				}
				wireguard.Section(section_interface).Key("PostUp").AddShadow(part)
			}
		} else {
			wireguard.Section(section_interface).Key("PostUp").SetValue((node.PostUp))
		}
	}
	if node.PostDown != "" {
		if node.OS == "freebsd" {
			parts := strings.Split(node.PostDown, " ; ")
			for i, part := range parts {
				if i == 0 {
					wireguard.Section(section_interface).Key("PostDown").SetValue(part)
				}
				wireguard.Section(section_interface).Key("PostDown").AddShadow(part)
			}
		} else {
			wireguard.Section(section_interface).Key("PostDown").SetValue((node.PostDown))
		}
	}
	if node.MTU != 0 {
		wireguard.Section(section_interface).Key("MTU").SetValue(strconv.FormatInt(int64(node.MTU), 10))
	}
	for i, peer := range peers {
		wireguard.SectionWithIndex(section_peers, i).Key("PublicKey").SetValue(peer.PublicKey.String())
		if peer.PresharedKey != nil {
			wireguard.SectionWithIndex(section_peers, i).Key("PreSharedKey").SetValue(peer.PresharedKey.String())
		}
		if peer.AllowedIPs != nil {
			var allowedIPs string
			for i, ip := range peer.AllowedIPs {
				if i == 0 {
					allowedIPs = ip.String()
				} else {
					allowedIPs = allowedIPs + ", " + ip.String()
				}
			}
			wireguard.SectionWithIndex(section_peers, i).Key("AllowedIps").SetValue(allowedIPs)
		}
		if peer.Endpoint != nil {
			wireguard.SectionWithIndex(section_peers, i).Key("Endpoint").SetValue(peer.Endpoint.String())
		}

		if peer.PersistentKeepaliveInterval != nil && peer.PersistentKeepaliveInterval.Seconds() > 0 {
			wireguard.SectionWithIndex(section_peers, i).Key("PersistentKeepalive").SetValue(strconv.FormatInt((int64)(peer.PersistentKeepaliveInterval.Seconds()), 10))
		}
	}
	if err := wireguard.SaveTo(config.GetNetclientInterfacePath() + node.Interface + ".conf"); err != nil {
		return err
	}
	return nil
}

// UpdatePrivateKey - updates the private key of a wireguard config file
func UpdatePrivateKey(file, privateKey string) error {
	options := ini.LoadOptions{
		AllowNonUniqueSections: true,
		AllowShadows:           true,
	}
	wireguard, err := ini.LoadSources(options, file)
	if err != nil {
		return err
	}
	wireguard.Section(section_interface).Key("PrivateKey").SetValue(privateKey)
	if err := wireguard.SaveTo(file); err != nil {
		return err
	}
	return nil
}

// UpdateWgInterface - updates the interface section of a wireguard config file
func UpdateWgInterface(file, nameserver string, node *config.Node) error {
	options := ini.LoadOptions{
		AllowNonUniqueSections: true,
		AllowShadows:           true,
	}
	wireguard, err := ini.LoadSources(options, file)
	if err != nil {
		return err
	}
	if node.UDPHolePunch {
		node.ListenPort = 0
	}
	wireguard.DeleteSection(section_interface)
	wireguard.Section(section_interface).Key("PrivateKey").SetValue(node.PrivateKey.String())
	wireguard.Section(section_interface).Key("ListenPort").SetValue(strconv.Itoa(node.ListenPort))
	addrString := node.Address.String()
	if node.Address6.IP != nil {
		if addrString != "" {
			addrString += ","
		}
		addrString += node.Address6.String()
	}
	wireguard.Section(section_interface).Key("Address").SetValue(addrString)
	//if node.DNSOn == "yes" {
	//	wireguard.Section(section_interface).Key("DNS").SetValue(nameserver)
	//}
	//need to split postup/postdown because ini lib adds a quotes which breaks freebsd
	if node.PostUp != "" {
		parts := strings.Split(node.PostUp, " ; ")
		for i, part := range parts {
			if i == 0 {
				wireguard.Section(section_interface).Key("PostUp").SetValue(part)
			}
			wireguard.Section(section_interface).Key("PostUp").AddShadow(part)
		}
	}
	if node.PostDown != "" {
		parts := strings.Split(node.PostDown, " ; ")
		for i, part := range parts {
			if i == 0 {
				wireguard.Section(section_interface).Key("PostDown").SetValue(part)
			}
			wireguard.Section(section_interface).Key("PostDown").AddShadow(part)
		}
	}
	if node.MTU != 0 {
		wireguard.Section(section_interface).Key("MTU").SetValue(strconv.FormatInt(int64(node.MTU), 10))
	}
	if err := wireguard.SaveTo(file); err != nil {
		return err
	}
	return nil
}

// UpdateKeepAlive - updates the persistentkeepalive of all peers
func UpdateKeepAlive(file string, keepalive int) error {
	options := ini.LoadOptions{
		AllowNonUniqueSections: true,
		AllowShadows:           true,
	}
	wireguard, err := ini.LoadSources(options, file)
	if err != nil {
		return err
	}
	peers, err := wireguard.SectionsByName(section_peers)
	if err != nil {
		return err
	}
	newvalue := strconv.Itoa(keepalive)
	for i := range peers {
		wireguard.SectionWithIndex(section_peers, i).Key("PersistentKeepALive").SetValue(newvalue)
	}
	if err := wireguard.SaveTo(file); err != nil {
		return err
	}
	return nil
}

func UpdateWgPeers(file string, peers []wgtypes.PeerConfig) (*net.UDPAddr, error) {
	var internetGateway *net.UDPAddr
	options := ini.LoadOptions{
		AllowNonUniqueSections: true,
		AllowShadows:           true,
	}
	wireguard, err := ini.LoadSources(options, file)
	if err != nil {
		return internetGateway, err
	}
	//delete the peers sections as they are going to be replaced
	wireguard.DeleteSection(section_peers)
	for i, peer := range peers {
		wireguard.SectionWithIndex(section_peers, i).Key("PublicKey").SetValue(peer.PublicKey.String())
		if peer.PresharedKey != nil {
			wireguard.SectionWithIndex(section_peers, i).Key("PreSharedKey").SetValue(peer.PresharedKey.String())
		}
		if peer.AllowedIPs != nil {
			var allowedIPs string
			for i, ip := range peer.AllowedIPs {
				if i == 0 {
					allowedIPs = ip.String()
				} else {
					allowedIPs = allowedIPs + ", " + ip.String()
				}
			}
			wireguard.SectionWithIndex(section_peers, i).Key("AllowedIps").SetValue(allowedIPs)
			if strings.Contains(allowedIPs, "0.0.0.0/0") || strings.Contains(allowedIPs, "::/0") {
				internetGateway = peer.Endpoint
			}
		}
		if peer.Endpoint != nil {
			wireguard.SectionWithIndex(section_peers, i).Key("Endpoint").SetValue(peer.Endpoint.String())
		}
		if peer.PersistentKeepaliveInterval != nil && peer.PersistentKeepaliveInterval.Seconds() > 0 {
			wireguard.SectionWithIndex(section_peers, i).Key("PersistentKeepalive").SetValue(strconv.FormatInt((int64)(peer.PersistentKeepaliveInterval.Seconds()), 10))
		}
	}
	if err := wireguard.SaveTo(file); err != nil {
		return internetGateway, err
	}
	return internetGateway, nil
}
