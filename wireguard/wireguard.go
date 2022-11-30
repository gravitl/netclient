package wireguard

import (
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"gopkg.in/ini.v1"
)

var wgMutex = sync.Mutex{} // used to mutex functions of the interface

// SetPeers - sets peers on netmaker WireGuard interface
func SetPeers() {
	nodes := config.GetNodes()
	peers := []wgtypes.PeerConfig{}
	for _, node := range nodes {
		if node.Connected {
			peers = append(peers, node.Peers...)
		}
	}
	config := wgtypes.Config{
		ReplacePeers: true,
		Peers:        peers,
	}
	apply(nil, &config)
}

//func SetPeers(iface string, node *config.Node, peers []wgtypes.PeerConfig) error {
//	var devicePeers []wgtypes.Peer
//	var keepalive = node.PersistentKeepalive
//	var oldPeerAllowedIps = make(map[string]bool, len(peers))
//	var err error
//	devicePeers, err = GetDevicePeers(iface)
//	if err != nil {
//		return err
//	}
//
//	if len(devicePeers) > 1 && len(peers) == 0 {
//		logger.Log(1, "no peers pulled")
//		return err
//	}
//	for _, peer := range peers {
//		// make sure peer has AllowedIP's before comparison
//		hasPeerIP := len(peer.AllowedIPs) > 0
//		for _, currentPeer := range devicePeers {
//			// make sure currenPeer has AllowedIP's before comparison
//			hascurrentPeerIP := len(currentPeer.AllowedIPs) > 0
//
//			if hasPeerIP && hascurrentPeerIP &&
//				currentPeer.AllowedIPs[0].String() == peer.AllowedIPs[0].String() &&
//				currentPeer.PublicKey.String() != peer.PublicKey.String() {
//				_, err := ncutils.RunCmd("wg set "+iface+" peer "+currentPeer.PublicKey.String()+" remove", true)
//				if err != nil {
//					logger.Log(0, "error removing peer", peer.Endpoint.String())
//				}
//			}
//		}
//		udpendpoint := peer.Endpoint.String()
//		var allowedips string
//		var iparr []string
//		for _, ipaddr := range peer.AllowedIPs {
//			if hasPeerIP {
//				iparr = append(iparr, ipaddr.String())
//			}
//		}
//		if len(iparr) > 0 {
//			allowedips = strings.Join(iparr, ",")
//		}
//		keepAliveString := strconv.Itoa(int(keepalive))
//		if keepAliveString == "0" {
//			keepAliveString = "15"
//		}
//		if node.IsServer || peer.Endpoint == nil {
//			_, err = ncutils.RunCmd("wg set "+iface+" peer "+peer.PublicKey.String()+
//				" persistent-keepalive "+keepAliveString+
//				" allowed-ips "+allowedips, true)
//		} else {
//			_, err = ncutils.RunCmd("wg set "+iface+" peer "+peer.PublicKey.String()+
//				" endpoint "+udpendpoint+
//				" persistent-keepalive "+keepAliveString+
//				" allowed-ips "+allowedips, true)
//		}
//		if err != nil {
//			logger.Log(0, "error setting peer", peer.PublicKey.String())
//		}
//	}
//	if len(devicePeers) > 0 {
//		for _, currentPeer := range devicePeers {
//			shouldDelete := true
//			if len(peers) > 0 {
//				for _, peer := range peers {
//
//					if len(peer.AllowedIPs) > 0 && len(currentPeer.AllowedIPs) > 0 &&
//						peer.AllowedIPs[0].String() == currentPeer.AllowedIPs[0].String() {
//						shouldDelete = false
//					}
//					// re-check this if logic is not working, added in case of allowedips not working
//					if peer.PublicKey.String() == currentPeer.PublicKey.String() {
//						shouldDelete = false
//					}
//				}
//				if shouldDelete {
//					output, err := ncutils.RunCmd("wg set "+iface+" peer "+currentPeer.PublicKey.String()+" remove", true)
//					if err != nil {
//						logger.Log(0, output, "error removing peer", currentPeer.PublicKey.String())
//					}
//				}
//				for _, ip := range currentPeer.AllowedIPs {
//					oldPeerAllowedIps[ip.String()] = true
//				}
//			}
//		}
//	}

// if routes are wrong, come back to this, but should work...I would think. Or we should get it working.
//	if len(peers) > 0 {
//		local.SetPeerRoutes(iface, oldPeerAllowedIps, peers)
//	}

//	return nil
//}

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

// Configure - configures a pre-installed network interface with WireGuard
func Configure() error {
	wgMutex.Lock()
	defer wgMutex.Unlock()
	host := config.Netclient()
	firewallMark := 0
	config := wgtypes.Config{
		PrivateKey:   &host.PrivateKey,
		ReplacePeers: true,
		FirewallMark: &firewallMark,
		ListenPort:   &host.ListenPort,
	}
	return apply(nil, &config)
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

// RemovePeers - removes all peers from a given node config
func RemovePeers(node *config.Node) error {
	currPeers, err := getPeers(node)
	if err != nil || len(currPeers) == 0 {
		return err
	}
	options := ini.LoadOptions{
		AllowNonUniqueSections: true,
		AllowShadows:           true,
	}
	wireguard := ini.Empty(options)
	wireguard.DeleteSection(sectionInterface)
	wireguard.Section(sectionInterface).Key("PrivateKey").SetValue(config.Netclient().PrivateKey.String())
	wireguard.Section(sectionInterface).Key("ListenPort").SetValue(strconv.Itoa(config.Netclient().ListenPort))
	addrString := node.Address.String()
	if node.Address6.IP != nil {
		if addrString != "" {
			addrString += ","
		}
		addrString += node.Address6.String()
	}
	wireguard.Section(sectionInterface).Key("Address").SetValue(addrString)
	//if node.DNSOn == "yes" {
	//	wireguard.Section(section_interface).Key("DNS").SetValue(nameserver)
	//}
	//need to split postup/postdown because ini lib adds a quotes which breaks freebsd
	if node.PostUp != "" {
		parts := strings.Split(node.PostUp, " ; ")
		for i, part := range parts {
			if i == 0 {
				wireguard.Section(sectionInterface).Key("PostUp").SetValue(part)
			}
			wireguard.Section(sectionInterface).Key("PostUp").AddShadow(part)
		}
	}
	if node.PostDown != "" {
		parts := strings.Split(node.PostDown, " ; ")
		for i, part := range parts {
			if i == 0 {
				wireguard.Section(sectionInterface).Key("PostDown").SetValue(part)
			}
			wireguard.Section(sectionInterface).Key("PostDown").AddShadow(part)
		}
	}
	if config.Netclient().MTU != 0 {
		wireguard.Section(sectionInterface).Key("MTU").SetValue(strconv.FormatInt(int64(config.Netclient().MTU), 10))
	}
	if err := wireguard.SaveTo(config.GetNetclientPath() + "netmaker.conf"); err != nil {
		return err
	}
	return nil
}

// == private ==

func getPeers(n *config.Node) ([]wgtypes.Peer, error) {
	wg, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	defer wg.Close()
	dev, err := wg.Device(getName())
	if err != nil {
		return nil, err
	}
	return dev.Peers, nil
}

func removePeer(n *config.Node, p *wgtypes.PeerConfig) error {
	p.Remove = true
	config := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{*p},
	}
	return apply(n, &config)
}

func updatePeer(n *config.Node, p *wgtypes.PeerConfig) error {
	config := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{*p},
	}
	return apply(n, &config)
}

func apply(n *config.Node, c *wgtypes.Config) error {
	wg, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer wg.Close()

	return wg.ConfigureDevice(getName(), *c)
}

func getName() string {
	if runtime.GOOS == "darwin" {
		return "utun69"
	}

	return "netmaker"
}
