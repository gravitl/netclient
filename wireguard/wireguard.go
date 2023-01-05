//go:build !freebsd
// +build !freebsd

package wireguard

import (
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/nmproxy/peer"
	"github.com/gravitl/netmaker/logger"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"gopkg.in/ini.v1"
)

// SetPeers - sets peers on netmaker WireGuard interface
func SetPeers() error {
	peers := config.GetHostPeerList()
	if config.Netclient().ProxyEnabled {
		peers = peer.SetPeersEndpointToProxy("", peers)
	}
	config := wgtypes.Config{
		ReplacePeers: true,
		Peers:        peers,
	}
	return apply(nil, &config)
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
	dev, err := wg.Device(ncutils.GetInterfaceName())
	if err != nil {
		return nil, err
	}
	return dev.Peers, nil
}

// RemovePeer replaces a wireguard peer
// temporarily making public func to pass staticchecks
// this function will be required in future when add/delete node on server is refactored
func RemovePeer(n *config.Node, p *wgtypes.PeerConfig) error {
	p.Remove = true
	config := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{*p},
	}
	return apply(n, &config)
}

// UpdatePeer replaces a wireguard peer
// temporarily making public func to pass staticchecks
// this function will be required in future when update node on server is refactored
func UpdatePeer(n *config.Node, p *wgtypes.PeerConfig) error {
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

	return wg.ConfigureDevice(ncutils.GetInterfaceName(), *c)
}
