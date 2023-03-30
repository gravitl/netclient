package wireguard

import (
	"crypto/sha1"
	"fmt"
	"net"
	"strconv"

	"github.com/gravitl/netclient/cache"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/nmproxy/peer"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"gopkg.in/ini.v1"
)

// SetPeers - sets peers on netmaker WireGuard interface
func SetPeers() error {

	peers := config.GetHostPeerList()
	for i := range peers {
		peer := peers[i]
		if checkForBetterEndpoint(&peer) {
			peers[i] = peer
		}
	}
	GetInterface().Config.Peers = peers
	peers = peer.SetPeersEndpointToProxy(peers)

	config := wgtypes.Config{
		ReplacePeers: false,
		Peers:        peers,
	}
	return apply(&config)
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
	return apply(&config)
}

// UpdatePeer replaces a wireguard peer
// temporarily making public func to pass staticchecks
// this function will be required in future when update node on server is refactored
func UpdatePeer(p *wgtypes.PeerConfig) error {
	config := wgtypes.Config{
		Peers:        []wgtypes.PeerConfig{*p},
		ReplacePeers: false,
	}
	return apply(&config)
}

func apply(c *wgtypes.Config) error {
	wg, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer wg.Close()

	return wg.ConfigureDevice(ncutils.GetInterfaceName(), *c)
}

// returns if better endpoint has been calculated for this peer already
// if so sets it and returns true
func checkForBetterEndpoint(peer *wgtypes.PeerConfig) bool {
	if endpoint, ok := cache.EndpointCache.Load(fmt.Sprintf("%v", sha1.Sum([]byte(peer.PublicKey.String())))); ok {
		peer.Endpoint.IP = net.ParseIP(endpoint.(cache.EndpointCacheValue).Endpoint.String())
		return ok
	}
	return false
}
