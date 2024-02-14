package wireguard

import (
	"fmt"
	"net"
	"strings"

	"github.com/gravitl/netclient/cache"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/stun"
	"github.com/gravitl/netmaker/logger"
	"golang.org/x/exp/slog"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// ShouldReplace - checks curr peers and incoming peers to see if the peers should be replaced
func ShouldReplace(incomingPeers []wgtypes.PeerConfig) bool {
	hostPeers := config.Netclient().HostPeers
	if len(incomingPeers) != len(hostPeers) {
		return true
	}

	hostpeerMap := make(map[string]struct{})
	for _, hostPeer := range hostPeers {
		hostpeerMap[hostPeer.PublicKey.String()] = struct{}{}
	}
	incomingPeerMap := make(map[string]struct{})
	for _, peer := range incomingPeers {
		incomingPeerMap[peer.PublicKey.String()] = struct{}{}
		if _, ok := hostpeerMap[peer.PublicKey.String()]; !ok {
			return true
		}
	}
	for _, hostPeer := range hostPeers {
		if _, ok := incomingPeerMap[hostPeer.PublicKey.String()]; !ok {
			return true
		}
	}
	return false
}

// SetPeers - sets peers on netmaker WireGuard interface
func SetPeers(replace bool) error {

	peers := config.Netclient().HostPeers
	for i := range peers {
		peer := peers[i]
		if peer.Endpoint != nil && peer.Endpoint.IP == nil {
			peers[i].Endpoint = nil
		}
		if !peer.Remove && checkForBetterEndpoint(&peer) {
			peers[i] = peer
		}
	}
	GetInterface().Config.Peers = peers
	// on freebsd, calling wgcltl.Client.ConfigureDevice() with []Peers{} causes an ioctl error --> ioctl: bad address
	if len(peers) == 0 {
		peers = nil
	}
	config := wgtypes.Config{
		ReplacePeers: replace,
		Peers:        peers,
	}
	return apply(&config)
}

// == private ==

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
	slog.Debug("applying wireguard config")
	wg, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("wgctrl %w", err)
	}
	defer wg.Close()

	return wg.ConfigureDevice(ncutils.GetInterfaceName(), *c)
}

// returns if better endpoint has been calculated for this peer already
// if so sets it and returns true
func checkForBetterEndpoint(peer *wgtypes.PeerConfig) bool {
	if endpoint, ok := cache.EndpointCache.Load(peer.PublicKey.String()); ok && endpoint != nil {
		var cacheEndpoint cache.EndpointCacheValue
		cacheEndpoint, ok = endpoint.(cache.EndpointCacheValue)
		if ok {
			peer.Endpoint = cacheEndpoint.Endpoint
		}
		return ok
	}
	return false
}

// EndpointDetectedAlready - checks if better endpoint has been detected already
func EndpointDetectedAlready(peerPubKey string) bool {
	if endpoint, ok := cache.EndpointCache.Load(peerPubKey); ok && endpoint != nil {
		return true
	}
	return false
}

// GetPeer - gets the peerinfo from the wg interface
func GetPeer(ifaceName, peerPubKey string) (wgtypes.Peer, error) {
	wg, err := wgctrl.New()
	if err != nil {
		return wgtypes.Peer{}, err
	}
	defer func() {
		err = wg.Close()
		if err != nil {
			logger.Log(0, "got error while closing wgctl: ", err.Error())
		}
	}()
	wgDevice, err := wg.Device(ifaceName)
	if err != nil {
		return wgtypes.Peer{}, err
	}
	for _, peer := range wgDevice.Peers {
		if peer.PublicKey.String() == peerPubKey {
			return peer, nil
		}
	}
	return wgtypes.Peer{}, fmt.Errorf("peer not found")
}

// getDefaultGatewayIpFromRouteList - an internal function to get the default gateway ip from route list string
func getDefaultGatewayIpFromRouteList(output string) string {

	var rList []string
	if strings.Contains(output, "\r") {
		rList = strings.Split(output, "\r")
	} else if strings.Contains(output, "\n") {
		rList = strings.Split(output, "\n")
	}

	var rLine string
	for _, l := range rList {
		if strings.Contains(l, "0.0.0.0") {
			rLine = l
			if strings.Contains(l, ncutils.GetInterfaceName()) {
				break
			}
		}
	}

	rLineList := strings.Fields(rLine)

	return strings.TrimSpace(rLineList[len(rLineList)-1])
}

// GetOriginalDefaulGw - fetches system's original default gw
func GetOriginalDefaulGw() (link int, gwIP net.IP, err error) {
	link = config.Netclient().OriginalDefaultGatewayIfLink
	gwIP = config.Netclient().OriginalDefaultGatewayIp
	if link == 0 || gwIP.String() == "" {
		link, gwIP, err = GetDefaultGatewayIp()
	}
	return
}

// GetIPNetfromIp - converts ip into ipnet based network class
func GetIPNetfromIp(ip net.IP) (ipCidr *net.IPNet) {
	if ipv4 := ip.To4(); ipv4 != nil {
		_, ipCidr, _ = net.ParseCIDR(fmt.Sprintf("%s/32", ipv4.String()))

	} else {
		_, ipCidr, _ = net.ParseCIDR(fmt.Sprintf("%s/128", ipv4.String()))
	}
	return
}

func GetServerAddressesDefaultGw(server *config.Server) (addrs []net.IPNet) {
	if server == nil {
		return
	}
	ips, _ := net.LookupIP(server.Name) // handle server base domain
	for _, ip := range ips {
		ipnet := GetIPNetfromIp(ip)
		if ipnet != nil {
			addrs = append(addrs, *ipnet)
		}
	}

	ips, _ = net.LookupIP(server.API) // handle server api
	for _, ip := range ips {
		ipnet := GetIPNetfromIp(ip)
		if ipnet != nil {
			addrs = append(addrs, *ipnet)
		}
	}

	broker := server.Broker
	brokerParts := strings.Split(broker, "//")
	if len(brokerParts) > 1 {
		broker = brokerParts[1]
	}

	ips, _ = net.LookupIP(broker) // handle server broker
	for _, ip := range ips {
		ipnet := GetIPNetfromIp(ip)
		if ipnet != nil {
			addrs = append(addrs, *ipnet)
		}
	}

	stunList := stun.StunServers
	for i := range stunList {
		stunServer := stunList[i]
		ips, err := net.LookupIP(stunServer.Domain) // handle server broker
		if err != nil {
			continue
		}
		for _, ip := range ips {
			ipnet := GetIPNetfromIp(ip)
			if ipnet != nil {
				addrs = append(addrs, *ipnet)
			}
		}
	}
	return
}
