package wireguard

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/gravitl/netclient/cache"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"golang.org/x/exp/slog"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	IPv4Network = "0.0.0.0/0"
	IPv6Network = "::/0"
)

// FindInternetGwPeer picks the WireGuard peer that should carry internet-exit
// traffic. Prefers a peer advertising 0.0.0.0/0 or ::/0; falls back to a peer
// that includes the overlay nexthop. Skips Remove peers.
func FindInternetGwPeer(peers []wgtypes.PeerConfig, gw4, gw6 net.IP) (wgtypes.PeerConfig, bool) {
	var byNexthop wgtypes.PeerConfig
	foundNexthop := false
	for _, peer := range peers {
		if peer.Remove {
			continue
		}
		for _, peerIP := range peer.AllowedIPs {
			s := peerIP.String()
			if s == IPv4Network || s == IPv6Network {
				return peer, true
			}
			if foundNexthop {
				continue
			}
			if len(gw4) > 0 && peerIP.Contains(gw4) {
				byNexthop = peer
				foundNexthop = true
			} else if len(gw6) > 0 && peerIP.Contains(gw6) {
				byNexthop = peer
				foundNexthop = true
			}
		}
	}
	return byNexthop, foundNexthop
}

// IsZeroWGPublicKey reports whether publicKey is empty or the all-zero WireGuard key.
func IsZeroWGPublicKey(publicKey string) bool {
	if publicKey == "" {
		return true
	}
	k, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		return true
	}
	var zero wgtypes.Key
	return k == zero
}

// NormalizeIGWNexthops splits DefaultGwIp / DefaultGwIp6 into family-correct nexthops.
// Legacy servers may place an IPv6 address in DefaultGwIp when the client has no EndpointIP.
func NormalizeIGWNexthops(gwIP, gwIP6 net.IP) (gw4, gw6 net.IP) {
	gw4, gw6 = gwIP, gwIP6
	if len(gw4) > 0 && gw4.To4() == nil {
		if len(gw6) == 0 {
			gw6 = gw4
		}
		gw4 = nil
	}
	if len(gw6) > 0 && gw6.To4() != nil {
		gw6 = nil
	}
	if len(gw4) == 0 {
		gw4 = nil
	}
	if len(gw6) == 0 {
		gw6 = nil
	}
	return gw4, gw6
}

var ErrPeerNotFound = fmt.Errorf("peer not found")

// InternetGwHostIPs returns underlay IPs that must stay reachable via the
// original LAN path when 0.0.0.0/0 is moved onto WireGuard (exit-node client).
// Without an OS pin, underlay traffic to the exit peer (UDP handshake and/or
// TCP uplink TLS) is routed into the tunnel and breaks. Collects HostPeers,
// endpoint cache, live GetPeer, and any TCP-proxy host IPs registered by the
// uplink client.
func InternetGwHostIPs(publicKey string) []net.IP {
	seen := make(map[string]struct{})
	var ips []net.IP
	add := func(ip net.IP) {
		if len(ip) == 0 || ip.IsUnspecified() {
			return
		}
		// net.IP.String() returns "<nil>" for some empty values; never pin that.
		s := ip.String()
		if s == "" || s == "<nil>" {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		ips = append(ips, append(net.IP(nil), ip...))
	}

	if pk, err := wgtypes.ParseKey(publicKey); err == nil {
		if host := config.Netclient(); host != nil {
			for _, p := range host.HostPeers {
				if p.PublicKey != pk || p.Endpoint == nil {
					continue
				}
				add(p.Endpoint.IP)
			}
		}
	}
	// When TCP uplink is active, ignore private live/cache endpoints from
	// detection — divert and underlay pins must stay on HostPeers / TCP-proxy.
	tcpActive := activeRelayTCPUplink() != nil
	if peer, err := GetPeer(ncutils.GetInterfaceName(), publicKey); err == nil && peer.Endpoint != nil {
		if !tcpActive || !peer.Endpoint.IP.IsPrivate() {
			add(peer.Endpoint.IP)
		}
	}
	if ep, ok := GetBetterEndpoint(publicKey); ok && ep != nil {
		if !tcpActive || !ep.IP.IsPrivate() {
			add(ep.IP)
		}
	}
	tcpUplinkHostIPsMu.Lock()
	for _, ip := range tcpUplinkHostIPs {
		add(ip)
	}
	tcpUplinkHostIPsMu.Unlock()
	return ips
}

var (
	tcpUplinkHostIPsMu sync.Mutex
	tcpUplinkHostIPs   []net.IP
)

// SetTCPUplinkHostRouteIPs registers underlay IPs of the TCP proxy endpoint so
// Windows/Linux exit-node setup can pin them via the LAN gateway before
// 0.0.0.0/0 moves onto netmaker. Pass nil/empty to clear.
func SetTCPUplinkHostRouteIPs(ips []net.IP) {
	tcpUplinkHostIPsMu.Lock()
	defer tcpUplinkHostIPsMu.Unlock()
	if len(ips) == 0 {
		tcpUplinkHostIPs = nil
		return
	}
	cp := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if len(ip) == 0 || ip.IsUnspecified() || ip.String() == "<nil>" {
			continue
		}
		cp = append(cp, append(net.IP(nil), ip...))
	}
	tcpUplinkHostIPs = cp
}

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
	wgMutex.Lock()
	defer wgMutex.Unlock()
	peers := config.Netclient().HostPeers
	server := config.GetServer(config.CurrServer)
	if server == nil {
		return errors.New("server config not found")
	}
	data := getHAEgressDataForProcessing(server.MetricsPort)
	for i := range peers {
		peer := peers[i]
		if peer.Endpoint != nil && peer.Endpoint.IP == nil {
			peers[i].Endpoint = nil
		}
		if !peer.Remove && checkForBetterEndpoint(&peer) {
			peers[i] = peer
		}
		// set egress routes on correct peer
		if !peer.Remove && checkIfEgressHAPeer(&peer, data) {
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
	if peer == nil {
		return false
	}
	if ShouldSkipEndpointDetection(peer.PublicKey.String()) {
		return false
	}
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

func GetBetterEndpoint(peerKey string) (*net.UDPAddr, bool) {
	if endpoint, ok := cache.EndpointCache.Load(peerKey); ok && endpoint != nil {
		var cacheEndpoint cache.EndpointCacheValue
		cacheEndpoint, ok = endpoint.(cache.EndpointCacheValue)
		if ok {
			return cacheEndpoint.Endpoint, ok
		}
	}
	return nil, false
}

// RestoreHostPeerEndpoint resets the live WG peer endpoint to the given
// host:port (typically the server-published HostPeers underlay address) so
// TCP-uplink divert keys stay aligned after endpoint detection.
func RestoreHostPeerEndpoint(endpoint string) {
	if endpoint == "" {
		return
	}
	udpAddr, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil || udpAddr == nil || udpAddr.IP == nil {
		return
	}
	host := config.Netclient()
	if host == nil {
		return
	}
	for _, p := range host.HostPeers {
		if p.Remove || p.Endpoint == nil || p.Endpoint.String() != endpoint {
			continue
		}
		_ = UpdatePeer(&wgtypes.PeerConfig{
			PublicKey:                   p.PublicKey,
			Endpoint:                    udpAddr,
			AllowedIPs:                  p.AllowedIPs,
			PersistentKeepaliveInterval: p.PersistentKeepaliveInterval,
			ReplaceAllowedIPs:           true,
			UpdateOnly:                  true,
		})
		cache.EndpointCache.Delete(p.PublicKey.String())
		return
	}
}

// EndpointDetectedAlready - checks if better endpoint has been detected already
func EndpointDetectedAlready(peerPubKey string) bool {
	if endpoint, ok := cache.EndpointCache.Load(peerPubKey); ok && endpoint != nil {
		return true
	}
	return false
}

// ShouldSkipEndpointDetection returns true for peers that must keep their
// server-published underlay endpoint: internet-exit peers (0.0.0.0/0 / ::/0)
// and the active TCP-uplink relay. Endpoint detection often picks private
// 10.x addresses that break TCP divert and blackhole UDP after IGW install.
func ShouldSkipEndpointDetection(peerPubKey string) bool {
	if peerPubKey == "" {
		return false
	}
	host := config.Netclient()
	if host == nil {
		return false
	}
	pk, err := wgtypes.ParseKey(peerPubKey)
	if err != nil {
		return false
	}
	for _, p := range host.HostPeers {
		if p.PublicKey != pk || p.Remove {
			continue
		}
		for _, a := range p.AllowedIPs {
			s := a.String()
			if s == IPv4Network || s == IPv6Network {
				return true
			}
		}
	}
	if ep := clientRelayEndpoint(); ep != "" {
		for _, p := range host.HostPeers {
			if p.PublicKey == pk && p.Endpoint != nil && p.Endpoint.String() == ep {
				return true
			}
		}
	}
	return false
}

func GetPeersFromDevice(ifaceName string) (map[string]wgtypes.Peer, error) {
	peerMap := make(map[string]wgtypes.Peer)
	wg, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	defer func() {
		err = wg.Close()
		if err != nil {
			logger.Log(0, "got error while closing wgctl: ", err.Error())
		}
	}()
	wgDevice, err := wg.Device(ifaceName)
	if err != nil {
		return nil, err
	}
	for _, peer := range wgDevice.Peers {
		peerMap[peer.PublicKey.String()] = peer
	}
	return peerMap, nil
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
	return wgtypes.Peer{}, ErrPeerNotFound
}

// GetOriginalDefaulGw - fetches system's original default gw
func GetOriginalDefaulGw() (gwIP net.IP, err error) {
	gwIP = config.Netclient().OriginalDefaultGatewayIp
	if gwIP.String() == "" {
		gwIP, err = GetDefaultGatewayIp()
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
