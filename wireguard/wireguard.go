package wireguard

import (
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"
	"time"

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
	ifaceName := ncutils.GetInterfaceName()

	const maxRetries = 3
	for attempt := 0; attempt <= maxRetries; attempt++ {
		wg, err := wgctrl.New()
		if err != nil {
			if runtime.GOOS == "windows" && attempt < maxRetries && isDeviceBusyError(err) {
				slog.Warn("wgctrl busy, retrying", "attempt", attempt+1, "error", err)
				time.Sleep(time.Duration(500*(attempt+1)) * time.Millisecond)
				continue
			}
			return fmt.Errorf("wgctrl %w", err)
		}
		err = wg.ConfigureDevice(ifaceName, *c)
		wg.Close()
		if err == nil {
			return nil
		}
		if runtime.GOOS == "windows" && attempt < maxRetries && isDeviceBusyError(err) {
			slog.Warn("ConfigureDevice busy, retrying", "attempt", attempt+1, "error", err)
			time.Sleep(time.Duration(500*(attempt+1)) * time.Millisecond)
			continue
		}
		return err
	}
	return fmt.Errorf("ConfigureDevice failed after %d retries", maxRetries)
}

func isDeviceBusyError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "being used by another process") ||
		strings.Contains(msg, "access is denied") ||
		strings.Contains(msg, "The process cannot access the file")
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

// EndpointDetectedAlready - checks if better endpoint has been detected already
func EndpointDetectedAlready(peerPubKey string) bool {
	if endpoint, ok := cache.EndpointCache.Load(peerPubKey); ok && endpoint != nil {
		return true
	}
	return false
}

func GetPeersFromDevice(ifaceName string) (map[string]wgtypes.Peer, error) {
	wgMutex.Lock()
	defer wgMutex.Unlock()
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
	wgMutex.Lock()
	defer wgMutex.Unlock()
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

// GetDeviceListenPort returns the current listen port from the WireGuard device.
// Returns 0 and an error if the device cannot be queried.
func GetDeviceListenPort() (int, error) {
	wgMutex.Lock()
	defer wgMutex.Unlock()
	wg, err := wgctrl.New()
	if err != nil {
		return 0, err
	}
	defer wg.Close()
	dev, err := wg.Device(ncutils.GetInterfaceName())
	if err != nil {
		return 0, err
	}
	return dev.ListenPort, nil
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
