package wireguard

import (
	"fmt"

	"github.com/gravitl/netclient/cache"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"golang.org/x/exp/slog"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

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
