package peer

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/gravitl/netclient/nm-proxy/config"
	"github.com/gravitl/netclient/nm-proxy/models"
	"github.com/gravitl/netclient/nm-proxy/proxy"
	"github.com/gravitl/netclient/nm-proxy/wg"
	"github.com/gravitl/netmaker/logger"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// AddNewPeer - adds new peer to proxy config and starts proxying the peer
func AddNewPeer(wgInterface *wg.WGIface, network string, peer *wgtypes.PeerConfig, peerAddr string,
	isRelayed, isExtClient, isAttachedExtClient bool, relayTo *net.UDPAddr) error {
	if peer.PersistentKeepaliveInterval == nil {
		d := time.Second * 25
		peer.PersistentKeepaliveInterval = &d
	}
	c := models.ProxyConfig{
		LocalKey:            wgInterface.Device.PublicKey,
		RemoteKey:           peer.PublicKey,
		WgInterface:         wgInterface,
		IsExtClient:         isExtClient,
		PeerConf:            peer,
		PersistentKeepalive: peer.PersistentKeepaliveInterval,
		Network:             network,
	}
	p := proxy.NewProxy(c)
	peerPort := models.NmProxyPort
	if isExtClient && isAttachedExtClient {
		peerPort = peer.Endpoint.Port

	}
	peerEndpointIP := peer.Endpoint.IP
	if isRelayed {
		//go server.NmProxyServer.KeepAlive(peer.Endpoint.IP.String(), common.NmProxyPort)
		if relayTo == nil {
			return errors.New("relay endpoint is nil")
		}
		peerEndpointIP = relayTo.IP
	}
	peerEndpoint, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", peerEndpointIP, peerPort))
	if err != nil {
		return err
	}
	p.Config.PeerEndpoint = peerEndpoint

	logger.Log(0, "Starting proxy for Peer: %s\n", peer.PublicKey.String())
	err = p.Start()
	if err != nil {
		return err
	}

	connConf := models.Conn{
		Mutex:               &sync.RWMutex{},
		Key:                 peer.PublicKey,
		IsRelayed:           isRelayed,
		RelayedEndpoint:     relayTo,
		IsAttachedExtClient: isAttachedExtClient,
		Config:              p.Config,
		StopConn:            p.Close,
		ResetConn:           p.Reset,
		LocalConn:           p.LocalConn,
	}
	rPeer := models.RemotePeer{
		Network:             network,
		Interface:           wgInterface.Name,
		PeerKey:             peer.PublicKey.String(),
		IsExtClient:         isExtClient,
		Endpoint:            peerEndpoint,
		IsAttachedExtClient: isAttachedExtClient,
		LocalConn:           p.LocalConn,
	}
	config.GetGlobalCfg().SavePeer(network, &connConf)
	config.GetGlobalCfg().SavePeerByHash(&rPeer)

	if isAttachedExtClient {
		config.GetGlobalCfg().SaveExtClientInfo(&rPeer)
	}
	return nil
}

// SetPeersEndpointToProxy - sets peer endpoints to local addresses connected to proxy
func SetPeersEndpointToProxy(network string, peers []wgtypes.PeerConfig) []wgtypes.PeerConfig {
	logger.Log(1, "Setting peers endpoints to proxy: ", network)
	if !config.GetGlobalCfg().ProxyStatus {
		return peers
	}
	for i := range peers {
		proxyPeer, found := config.GetGlobalCfg().GetPeer(network, peers[i].PublicKey.String())
		if found {
			proxyPeer.Mutex.RLock()
			peers[i].Endpoint = proxyPeer.Config.LocalConnAddr
			proxyPeer.Mutex.RUnlock()
		}
	}
	return peers
}
