package peer

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/gravitl/netclient/nmproxy/config"
	"github.com/gravitl/netclient/nmproxy/models"
	"github.com/gravitl/netclient/nmproxy/proxy"
	"github.com/gravitl/netmaker/logger"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// AddNew - adds new peer to proxy config and starts proxying the peer
func AddNew(network string, peer *wgtypes.PeerConfig, peerConf models.PeerConf,
	isRelayed bool, relayTo *net.UDPAddr) error {

	if peer.PersistentKeepaliveInterval == nil {
		d := models.DefaultPersistentKeepaliveInterval
		peer.PersistentKeepaliveInterval = &d
	}
	c := models.Proxy{
		LocalKey:            config.GetCfg().GetDevicePubKey(),
		RemoteKey:           peer.PublicKey,
		IsExtClient:         peerConf.IsExtClient,
		PeerConf:            peer,
		PersistentKeepalive: peer.PersistentKeepaliveInterval,
		Network:             network,
	}
	p := proxy.New(c)
	peerPort := int(peerConf.ProxyListenPort)
	if peerPort == 0 {
		peerPort = models.NmProxyPort
	}
	if peerConf.IsExtClient && peerConf.IsAttachedExtClient {
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
		IsAttachedExtClient: peerConf.IsAttachedExtClient,
		Config:              p.Config,
		StopConn:            p.Close,
		ResetConn:           p.Reset,
		LocalConn:           p.LocalConn,
	}
	rPeer := models.RemotePeer{
		Network:             network,
		Interface:           config.GetCfg().GetIface().Name,
		PeerKey:             peer.PublicKey.String(),
		IsExtClient:         peerConf.IsExtClient,
		Endpoint:            peerEndpoint,
		IsAttachedExtClient: peerConf.IsAttachedExtClient,
		LocalConn:           p.LocalConn,
	}
	config.GetCfg().SavePeer(network, &connConf)
	config.GetCfg().SavePeerByHash(&rPeer)

	if peerConf.IsAttachedExtClient {
		config.GetCfg().SaveExtClientInfo(&rPeer)
		//add rules to sniffer
		routingInfo := &config.Routing{
			InternalIP: peerConf.ExtInternalIp,
			ExternalIP: peerConf.Address,
		}
		config.GetCfg().SaveRoutingInfo(routingInfo)

	}
	return nil
}

// SetPeersEndpointToProxy - sets peer endpoints to local addresses connected to proxy
func SetPeersEndpointToProxy(network string, peers []wgtypes.PeerConfig) []wgtypes.PeerConfig {
	logger.Log(1, "Setting peers endpoints to proxy: ", network)
	if !config.GetCfg().ProxyStatus {
		return peers
	}
	for i := range peers {
		proxyPeer, found := config.GetCfg().GetPeer(network, peers[i].PublicKey.String())
		if found {
			proxyPeer.Mutex.RLock()
			peers[i].Endpoint = proxyPeer.Config.LocalConnAddr
			proxyPeer.Mutex.RUnlock()
		}
	}
	return peers
}
