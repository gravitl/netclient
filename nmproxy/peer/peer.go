package peer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/gravitl/netclient/nmproxy/config"
	"github.com/gravitl/netclient/nmproxy/models"
	"github.com/gravitl/netclient/nmproxy/proxy"
	"github.com/gravitl/netclient/nmproxy/wg"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/metrics"
	nm_models "github.com/gravitl/netmaker/models"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// AddNew - adds new peer to proxy config and starts proxying the peer
func AddNew(server string, peer wgtypes.PeerConfig, peerConf nm_models.PeerConf,
	isRelayed bool, relayTo *net.UDPAddr, usingTurn bool) error {

	if peer.PersistentKeepaliveInterval == nil {
		d := nm_models.DefaultPersistentKeepaliveInterval
		peer.PersistentKeepaliveInterval = &d
	}
	c := models.Proxy{
		PeerPublicKey:   peer.PublicKey,
		IsExtClient:     peerConf.IsExtClient,
		PeerConf:        peer,
		ListenPort:      int(peerConf.PublicListenPort),
		ProxyListenPort: peerConf.ProxyListenPort,
		ProxyStatus:     peerConf.Proxy || isRelayed,
		UsingTurn:       usingTurn,
	}
	p := proxy.New(c)
	peerPort := int(peerConf.PublicListenPort)
	if peerPort == 0 {
		peerPort = models.NmProxyPort
	}
	if peerConf.IsExtClient || !peerConf.Proxy {
		peerPort = peer.Endpoint.Port

	}
	peerEndpointIP := peer.Endpoint.IP
	if isRelayed || usingTurn {
		//go server.NmProxyServer.KeepAlive(peer.Endpoint.IP.String(), common.NmProxyPort)
		if relayTo == nil {
			return errors.New("relay endpoint is nil")
		}
		peerEndpointIP = relayTo.IP
		peerPort = relayTo.Port
	}

	peerEndpoint, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", peerEndpointIP, peerPort))
	if err != nil {
		return err
	}
	p.Config.PeerEndpoint = peerEndpoint
	if t := config.GetCfg().GetTurnCfg(); t != nil && t.TurnConn != nil {
		t.Mutex.RLock()
		p.Config.TurnConn = t.TurnConn
		t.Mutex.RUnlock()
	} else {
		p.Config.UsingTurn = false
	}
	logger.Log(0, "Starting proxy for Peer: ", peer.PublicKey.String())
	err = p.Start()
	if err != nil {
		return err
	}

	connConf := models.Conn{
		Mutex:           &sync.RWMutex{},
		Key:             peer.PublicKey,
		Config:          p.Config,
		StopConn:        p.Close,
		ResetConn:       p.Reset,
		LocalConn:       p.LocalConn,
		IsRelayed:       isRelayed,
		RelayedEndpoint: relayTo,
		NetworkSettings: make(map[string]models.Settings),
		ServerMap:       make(map[string]struct{}),
	}
	connConf.ServerMap[server] = struct{}{}
	rPeer := models.RemotePeer{
		PeerKey:   peer.PublicKey.String(),
		Endpoint:  peerEndpoint,
		LocalConn: p.LocalConn,
	}

	logger.Log(1, "-----> saving as proxy peer: ", connConf.Key.String())
	config.GetCfg().SavePeer(&connConf)
	config.GetCfg().SavePeerByHash(&rPeer)
	return nil
}

// SetPeersEndpointToProxy - sets peer endpoints to local addresses connected to proxy
func SetPeersEndpointToProxy(peers []wgtypes.PeerConfig) []wgtypes.PeerConfig {
	logger.Log(1, "Setting peers endpoints to proxy...")
	for i := range peers {
		proxyPeer, found := config.GetCfg().GetPeer(peers[i].PublicKey.String())
		if found {
			proxyPeer.Mutex.RLock()
			peers[i].Endpoint = proxyPeer.Config.LocalConnAddr
			proxyPeer.Mutex.RUnlock()
		}
	}
	return peers
}

// StartMetricsCollectionForHostPeers - starts metrics collection when host proxy setting is off
func StartMetricsCollectionForHostPeers(ctx context.Context) {
	logger.Log(1, "Starting Metrics Thread...")
	ticker := time.NewTicker(metrics.MetricCollectionInterval)
	for {
		select {
		case <-ctx.Done():
			logger.Log(1, "Stopping metrics collection...")
			return
		case <-ticker.C:

			peersServerMap := config.GetCfg().GetAllPeersIDsAndAddrs()
			for server, peerMap := range peersServerMap {
				go collectMetricsForServerPeers(server, peerMap)
			}

		}
	}
}

func collectMetricsForServerPeers(server string, peerIDAndAddrMap nm_models.HostPeerMap) {

	ifacePeers, err := wg.GetPeers(config.GetCfg().GetIface().Name)
	if err != nil {
		return
	}
	for _, peer := range ifacePeers {
		if _, ok := peerIDAndAddrMap[peer.PublicKey.String()]; ok {
			metric := metrics.GetMetric(server, peer.PublicKey.String())
			metric.NodeConnectionStatus = make(map[string]bool)
			if peer.Endpoint == nil {
				continue
			}
			metric.LastRecordedLatency = 999
			metric.TrafficRecieved = metric.TrafficRecieved + peer.ReceiveBytes
			metric.TrafficSent = metric.TrafficSent + peer.TransmitBytes
			metrics.UpdateMetric(server, peer.PublicKey.String(), &metric)
		}
	}
}

func ResetPeers() {
	logger.Log(1, "cleaning up proxy peer connections")
	peerConnMap := config.GetCfg().GetAllProxyPeers()
	for _, peerI := range peerConnMap {
		config.GetCfg().RemovePeer(peerI.Key.String())
		config.GetCfg().GetIface().UpdatePeerEndpoint(peerI.Config.PeerConf)
	}
}
