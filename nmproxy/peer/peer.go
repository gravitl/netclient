package peer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gravitl/netclient/nmproxy/config"
	"github.com/gravitl/netclient/nmproxy/models"
	"github.com/gravitl/netclient/nmproxy/packet"
	"github.com/gravitl/netclient/nmproxy/proxy"
	"github.com/gravitl/netclient/nmproxy/wg"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/metrics"
	nm_models "github.com/gravitl/netmaker/models"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// AddNew - adds new peer to proxy config and starts proxying the peer
func AddNew(server string, peer wgtypes.PeerConfig, peerConf nm_models.PeerConf,
	isRelayed bool, relayTo *net.UDPAddr) error {

	if peer.PersistentKeepaliveInterval == nil {
		d := nm_models.DefaultPersistentKeepaliveInterval
		peer.PersistentKeepaliveInterval = &d
	}
	c := models.Proxy{
		PeerPublicKey: peer.PublicKey,
		IsExtClient:   peerConf.IsExtClient,
		PeerConf:      peer,
		ListenPort:    int(peerConf.PublicListenPort),
		ProxyStatus:   peerConf.Proxy,
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

	logger.Log(0, "Starting proxy for Peer: ", peer.PublicKey.String())
	err = p.Start()
	if err != nil {
		return err
	}

	connConf := models.Conn{
		Mutex:           &sync.RWMutex{},
		Key:             peer.PublicKey,
		IsExtClient:     peerConf.IsExtClient,
		Config:          p.Config,
		StopConn:        p.Close,
		ResetConn:       p.Reset,
		LocalConn:       p.LocalConn,
		NetworkSettings: make(map[string]models.Settings),
		ServerMap:       make(map[string]struct{}),
	}
	connConf.ServerMap[server] = struct{}{}
	rPeer := models.RemotePeer{
		PeerKey:     peer.PublicKey.String(),
		IsExtClient: peerConf.IsExtClient,
		Endpoint:    peerEndpoint,
		LocalConn:   p.LocalConn,
	}
	if peerConf.Proxy || peerConf.IsExtClient {
		logger.Log(0, "-----> saving as proxy peer: ", connConf.Key.String())
		config.GetCfg().SavePeer(&connConf)
	} else {
		logger.Log(0, "-----> saving as no proxy peer: ", connConf.Key.String())
		config.GetCfg().SaveNoProxyPeer(&connConf)
	}
	config.GetCfg().SavePeerByHash(&rPeer)
	if peerConf.IsExtClient {
		config.GetCfg().SaveExtClientInfo(&rPeer)

	}
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
		} else {
			if peers[i].Endpoint == nil {
				continue
			}
			noProxyPeer, found := config.GetCfg().GetNoProxyPeer(peers[i].Endpoint.IP)
			if found {
				noProxyPeer.Mutex.RLock()
				peers[i].Endpoint = noProxyPeer.Config.LocalConnAddr
				noProxyPeer.Mutex.RUnlock()
			}
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
		if peerIDMap, ok := peerIDAndAddrMap[peer.PublicKey.String()]; ok {
			metric := metrics.GetMetric(server, peer.PublicKey.String())
			metric.NodeConnectionStatus = make(map[string]bool)
			connectionStatus := metrics.PeerConnectionStatus(peer.PublicKey.String())
			for peerID := range peerIDMap {
				metric.NodeConnectionStatus[peerID] = connectionStatus
			}
			metric.LastRecordedLatency = 999
			metric.TrafficRecieved = metric.TrafficRecieved + peer.ReceiveBytes
			metric.TrafficSent = metric.TrafficSent + peer.TransmitBytes
			metrics.UpdateMetric(server, peer.PublicKey.String(), &metric)
			pkt, err := packet.CreateMetricPacket(uuid.New().ID(), config.GetCfg().GetDevicePubKey(), peer.PublicKey)
			if err == nil {
				conn := config.GetCfg().GetServerConn()
				if conn != nil {
					_, err = conn.WriteToUDP(pkt, peer.Endpoint)
					if err != nil {
						logger.Log(1, "Failed to send to metric pkt: ", err.Error())
					}
				}

			}
		}

	}

}
