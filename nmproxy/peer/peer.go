package peer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/nmproxy/config"
	"github.com/gravitl/netclient/nmproxy/metrics"
	"github.com/gravitl/netclient/nmproxy/models"
	"github.com/gravitl/netclient/nmproxy/packet"
	"github.com/gravitl/netclient/nmproxy/proxy"
	"github.com/gravitl/netclient/nmproxy/wg"
	"github.com/gravitl/netmaker/logger"
	nm_models "github.com/gravitl/netmaker/models"
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
		ListenPort:          int(peerConf.PublicListenPort),
		ProxyStatus:         peerConf.Proxy,
	}
	p := proxy.New(c)
	peerPort := int(peerConf.PublicListenPort)
	if peerPort == 0 {
		peerPort = models.NmProxyPort
	}
	if peerConf.IsAttachedExtClient || !peerConf.Proxy {
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
	if peerConf.Proxy {
		logger.Log(0, "-----> saving as proxy peer: ", connConf.Key.String())
		config.GetCfg().SavePeer(network, &connConf)
	} else {
		logger.Log(0, "-----> saving as no proxy peer: ", connConf.Key.String())
		config.GetCfg().SaveNoProxyPeer(&connConf)
	}
	config.GetCfg().SavePeerByHash(&rPeer)
	if peerConf.IsAttachedExtClient {
		config.GetCfg().SaveExtClientInfo(&rPeer)
		//add rules to router
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

// StartMetricsCollectionForHostPeers - starts metrics collection when host proxy setting is off
func StartMetricsCollectionForHostPeers(ctx context.Context) {
	logger.Log(0, "Starting Metrics Thread...")
	ticker := time.NewTicker(time.Minute)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			allPeers := config.GetCfg().GetAllPeersConf()

			for network, peerMap := range allPeers {
				for peerKey, peer := range peerMap {
					go collectMetricsForPeer(network, peerKey, peer)
				}
			}

		}
	}
}

func collectMetricsForPeer(network, peerKey string, peerInfo nm_models.IDandAddr) {

	devPeer, err := wg.GetPeer(ncutils.GetInterfaceName(), peerKey)
	if err != nil {
		return
	}
	connectionStatus := metrics.PeerConnectionStatus(peerInfo.Address)
	metric := models.Metric{
		LastRecordedLatency: 999,
		ConnectionStatus:    connectionStatus,
	}
	metric.TrafficRecieved = float64(devPeer.ReceiveBytes) / (1 << 20) // collected in MB
	metric.TrafficSent = float64(devPeer.TransmitBytes) / (1 << 20)    // collected in MB
	metrics.UpdateMetric(network, peerKey, &metric)
	pkt, err := packet.CreateMetricPacket(uuid.New().ID(), network, config.GetCfg().GetDevicePubKey(), devPeer.PublicKey)
	if err == nil {
		conn := config.GetCfg().GetServerConn()
		if conn != nil {
			_, err = conn.WriteToUDP(pkt, devPeer.Endpoint)
			if err != nil {
				logger.Log(1, "Failed to send to metric pkt: ", err.Error())
			}
		}

	}
}
