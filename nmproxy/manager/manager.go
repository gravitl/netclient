package manager

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/nmproxy/config"
	"github.com/gravitl/netclient/nmproxy/models"
	peerpkg "github.com/gravitl/netclient/nmproxy/peer"
	"github.com/gravitl/netclient/nmproxy/router"
	"github.com/gravitl/netclient/nmproxy/wg"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/logger"
	nm_models "github.com/gravitl/netmaker/models"
)

type proxyPayload nm_models.ProxyManagerPayload

func getRecieverType(m *nm_models.ProxyManagerPayload) *proxyPayload {
	mI := proxyPayload(*m)
	return &mI
}

// Start - starts the proxy manager loop and listens for events on the Channel provided
func Start(ctx context.Context, managerChan chan *nm_models.HostPeerUpdate) {
	for {
		select {
		case <-ctx.Done():
			logger.Log(0, "shutting down proxy manager...")
			return
		case mI := <-managerChan:
			if mI == nil {
				continue
			}
			logger.Log(3, fmt.Sprintf("-------> PROXY-MANAGER: %+v\n", mI.ProxyUpdate))
			err := configureProxy(mI)
			if err != nil {
				logger.Log(1, "failed to configure proxy:  ", err.Error())
			}
		}
	}
}

// configureProxy - confgures proxy by payload action
func configureProxy(payload *nm_models.HostPeerUpdate) error {
	var err error
	m := getRecieverType(&payload.ProxyUpdate)
	m.InterfaceName = ncutils.GetInterfaceName()
	m.Peers = payload.Peers
	wgIface, err := wg.GetWgIface(m.InterfaceName)
	if err != nil {
		logger.Log(1, "Failed get interface config: ", err.Error())
		return err
	}

	// sync map with wg device config
	// check if listen port has changed
	if !config.GetCfg().IsIfaceNil() && wgIface.Device.ListenPort != config.GetCfg().GetInterfaceListenPort() {
		// reset proxy
		cleanUpInterface()
		return nil
	}
	config.GetCfg().SetIface(wgIface)
	config.GetCfg().SetPeersIDsAndAddrs(m.Server, payload.HostPeerIDs)
	startMetricsThread(payload) // starts or stops the metrics collection based on host proxy setting
	fwUpdate(payload)
	switch m.Action {
	case nm_models.ProxyUpdate, nm_models.NoProxy:
		m.peerUpdate()
	case nm_models.ProxyDeleteAllPeers:
		cleanUpInterface()

	}
	return err
}

func fwUpdate(payload *nm_models.HostPeerUpdate) {
	isIngressGw := len(payload.IngressInfo.ExtPeers) > 0
	isEgressGw := len(payload.EgressInfo) > 0
	if isIngressGw || isEgressGw {
		if !config.GetCfg().GetFwStatus() {

			fwClose, err := router.Init()
			if err != nil {
				logger.Log(0, "failed to intialize firewall: ", err.Error())
				return
			}
			config.GetCfg().SetFwStatus(true)
			config.GetCfg().SetFwCloseFunc(fwClose)

		} else {
			logger.Log(0, "firewall controller is intialized already")
		}

	}
	config.GetCfg().SetIngressGwStatus(payload.Server, isIngressGw)
	config.GetCfg().SetEgressGwStatus(payload.Server, isEgressGw)

	if isIngressGw {
		router.SetIngressRoutes(payload.Server, payload.IngressInfo)
	}
	if isEgressGw {
		router.SetEgressRoutes(payload.Server, payload.EgressInfo)
	}
	if config.GetCfg().GetFwStatus() && !isIngressGw {
		router.DeleteIngressRules(payload.Server)
	}
	if config.GetCfg().GetFwStatus() && !isEgressGw {
		router.DeleteEgressGwRoutes(payload.Server)
	}

}

func startMetricsThread(peerUpdate *nm_models.HostPeerUpdate) {
	if !config.GetCfg().GetMetricsCollectionStatus() {
		ctx, cancel := context.WithCancel(context.Background())
		go peerpkg.StartMetricsCollectionForHostPeers(ctx)
		config.GetCfg().SetMetricsThreadCtx(cancel)
	}
}

// settingsUpdate - updates the host settings in the config
func (m *proxyPayload) settingsUpdate(server string) (reset bool) {
	if !m.IsRelay && config.GetCfg().IsRelay(server) {
		config.GetCfg().DeleteRelayedPeers()
	}

	config.GetCfg().SetRelayStatus(server, m.IsRelay)
	config.GetCfg().SetIngressGwStatus(server, m.IsIngress)
	if config.GetCfg().GetRelayedStatus(server) != m.IsRelayed {
		reset = true
	}
	config.GetCfg().SetRelayedStatus(server, m.IsRelayed)
	if m.IsRelay {
		m.setRelayedPeers()
	}
	return
}

// ProxyManagerPayload.setRelayedPeers - processes the payload for the relayed peers
func (m *proxyPayload) setRelayedPeers() {
	c := config.GetCfg()
	for relayedNodePubKey, relayedNodeConf := range m.RelayedPeerConf {
		for _, peer := range relayedNodeConf.Peers {
			if peer.Endpoint != nil {
				peer.Endpoint.Port = m.PeerMap[peer.PublicKey.String()].ProxyListenPort
				rPeer := models.RemotePeer{
					PeerKey:  peer.PublicKey.String(),
					Endpoint: peer.Endpoint,
				}
				c.SaveRelayedPeer(relayedNodePubKey, &rPeer)
			}

		}
		relayedNodeConf.RelayedPeerEndpoint.Port = m.PeerMap[relayedNodePubKey].ProxyListenPort
		relayedNode := models.RemotePeer{
			PeerKey:  relayedNodePubKey,
			Endpoint: relayedNodeConf.RelayedPeerEndpoint,
		}
		c.SaveRelayedPeer(relayedNodePubKey, &relayedNode)

	}
}

func cleanUpInterface() {
	logger.Log(1, "cleaning up proxy peer connections")
	peerConnMap := config.GetCfg().GetAllProxyPeers()
	for _, peerI := range peerConnMap {
		config.GetCfg().RemovePeer(peerI.Key.String())
		wireguard.UpdatePeer(&peerI.Config.PeerConf)
	}

}

// ProxyManagerPayload.processPayload - updates the peers and config with the recieved payload
func (m *proxyPayload) processPayload() error {
	if m.InterfaceName == "" {
		return errors.New("interface cannot be empty")
	}
	if len(m.Peers) == 0 {
		return errors.New("no peers to add")
	}
	gCfg := config.GetCfg()

	reset := m.settingsUpdate(m.Server)
	if reset {
		cleanUpInterface()
		return nil
	}

	peerConnMap := gCfg.GetAllProxyPeers()
	// check device conf different from proxy
	// sync peer map with new update
	for i := len(m.Peers) - 1; i >= 0; i-- {
		if m.Peers[i].Remove {
			if peerConn, ok := gCfg.GetPeer(m.Peers[i].PublicKey.String()); ok {
				_, found := peerConn.ServerMap[m.Server]
				if !found {
					continue
				} else {
					delete(peerConn.ServerMap, m.Server)
					peerConnMap[m.Peers[i].PublicKey.String()] = &peerConn
					if len(peerConn.ServerMap) > 0 {
						continue
					}
				}
				gCfg.DeletePeerHash(peerConn.Key.String())
				gCfg.RemovePeer(peerConn.Key.String())
			}

			continue
		}

		if currentPeer, ok := peerConnMap[m.Peers[i].PublicKey.String()]; ok {
			currentPeer.Mutex.Lock()
			// check if proxy is not required for the peer anymore
			if (m.Action == nm_models.NoProxy) && !m.PeerMap[m.Peers[i].PublicKey.String()].IsRelayed {
				// cleanup proxy connections for the peer
				currentPeer.StopConn()
				delete(peerConnMap, currentPeer.Key.String())
				wireguard.UpdatePeer(&m.Peers[i])
				currentPeer.Mutex.Unlock()
				m.Peers = append(m.Peers[:i], m.Peers[i+1:]...)
				continue
			}
			if !m.IsRelayed && (m.Action == nm_models.ProxyUpdate) && !m.PeerMap[m.Peers[i].PublicKey.String()].Proxy {
				// cleanup proxy connections for the peer
				currentPeer.StopConn()
				delete(peerConnMap, currentPeer.Key.String())
				wireguard.UpdatePeer(&m.Peers[i])
				currentPeer.Mutex.Unlock()
				m.Peers = append(m.Peers[:i], m.Peers[i+1:]...)
				continue
			}
			// check if peer is not connected to proxy
			devPeer, err := wg.GetPeer(m.InterfaceName, currentPeer.Key.String())
			if err == nil {
				logger.Log(3, fmt.Sprintf("---------> comparing peer endpoint: onDevice: %s, Proxy: %s", devPeer.Endpoint.String(),
					currentPeer.Config.LocalConnAddr.String()))
				if devPeer.Endpoint != nil && devPeer.Endpoint.String() != currentPeer.Config.LocalConnAddr.String() {
					logger.Log(1, "---------> endpoint is not set to proxy: ", currentPeer.Key.String())
					currentPeer.StopConn()
					currentPeer.Mutex.Unlock()
					delete(peerConnMap, currentPeer.Key.String())
					continue
				}
			}

			//check if peer is being relayed
			if !m.IsRelayed && !config.GetCfg().IsGlobalRelay() && currentPeer.IsRelayed != m.PeerMap[m.Peers[i].PublicKey.String()].IsRelayed {
				logger.Log(1, "---------> peer relay status has been changed: ", currentPeer.Key.String())
				currentPeer.StopConn()
				currentPeer.Mutex.Unlock()
				delete(peerConnMap, currentPeer.Key.String())
				continue
			}

			// check if relay endpoint has been changed
			if !m.IsRelayed && !config.GetCfg().IsGlobalRelay() && currentPeer.RelayedEndpoint != nil &&
				m.PeerMap[m.Peers[i].PublicKey.String()].RelayedTo != nil &&
				currentPeer.RelayedEndpoint.String() != m.PeerMap[m.Peers[i].PublicKey.String()].RelayedTo.String() {
				logger.Log(1, "---------> peer relay endpoint has been changed: ", currentPeer.Key.String())
				currentPeer.StopConn()
				currentPeer.Mutex.Unlock()
				delete(peerConnMap, currentPeer.Key.String())
				continue
			}

			// check if proxy listen port has changed for the peer
			if (currentPeer.Config.ListenPort != int(m.PeerMap[m.Peers[i].PublicKey.String()].PublicListenPort) &&
				m.PeerMap[m.Peers[i].PublicKey.String()].PublicListenPort != 0) ||
				(m.PeerMap[m.Peers[i].PublicKey.String()].ProxyListenPort != currentPeer.Config.ProxyListenPort &&
					m.PeerMap[m.Peers[i].PublicKey.String()].ProxyListenPort != 0) {
				// listen port has been changed, reset conn
				logger.Log(1, "--------> peer proxy listen port has been changed", currentPeer.Key.String())
				currentPeer.StopConn()
				currentPeer.Mutex.Unlock()
				delete(peerConnMap, currentPeer.Key.String())
				continue
			}

			if m.Peers[i].Endpoint != nil && currentPeer.Config.PeerConf.Endpoint.IP.String() != m.Peers[i].Endpoint.IP.String() {
				logger.Log(1, fmt.Sprintf("----> Peer Endpoint has changed from %s to %s",
					currentPeer.Config.PeerConf.Endpoint.String(), m.Peers[i].Endpoint.String()))
				logger.Log(1, "----------> Resetting proxy for Peer: ", currentPeer.Key.String())
				currentPeer.StopConn()
				currentPeer.Mutex.Unlock()
				delete(peerConnMap, currentPeer.Key.String())
				continue

			}
			if !config.GetCfg().IsGlobalRelay() && !currentPeer.IsRelayed && m.Peers[i].Endpoint != nil && currentPeer.Config.RemoteConnAddr.IP.String() != m.Peers[i].Endpoint.IP.String() {
				logger.Log(1, fmt.Sprintf("----> Peer RemoteConn has changed from %s to %s",
					currentPeer.Config.RemoteConnAddr.String(), m.Peers[i].Endpoint.String()))
				logger.Log(1, "----------> Resetting proxy for Peer: ", currentPeer.Key.String())
				currentPeer.StopConn()
				currentPeer.Mutex.Unlock()
				delete(peerConnMap, currentPeer.Key.String())
				continue
			}
			// delete the peer from the list
			logger.Log(1, "-----------> No updates observed so deleting peer: ", m.Peers[i].PublicKey.String())
			currentPeer.ServerMap[m.Server] = struct{}{}
			peerConnMap[currentPeer.Key.String()] = currentPeer
			m.Peers = append(m.Peers[:i], m.Peers[i+1:]...)
			currentPeer.Mutex.Unlock()
			continue

		}

	}

	gCfg.UpdateProxyPeers(&peerConnMap)
	logger.Log(1, "--> processed peer update for proxy")
	return nil
}

// ProxyManagerPayload.peerUpdate - processes the peer update
func (m *proxyPayload) peerUpdate() error {

	err := m.processPayload()
	if err != nil {
		return err
	}
	for _, peerI := range m.Peers {

		peerConf := m.PeerMap[peerI.PublicKey.String()]
		if peerI.Endpoint == nil {
			logger.Log(1, "Endpoint nil for peer: ", peerI.PublicKey.String())
			continue
		}

		var isRelayed bool
		var relayedTo *net.UDPAddr
		if m.IsRelayed {
			isRelayed = true
			relayedTo = m.RelayedTo
		} else {

			isRelayed = peerConf.IsRelayed
			relayedTo = peerConf.RelayedTo

		}
		if peerI.Remove {
			// peer has been deleted so skip
			continue
		}
		var shouldUseProxy bool
		if isRelayed {
			shouldUseProxy = true
		}
		if peerConf.Proxy && m.Action == nm_models.ProxyUpdate {
			shouldUseProxy = true
		}
		if shouldUseProxy {
			peerpkg.AddNew(m.Server, peerI, peerConf, isRelayed, relayedTo)
		}

	}
	return nil
}
