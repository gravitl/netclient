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
	"github.com/gravitl/netmaker/logger"
	nm_models "github.com/gravitl/netmaker/models"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
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
			logger.Log(0, fmt.Sprintf("-------> PROXY-MANAGER: %+v\n", mI.ProxyUpdate))
			err := configureProxy(mI)
			if err != nil {
				logger.Log(0, "failed to configure proxy:  ", err.Error())
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
	config.GetCfg().SetPeersIDsAndAddrs(m.Server, payload.PeerIDs)
	noProxy(payload) // starts or stops the metrics collection based on host proxy setting
	fwUpdate(payload)
	switch m.Action {
	case nm_models.ProxyUpdate:
		m.peerUpdate()
	case nm_models.ProxyDeleteAllPeers:
		cleanUpInterface()

	}
	return err
}

func fwUpdate(payload *nm_models.HostPeerUpdate) {
	isingressGw := len(payload.IngressInfo.ExtPeers) > 0
	if isingressGw && config.GetCfg().IsIngressGw(payload.Server) != isingressGw {
		if !config.GetCfg().GetFwStatus() {

			fwClose, err := router.Init()
			if err != nil {
				logger.Log(0, "failed to intialize firewall: ", err.Error())
				return
			}
			config.GetCfg().SetFwStatus(true)
			config.GetCfg().SetFwCloseFunc(fwClose)

		}
		config.GetCfg().SetIngressGwStatus(payload.Server, isingressGw)
	} else {
		logger.Log(0, "firewall controller is intialized already")
	}

	if isingressGw {
		router.SetIngressRoutes(payload.Server, payload.IngressInfo)
	}
	if config.GetCfg().GetFwStatus() && !isingressGw {
		router.DeleteIngressRules(payload.Server)
	}

}

func noProxy(peerUpdate *nm_models.HostPeerUpdate) {
	if peerUpdate.ProxyUpdate.Action != nm_models.NoProxy && config.GetCfg().GetMetricsCollectionStatus() {
		// stop the metrics thread since proxy is switched on for the host
		logger.Log(0, "Stopping Metrics Thread...")
		config.GetCfg().StopMetricsCollectionThread()
	} else if peerUpdate.ProxyUpdate.Action == nm_models.NoProxy && !config.GetCfg().GetMetricsCollectionStatus() {
		ctx, cancel := context.WithCancel(context.Background())
		go peerpkg.StartMetricsCollectionForHostPeers(ctx)
		config.GetCfg().SetMetricsThreadCtx(cancel)
	}
	if peerUpdate.ProxyUpdate.Action == nm_models.NoProxy {
		cleanUpInterface()
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
				//peer.Endpoint.Port = models.NmProxyPort
				rPeer := models.RemotePeer{
					PeerKey:  peer.PublicKey.String(),
					Endpoint: peer.Endpoint,
				}
				c.SaveRelayedPeer(relayedNodePubKey, &rPeer)

			}

		}
		//relayedNodeConf.RelayedPeerEndpoint.Port = models.NmProxyPort
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
	}
	noProxyPeers := config.GetCfg().GetNoProxyPeers()
	for _, peerI := range noProxyPeers {
		config.GetCfg().DeleteNoProxyPeer(peerI.Config.PeerEndpoint.IP.String())
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
	noProxyPeerMap := gCfg.GetNoProxyPeers()
	// check device conf different from proxy
	// sync peer map with new update
	for peerPubKey, peerConn := range peerConnMap {
		if _, ok := m.PeerMap[peerPubKey]; !ok {
			_, found := peerConn.ServerMap[m.Server]
			if !found {
				continue
			} else {
				delete(peerConn.ServerMap, m.Server)
				peerConnMap[peerPubKey] = peerConn
				if len(peerConn.ServerMap) > 0 {
					continue
				}
			}

			if peerConn.IsExtClient {
				logger.Log(1, "------> Deleting ExtClient Watch Thread: ", peerConn.Key.String())
				gCfg.DeleteExtWaitCfg(peerConn.Key.String())
				gCfg.DeleteExtClientInfo(peerConn.Config.PeerConf.Endpoint)
			}
			gCfg.DeletePeerHash(peerConn.Key.String())
			gCfg.RemovePeer(peerConn.Key.String())
		}
	}

	// update no proxy peers map with peer update
	for peerIP, peerConn := range noProxyPeerMap {

		if _, ok := m.PeerMap[peerConn.Key.String()]; !ok {
			_, found := peerConn.ServerMap[m.Server]
			if !found {
				continue
			} else {
				delete(peerConn.ServerMap, m.Server)
				noProxyPeerMap[peerIP] = peerConn
				if len(peerConn.ServerMap) > 0 {
					continue
				}

			}
			gCfg.DeleteNoProxyPeer(peerIP)
		}
	}

	for i := len(m.Peers) - 1; i >= 0; i-- {

		if currentPeer, ok := peerConnMap[m.Peers[i].PublicKey.String()]; ok {
			currentPeer.Mutex.Lock()
			if currentPeer.IsExtClient {
				_, found := gCfg.GetExtClientInfo(currentPeer.Config.PeerEndpoint)
				if found {
					m.Peers = append(m.Peers[:i], m.Peers[i+1:]...)
					currentPeer.Mutex.Unlock()

				}
				continue

			}
			// check if proxy is off for the peer
			if !m.PeerMap[m.Peers[i].PublicKey.String()].Proxy {

				// cleanup proxy connections for the peer
				currentPeer.StopConn()
				delete(peerConnMap, currentPeer.Key.String())
				//m.Peers = append(m.Peers[:i], m.Peers[i+1:]...)
				currentPeer.Mutex.Unlock()
				continue

			}
			// check if peer is not connected to proxy
			devPeer, err := wg.GetPeer(m.InterfaceName, currentPeer.Key.String())
			if err == nil {
				logger.Log(0, fmt.Sprintf("---------> comparing peer endpoint: onDevice: %s, Proxy: %s", devPeer.Endpoint.String(),
					currentPeer.Config.LocalConnAddr.String()))
				if devPeer.Endpoint.String() != currentPeer.Config.LocalConnAddr.String() {
					logger.Log(1, "---------> endpoint is not set to proxy: ", currentPeer.Key.String())
					currentPeer.StopConn()
					currentPeer.Mutex.Unlock()
					delete(peerConnMap, currentPeer.Key.String())
					continue
				}
			}

			//check if peer is being relayed
			if currentPeer.IsRelayed != m.PeerMap[m.Peers[i].PublicKey.String()].IsRelayed {
				logger.Log(1, "---------> peer relay status has been changed: ", currentPeer.Key.String())
				currentPeer.StopConn()
				currentPeer.Mutex.Unlock()
				delete(peerConnMap, currentPeer.Key.String())
				continue
			}

			// check if relay endpoint has been changed
			if currentPeer.RelayedEndpoint != nil &&
				m.PeerMap[m.Peers[i].PublicKey.String()].RelayedTo != nil &&
				currentPeer.RelayedEndpoint.String() != m.PeerMap[m.Peers[i].PublicKey.String()].RelayedTo.String() {
				logger.Log(1, "---------> peer relay endpoint has been changed: ", currentPeer.Key.String())
				currentPeer.StopConn()
				currentPeer.Mutex.Unlock()
				delete(peerConnMap, currentPeer.Key.String())
				continue
			}

			// check if proxy listen port has changed for the peer
			if currentPeer.Config.ListenPort != int(m.PeerMap[m.Peers[i].PublicKey.String()].PublicListenPort) &&
				m.PeerMap[m.Peers[i].PublicKey.String()].PublicListenPort != 0 {
				// listen port has been changed, reset conn
				logger.Log(1, "--------> peer proxy listen port has been changed", currentPeer.Key.String())
				currentPeer.StopConn()
				currentPeer.Mutex.Unlock()
				delete(peerConnMap, currentPeer.Key.String())
				continue
			}

			if currentPeer.Config.RemoteConnAddr.IP.String() != m.Peers[i].Endpoint.IP.String() {
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
		if m.Peers[i].Endpoint == nil {
			continue
		}
		if noProxypeer, found := noProxyPeerMap[m.Peers[i].Endpoint.IP.String()]; found {
			if m.PeerMap[m.Peers[i].PublicKey.String()].Proxy {
				// cleanup proxy connections for the no proxy peer since proxy is switched on for the peer
				noProxypeer.Mutex.Lock()
				noProxypeer.StopConn()
				noProxypeer.Mutex.Unlock()
				delete(noProxyPeerMap, noProxypeer.Config.PeerEndpoint.IP.String())
				continue
			}
			// check if peer is not connected to proxy
			devPeer, err := wg.GetPeer(m.InterfaceName, noProxypeer.Key.String())
			if err == nil {
				logger.Log(0, fmt.Sprintf("--------->[noProxy] comparing peer endpoint: onDevice: %s, Proxy: %s", devPeer.Endpoint.String(),
					noProxypeer.Config.LocalConnAddr.String()))
				if devPeer.Endpoint.String() != noProxypeer.Config.LocalConnAddr.String() {
					logger.Log(1, "---------> endpoint is not set to proxy: ", noProxypeer.Key.String())
					noProxypeer.StopConn()
					noProxypeer.Mutex.Unlock()
					delete(noProxyPeerMap, noProxypeer.Config.PeerEndpoint.IP.String())
					continue
				}
			}
			// check if proxy listen port has changed for the peer
			if noProxypeer.Config.ListenPort != int(m.PeerMap[m.Peers[i].PublicKey.String()].PublicListenPort) &&
				m.PeerMap[m.Peers[i].PublicKey.String()].PublicListenPort != 0 {
				// listen port has been changed, reset conn
				logger.Log(1, "-------->[noProxy] peer proxy listen port has been changed", noProxypeer.Key.String())
				noProxypeer.StopConn()
				noProxypeer.Mutex.Unlock()
				delete(noProxyPeerMap, noProxypeer.Config.PeerEndpoint.IP.String())
				continue
			}
			// update network map
			noProxypeer.ServerMap[m.Server] = struct{}{}
			noProxyPeerMap[noProxypeer.Key.String()] = noProxypeer
			m.Peers = append(m.Peers[:i], m.Peers[i+1:]...)
		}

	}

	gCfg.UpdateProxyPeers(&peerConnMap)
	gCfg.UpdateNoProxyPeers(&noProxyPeerMap)
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
		if peerI.Endpoint == nil && !peerConf.IsExtClient {
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
		if peerConf.IsExtClient {
			if _, found := config.GetCfg().GetExtClientWaitCfg(peerI.PublicKey.String()); found {
				continue
			}
			logger.Log(1, "extclient watch thread starting for: ", peerI.PublicKey.String())
			go func(server string, peer wgtypes.PeerConfig, isRelayed bool, relayTo *net.UDPAddr,
				peerConf nm_models.PeerConf) {
				addExtClient := false
				commChan := make(chan *net.UDPAddr, 5)
				ctx, cancel := context.WithCancel(context.Background())
				extPeer := models.RemotePeer{
					PeerKey:     peer.PublicKey.String(),
					CancelFunc:  cancel,
					CommChan:    commChan,
					IsExtClient: true,
				}
				config.GetCfg().SaveExtclientWaitCfg(&extPeer)
				defer func() {
					if addExtClient {
						logger.Log(1, "Got endpoint for Extclient adding peer...", extPeer.Endpoint.String())
						peerpkg.AddNew(server, peer, peerConf, isRelayed, relayedTo)
					}
					logger.Log(1, "Exiting extclient watch Thread for: ", peer.PublicKey.String())
				}()
				for {
					select {
					case <-ctx.Done():
						return
					case endpoint := <-commChan:
						if endpoint != nil {
							addExtClient = true
							peer.Endpoint = endpoint
							peerI.Endpoint = endpoint
							config.GetCfg().DeleteExtWaitCfg(peer.PublicKey.String())
							return
						}
					}

				}

			}(m.Server, peerI, isRelayed, relayedTo, peerConf)
			continue
		}

		peerpkg.AddNew(m.Server, peerI, peerConf, isRelayed, relayedTo)

	}
	return nil
}
