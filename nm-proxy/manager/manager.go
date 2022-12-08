package manager

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/gravitl/netclient/nm-proxy/config"
	"github.com/gravitl/netclient/nm-proxy/models"
	"github.com/gravitl/netclient/nm-proxy/packet"
	peerpkg "github.com/gravitl/netclient/nm-proxy/peer"
	"github.com/gravitl/netclient/nm-proxy/wg"
	"github.com/gravitl/netmaker/logger"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// ProxyAction - type for proxy action
type ProxyAction string

const (
	// AddNetwork - constant for ADD_NETWORK_TO_PROXY ProxyAction
	AddNetwork ProxyAction = "ADD_NETWORK_TO_PROXY"
	// DeleteNetwork - constant for DELETE_NETWORK_FROM_PROXY ProxyAction
	DeleteNetwork ProxyAction = "DELETE_NETWORK_FROM_PROXY"
)

// ProxyManagerPayload - struct for proxy manager payload
type ProxyManagerPayload struct {
	Action          ProxyAction            `json:"action"`
	InterfaceName   string                 `json:"interface_name"`
	Network         string                 `json:"network"`
	WgAddr          string                 `json:"wg_addr"`
	Peers           []wgtypes.PeerConfig   `json:"peers"`
	PeerMap         map[string]PeerConf    `json:"peer_map"`
	IsRelayed       bool                   `json:"is_relayed"`
	IsIngress       bool                   `json:"is_ingress"`
	RelayedTo       *net.UDPAddr           `json:"relayed_to"`
	IsRelay         bool                   `json:"is_relay"`
	RelayedPeerConf map[string]RelayedConf `json:"relayed_conf"`
}

// RelayedConf - struct relayed peers config
type RelayedConf struct {
	RelayedPeerEndpoint *net.UDPAddr         `json:"relayed_peer_endpoint"`
	RelayedPeerPubKey   string               `json:"relayed_peer_pub_key"`
	Peers               []wgtypes.PeerConfig `json:"relayed_peers"`
}

// PeerConf - struct for peer config in the network
type PeerConf struct {
	IsExtClient            bool         `json:"is_ext_client"`
	ExtInternalIp          string       `json:"ext_internal_ip"`
	Address                string       `json:"address"`
	IsAttachedExtClient    bool         `json:"is_attached_ext_client"`
	IngressGatewayEndPoint *net.UDPAddr `json:"ingress_gateway_endpoint"`
	IsRelayed              bool         `json:"is_relayed"`
	RelayedTo              *net.UDPAddr `json:"relayed_to"`
	Proxy                  bool         `json:"proxy"`
}

// Start - starts the proxy manager loop and listens for events on the Channel provided
func Start(ctx context.Context, managerChan chan *ProxyManagerPayload) {
	for {
		select {
		case <-ctx.Done():
			logger.Log(1, "shutting down proxy manager...")
			return
		case mI := <-managerChan:
			if mI == nil {
				continue
			}
			logger.Log(0, fmt.Sprintf("-------> PROXY-MANAGER: %+v\n", mI))
			err := mI.configureProxy()
			if err != nil {
				logger.Log(0, "failed to add interface: [%s] to proxy: %v\n  ", mI.InterfaceName, err.Error())
			}
		}
	}
}

// ProxyManagerPayload.configureProxy - confgures proxy by payload action
func (m *ProxyManagerPayload) configureProxy() error {
	switch m.Action {
	case AddNetwork:
		m.addNetwork()
	case DeleteNetwork:
		m.deleteNetwork()

	}
	return nil
}

// ProxyManagerPayload.settingsUpdate - updates the network settings in the config
func (m *ProxyManagerPayload) settingsUpdate() (reset bool) {
	if !m.IsRelay && config.GetCfg().IsRelay(m.Network) {
		config.GetCfg().DeleteRelayedPeers(m.Network)
	}
	config.GetCfg().SetRelayStatus(m.Network, m.IsRelay)
	config.GetCfg().SetIngressGwStatus(m.Network, m.IsIngress)
	if config.GetCfg().GetRelayedStatus(m.Network) != m.IsRelayed {
		reset = true
	}
	config.GetCfg().SetRelayedStatus(m.Network, m.IsRelayed)
	if m.IsRelay {
		m.setRelayedPeers()
	}
	return
}

// ProxyManagerPayload.setRelayedPeers - processes the payload for the relayed peers
func (m *ProxyManagerPayload) setRelayedPeers() {
	c := config.GetCfg()
	for relayedNodePubKey, relayedNodeConf := range m.RelayedPeerConf {
		for _, peer := range relayedNodeConf.Peers {
			if peer.Endpoint != nil {
				peer.Endpoint.Port = models.NmProxyPort
				rPeer := models.RemotePeer{
					Network:  m.Network,
					PeerKey:  peer.PublicKey.String(),
					Endpoint: peer.Endpoint,
				}
				c.SaveRelayedPeer(relayedNodePubKey, &rPeer)

			}

		}
		relayedNodeConf.RelayedPeerEndpoint.Port = models.NmProxyPort
		relayedNode := models.RemotePeer{
			Network:  m.Network,
			PeerKey:  relayedNodePubKey,
			Endpoint: relayedNodeConf.RelayedPeerEndpoint,
		}
		c.SaveRelayedPeer(relayedNodePubKey, &relayedNode)

	}
}

func cleanUpInterface(network string) {
	logger.Log(1, "Removing proxy configuration for: ", network)
	peerConnMap := config.GetCfg().GetNetworkPeers(network)
	for _, peerI := range peerConnMap {
		config.GetCfg().RemovePeer(network, peerI.Key.String())
	}
	config.GetCfg().DeleteNetworkPeers(network)

}

// ProxyManagerPayload.processPayload - updates the peers and config with the recieved payload
func (m *ProxyManagerPayload) processPayload() (*wg.WGIface, error) {
	var err error
	var wgIface *wg.WGIface
	if m.InterfaceName == "" {
		return nil, errors.New("interface cannot be empty")
	}
	if m.Network == "" {
		return nil, errors.New("network name cannot be empty")
	}
	if len(m.Peers) == 0 {
		return nil, errors.New("no peers to add")
	}
	gCfg := config.GetCfg()
	wgIface, err = wg.GetWgIface(m.InterfaceName)
	if err != nil {
		logger.Log(1, "Failed get interface config: ", err.Error())
		return nil, err
	}
	if gCfg.IsIfaceNil() {
		gCfg.SetIface(wgIface)
	}

	if !gCfg.CheckIfNetworkExists(m.Network) {
		return wgIface, nil
	}
	reset := m.settingsUpdate()
	if reset {
		cleanUpInterface(m.Network)
		return wgIface, nil
	}

	// sync map with wg device config
	// check if listen port has changed
	if wgIface.Device.ListenPort != gCfg.GetInterfaceListenPort() {
		// reset proxy for this network
		cleanUpInterface(m.Network)
		return wgIface, nil
	}
	peerConnMap := gCfg.GetNetworkPeers(m.Network)

	//update wg device
	gCfg.UpdateWgIface(wgIface)
	// check device conf different from proxy
	// sync peer map with new update
	for peerPubKey, peerConn := range peerConnMap {
		if _, ok := m.PeerMap[peerPubKey]; !ok {

			if peerConn.IsAttachedExtClient {
				logger.Log(1, "------> Deleting ExtClient Watch Thread: ", peerConn.Key.String())
				gCfg.DeleteExtWaitCfg(peerConn.Key.String())
				gCfg.DeleteExtClientInfo(peerConn.Config.PeerConf.Endpoint)
			}
			gCfg.DeletePeerHash(peerConn.Key.String())
			gCfg.RemovePeer(peerConn.Config.Network, peerConn.Key.String())
		}
	}
	for i := len(m.Peers) - 1; i >= 0; i-- {

		if currentPeer, ok := peerConnMap[m.Peers[i].PublicKey.String()]; ok {
			currentPeer.Mutex.Lock()
			if currentPeer.IsAttachedExtClient {
				m.Peers = append(m.Peers[:i], m.Peers[i+1:]...)
				currentPeer.Mutex.Unlock()
				continue
			}
			// check if proxy is off for the peer
			if !m.PeerMap[m.Peers[i].PublicKey.String()].Proxy {

				// cleanup proxy connections for the peer
				currentPeer.StopConn()
				delete(peerConnMap, currentPeer.Key.String())
				m.Peers = append(m.Peers[:i], m.Peers[i+1:]...)
				currentPeer.Mutex.Unlock()
				continue

			}
			// check if peer is not connected to proxy
			devPeer, err := wg.GetPeer(m.InterfaceName, currentPeer.Key.String())
			if err == nil {
				logger.Log(0, "---------> COMPARING ENDPOINT: DEV: %s, Proxy: %s", devPeer.Endpoint.String(), currentPeer.Config.LocalConnAddr.String())
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

			if currentPeer.Config.RemoteConnAddr.IP.String() != m.Peers[i].Endpoint.IP.String() {
				logger.Log(1, "----------> Resetting proxy for Peer: ", currentPeer.Key.String(), m.InterfaceName)
				currentPeer.StopConn()
				currentPeer.Mutex.Unlock()
				delete(peerConnMap, currentPeer.Key.String())
				continue

			} else {
				// delete the peer from the list
				logger.Log(1, "-----------> No updates observed so deleting peer: ", m.Peers[i].PublicKey.String())
				m.Peers = append(m.Peers[:i], m.Peers[i+1:]...)
			}
			currentPeer.Mutex.Unlock()

		} else if !m.PeerMap[m.Peers[i].PublicKey.String()].Proxy && !m.PeerMap[m.Peers[i].PublicKey.String()].IsAttachedExtClient {
			logger.Log(1, "-----------> skipping peer, proxy is off: ", m.Peers[i].PublicKey.String())
			m.Peers = append(m.Peers[:i], m.Peers[i+1:]...)
		}
	}

	gCfg.UpdateNetworkPeers(m.Network, &peerConnMap)
	logger.Log(1, "CLEANED UP..........")
	return wgIface, nil
}

// ProxyManagerPayload.deleteNetwork - deletes network and the peers from proxy
func (m *ProxyManagerPayload) deleteNetwork() {
	cleanUpInterface(m.Network)
}

// ProxyManagerPayload.addNetwork - adds new peers to proxy
func (m *ProxyManagerPayload) addNetwork() error {
	var err error

	wgInterface, err := m.processPayload()
	if err != nil {
		return err
	}
	for i, peerI := range m.Peers {
		if !m.PeerMap[m.Peers[i].PublicKey.String()].Proxy && !m.PeerMap[m.Peers[i].PublicKey.String()].IsAttachedExtClient {
			continue
		}
		peerConf := m.PeerMap[peerI.PublicKey.String()]
		if peerI.Endpoint == nil && !(peerConf.IsAttachedExtClient || peerConf.IsExtClient) {
			logger.Log(1, "Endpoint nil for peer: ", peerI.PublicKey.String())
			continue
		}

		if peerConf.IsExtClient && !peerConf.IsAttachedExtClient {
			peerI.Endpoint = peerConf.IngressGatewayEndPoint
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
		if peerConf.IsAttachedExtClient {
			logger.Log(1, "extclient watch thread starting for: ", peerI.PublicKey.String())
			go func(wgInterface *wg.WGIface, peer *wgtypes.PeerConfig,
				isRelayed bool, relayTo *net.UDPAddr, peerConf PeerConf, wgAddr string) {
				addExtClient := false
				commChan := make(chan *net.UDPAddr, 30)
				ctx, cancel := context.WithCancel(context.Background())
				extPeer := models.RemotePeer{
					PeerKey:             peer.PublicKey.String(),
					CancelFunc:          cancel,
					CommChan:            commChan,
					IsAttachedExtClient: true,
				}
				config.GetCfg().SaveExtclientWaitCfg(&extPeer)
				defer func() {
					if addExtClient {
						logger.Log(1, "GOT ENDPOINT for Extclient adding peer...")
						ctx, _ := context.WithCancel(context.Background())
						go packet.StartSniffer(ctx, wgInterface.Name, wgAddr, peerConf.ExtInternalIp, peerConf.Address)
						peerpkg.AddNew(wgInterface, m.Network, peer, peerConf.Address, isRelayed,
							peerConf.IsExtClient, peerConf.IsAttachedExtClient, relayedTo)

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
							config.GetCfg().DeleteExtWaitCfg(peer.PublicKey.String())
							return
						}
					}

				}

			}(wgInterface, &peerI, isRelayed, relayedTo, peerConf, m.WgAddr)
			continue
		}

		peerpkg.AddNew(wgInterface, m.Network, &peerI, peerConf.Address, isRelayed,
			peerConf.IsExtClient, peerConf.IsAttachedExtClient, relayedTo)

	}
	return nil
}
