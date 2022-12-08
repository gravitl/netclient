package config

import (
	"net"

	"github.com/gravitl/netclient/nm-proxy/models"
	"github.com/gravitl/netclient/nm-proxy/wg"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// wgIfaceConf - interface config
type wgIfaceConf struct {
	iface            *wg.WGIface
	ifaceKeyHash     string
	networkPeerMap   map[string]models.PeerConnMap
	peerHashMap      map[string]*models.RemotePeer
	extSrcIpMap      map[string]*models.RemotePeer
	extClientWaitMap map[string]*models.RemotePeer
	relayPeerMap     map[string]map[string]*models.RemotePeer
}

// GlobalConfig.IsIfaceNil - checks if ifconfig is nil in the memory config
func (g *Config) IsIfaceNil() bool {
	return g.ifaceConfig.iface == nil
}

// GlobalConfig.SetIface - sets the iface value in the config
func (g *Config) SetIface(iface *wg.WGIface) {
	g.ifaceConfig.iface = iface
	g.setIfaceKeyHash()
}

// GlobalConfig.GetIface - gets the wg device value
func (g *Config) GetIface() wgtypes.Device {
	var iface wgtypes.Device
	if g.ifaceConfig.iface != nil {
		iface = *g.ifaceConfig.iface.Device
	}
	return iface
}

// sets the interface pubky hash in the config
func (g *Config) setIfaceKeyHash() {
	if !g.IsIfaceNil() {
		g.ifaceConfig.ifaceKeyHash = models.ConvPeerKeyToHash(g.ifaceConfig.iface.Device.PublicKey.String())
	}
}

// GlobalConfig.GetDeviceKeyHash - gets the interface pubkey hash
func (g *Config) GetDeviceKeyHash() string {
	if !g.IsIfaceNil() {
		return g.ifaceConfig.ifaceKeyHash
	}
	return ""
}

// GlobalConfig.GetDeviceKeys - fetches interface private,pubkey
func (g *Config) GetDeviceKeys() (privateKey wgtypes.Key, publicKey wgtypes.Key) {
	if !g.IsIfaceNil() {
		privateKey = g.GetIface().PrivateKey
		publicKey = g.GetIface().PublicKey
	}
	return
}

// GlobalConfig.GetDevicePubKey - fetches device public key
func (g *Config) GetDevicePubKey() (publicKey wgtypes.Key) {
	if !g.IsIfaceNil() {
		publicKey = g.GetIface().PublicKey
	}
	return
}

// GlobalConfig.CheckIfNetworkExists - checks if network exists
func (g *Config) CheckIfNetworkExists(network string) bool {
	_, found := g.ifaceConfig.networkPeerMap[network]
	return found
}

// GlobalConfig.GetNetworkPeers - fetches all peers in the network
func (g *Config) GetNetworkPeers(network string) models.PeerConnMap {
	return g.ifaceConfig.networkPeerMap[network]
}

// GlobalConfig.UpdateNetworkPeers - updates all peers in the network
func (g *Config) UpdateNetworkPeers(network string, peers *models.PeerConnMap) {
	if peers != nil {
		g.ifaceConfig.networkPeerMap[network] = *peers
	}

}

// GlobalConfig.SavePeer - saves peer to the config
func (g *Config) SavePeer(network string, connConf *models.Conn) {
	if _, ok := g.ifaceConfig.networkPeerMap[network]; !ok {
		g.ifaceConfig.networkPeerMap[network] = make(models.PeerConnMap)
	}
	g.ifaceConfig.networkPeerMap[network][connConf.Key.String()] = connConf
}

// GlobalConfig.GetPeer - fetches the peer by network and pubkey
func (g *Config) GetPeer(network, peerPubKey string) (models.Conn, bool) {

	if g.CheckIfNetworkExists(network) {
		if peerConn, found := g.ifaceConfig.networkPeerMap[network][peerPubKey]; found {
			return *peerConn, found
		}
	}
	return models.Conn{}, false
}

// GlobalConfig.UpdatePeer - updates peer by network
func (g *Config) UpdatePeer(network string, updatedPeer *models.Conn) {
	if g.CheckIfNetworkExists(network) {
		if peerConf, found := g.ifaceConfig.networkPeerMap[network][updatedPeer.Key.String()]; found {
			peerConf.Mutex.Lock()
			g.ifaceConfig.networkPeerMap[network][updatedPeer.Key.String()] = updatedPeer
			peerConf.Mutex.Unlock()
		}
	}

}

// GlobalConfig.ResetPeer - resets the peer connection to proxy
func (g *Config) ResetPeer(network, peerKey string) {
	if g.CheckIfNetworkExists(network) {
		if peerConf, found := g.ifaceConfig.networkPeerMap[network][peerKey]; found {
			peerConf.Mutex.Lock()
			peerConf.ResetConn()
			peerConf.Mutex.Unlock()
		}
	}
}

// GlobalConfig.RemovePeer - removes the peer from the network peer config
func (g *Config) RemovePeer(network string, peerPubKey string) {
	if g.CheckIfNetworkExists(network) {
		if peerConf, found := g.ifaceConfig.networkPeerMap[network][peerPubKey]; found {
			peerConf.Mutex.Lock()
			peerConf.StopConn()
			peerConf.Mutex.Unlock()
			delete(g.ifaceConfig.networkPeerMap[network], peerPubKey)
		}
	}

}

// GlobalConfig.DeleteNetworkPeers - deletes all peers in the network from the config
func (g *Config) DeleteNetworkPeers(network string) {
	delete(g.ifaceConfig.networkPeerMap, network)
}

// GlobalConfig.CheckIfPeerExists - checks if peer exists in the config
func (g *Config) CheckIfPeerExists(network, peerPubKey string) bool {
	if !g.CheckIfNetworkExists(network) {
		return false
	}
	_, found := g.ifaceConfig.networkPeerMap[network][peerPubKey]
	return found
}

// GlobalConfig.GetNetworkPeerMap - fetches all peers in the network
func (g *Config) GetNetworkPeerMap() map[string]models.PeerConnMap {
	return g.ifaceConfig.networkPeerMap
}

// GlobalConfig.SavePeerByHash - saves peer by its publicKey hash to the config
func (g *Config) SavePeerByHash(peerInfo *models.RemotePeer) {
	g.ifaceConfig.peerHashMap[models.ConvPeerKeyToHash(peerInfo.PeerKey)] = peerInfo
}

// GlobalConfig.GetPeerInfoByHash - fetches the peerInfo by its pubKey hash
func (g *Config) GetPeerInfoByHash(peerKeyHash string) (models.RemotePeer, bool) {

	if peerInfo, found := g.ifaceConfig.peerHashMap[peerKeyHash]; found {
		return *peerInfo, found
	}
	return models.RemotePeer{}, false
}

// GlobalConfig.DeletePeerHash - deletes peer by its pubkey hash from config
func (g *Config) DeletePeerHash(peerKey string) {
	delete(g.ifaceConfig.peerHashMap, models.ConvPeerKeyToHash(peerKey))
}

// GlobalConfig.GetExtClientInfo - fetches ext. client from the config by it's endpoint
func (g *Config) GetExtClientInfo(udpAddr *net.UDPAddr) (models.RemotePeer, bool) {

	if udpAddr == nil {
		return models.RemotePeer{}, false
	}
	if peerInfo, found := g.ifaceConfig.extSrcIpMap[udpAddr.String()]; found {
		return *peerInfo, found
	}
	return models.RemotePeer{}, false

}

// GlobalConfig.SaveExtClientInfo - saves the ext. client info to config
func (g *Config) SaveExtClientInfo(peerInfo *models.RemotePeer) {
	g.ifaceConfig.extSrcIpMap[peerInfo.Endpoint.String()] = peerInfo
}

// GlobalConfig.DeleteExtClientInfo - deletes the ext. client info from the config
func (g *Config) DeleteExtClientInfo(udpAddr *net.UDPAddr) {
	delete(g.ifaceConfig.extSrcIpMap, udpAddr.String())
}

// GlobalConfig.GetExtClientWaitCfg - fetches the ext. info from wait config
func (g *Config) GetExtClientWaitCfg(peerKey string) (models.RemotePeer, bool) {

	if peerInfo, found := g.ifaceConfig.extClientWaitMap[peerKey]; found {
		return *peerInfo, found
	}
	return models.RemotePeer{}, false
}

// GlobalConfig.SaveExtclientWaitCfg - saves extclient wait cfg
func (g *Config) SaveExtclientWaitCfg(extPeer *models.RemotePeer) {
	g.ifaceConfig.extClientWaitMap[extPeer.PeerKey] = extPeer
}

// GlobalConfig.DeleteExtWaitCfg - deletes ext. wait cfg
func (g *Config) DeleteExtWaitCfg(peerKey string) {
	if extPeerCfg, ok := g.ifaceConfig.extClientWaitMap[peerKey]; ok {
		extPeerCfg.CancelFunc()
		close(extPeerCfg.CommChan)
		delete(g.ifaceConfig.extClientWaitMap, peerKey)
	}
}

// GlobalConfig.SaveRelayedPeer - saves relayed peer to config
func (g *Config) SaveRelayedPeer(relayedNodePubKey string, peer *models.RemotePeer) {
	if _, ok := g.ifaceConfig.relayPeerMap[models.ConvPeerKeyToHash(relayedNodePubKey)]; !ok {
		g.ifaceConfig.relayPeerMap[models.ConvPeerKeyToHash(relayedNodePubKey)] = make(map[string]*models.RemotePeer)
	}
	g.ifaceConfig.relayPeerMap[models.ConvPeerKeyToHash(relayedNodePubKey)][models.ConvPeerKeyToHash(peer.PeerKey)] = peer
}

// GlobalConfig.CheckIfRelayedNodeExists - checks if relayed node exists
func (g *Config) CheckIfRelayedNodeExists(peerHash string) bool {
	_, found := g.ifaceConfig.relayPeerMap[peerHash]
	return found
}

// GlobalConfig.GetRelayedPeer - fectches the relayed peer
func (g *Config) GetRelayedPeer(srcKeyHash, dstPeerHash string) (models.RemotePeer, bool) {

	if g.CheckIfRelayedNodeExists(srcKeyHash) {
		if peer, found := g.ifaceConfig.relayPeerMap[srcKeyHash][dstPeerHash]; found {
			return *peer, found
		}
	} else if g.CheckIfRelayedNodeExists(dstPeerHash) {
		if peer, found := g.ifaceConfig.relayPeerMap[dstPeerHash][dstPeerHash]; found {
			return *peer, found
		}
	}
	return models.RemotePeer{}, false
}

// GlobalConfig.DeleteRelayedPeers - deletes relayed peer info
func (g *Config) DeleteRelayedPeers(network string) {
	peersMap := g.GetNetworkPeers(network)
	for _, peer := range peersMap {
		if peer.IsRelayed {
			delete(g.ifaceConfig.relayPeerMap, models.ConvPeerKeyToHash(peer.Key.String()))
		}
	}
}

// GlobalConfig.UpdateListenPortForRelayedPeer - updates listen port for the relayed peer
func (g *Config) UpdateListenPortForRelayedPeer(port int, srcKeyHash, dstPeerHash string) {
	if g.CheckIfRelayedNodeExists(srcKeyHash) {
		if peer, found := g.ifaceConfig.relayPeerMap[srcKeyHash][dstPeerHash]; found {
			peer.Endpoint.Port = port
			g.SaveRelayedPeer(srcKeyHash, peer)
		}
	} else if g.CheckIfRelayedNodeExists(dstPeerHash) {
		if peer, found := g.ifaceConfig.relayPeerMap[dstPeerHash][dstPeerHash]; found {
			peer.Endpoint.Port = port
			g.SaveRelayedPeer(dstPeerHash, peer)
		}
	}
}

// GlobalConfig.GetInterfaceListenPort - fetches interface listen port from config
func (g *Config) GetInterfaceListenPort() (port int) {
	if !g.IsIfaceNil() {
		port = g.GetIface().ListenPort
	}
	return
}

// GlobalConfig.UpdateWgIface - updates iface config in memory
func (g *Config) UpdateWgIface(wgIface *wg.WGIface) {
	g.ifaceConfig.iface = wgIface
}
