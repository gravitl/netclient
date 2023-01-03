package config

import (
	"net"
	"sync"

	"github.com/gravitl/netclient/nmproxy/models"
	"github.com/gravitl/netclient/nmproxy/wg"
	nm_models "github.com/gravitl/netmaker/models"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var extPeerMapMutex = sync.Mutex{}

// wgIfaceConf - interface config
type wgIfaceConf struct {
	iface            *wg.WGIface
	ifaceKeyHash     string
	networkPeerMap   map[string]models.PeerConnMap
	peerHashMap      map[string]*models.RemotePeer
	extSrcIpMap      map[string]*models.RemotePeer
	extClientWaitMap map[string]*models.RemotePeer
	relayPeerMap     map[string]map[string]*models.RemotePeer
	noProxyPeerMap   models.PeerConnMap
	allPeersConf     map[string]nm_models.PeerMap
	ServerConn       *net.UDPAddr
}

// Config.IsIfaceNil - checks if ifconfig is nil in the memory config
func (c *Config) IsIfaceNil() bool {
	return c.ifaceConfig.iface == nil
}

// Config.SetIface - sets the iface value in the config
func (c *Config) SetIface(iface *wg.WGIface) {
	c.ifaceConfig.iface = iface
	c.setIfaceKeyHash()
}

// Config.GetGetIfaceDeviceIface - gets the wg device value
func (c *Config) GetIfaceDevice() wgtypes.Device {
	var iface wgtypes.Device
	if c.ifaceConfig.iface != nil {
		iface = *c.ifaceConfig.iface.Device
	}
	return iface
}

// Config.GetIface - gets the interface config
func (c *Config) GetIface() *wg.WGIface {
	return c.ifaceConfig.iface
}

// sets the interface pubky hash in the config
func (c *Config) setIfaceKeyHash() {
	if !c.IsIfaceNil() {
		c.ifaceConfig.ifaceKeyHash = models.ConvPeerKeyToHash(c.ifaceConfig.iface.Device.PublicKey.String())
	}
}

// Config.GetDeviceKeyHash - gets the interface pubkey hash
func (c *Config) GetDeviceKeyHash() string {
	if !c.IsIfaceNil() {
		return c.ifaceConfig.ifaceKeyHash
	}
	return ""
}

// Config.GetDeviceKeys - fetches interface private,pubkey
func (c *Config) GetDeviceKeys() (privateKey wgtypes.Key, publicKey wgtypes.Key) {
	if !c.IsIfaceNil() {
		privateKey = c.GetIfaceDevice().PrivateKey
		publicKey = c.GetIfaceDevice().PublicKey
	}
	return
}

// Config.GetDevicePubKey - fetches device public key
func (c *Config) GetDevicePubKey() (publicKey wgtypes.Key) {
	if !c.IsIfaceNil() {
		publicKey = c.GetIfaceDevice().PublicKey
	}
	return
}

// Config.CheckIfNetworkExists - checks if network exists
func (c *Config) CheckIfNetworkExists(network string) bool {
	_, found := c.ifaceConfig.networkPeerMap[network]
	return found
}

// Config.GetNetworkPeers - fetches all peers in the network
func (c *Config) GetNetworkPeers(network string) models.PeerConnMap {
	return c.ifaceConfig.networkPeerMap[network]
}

// Config.UpdateNetworkPeers - updates all peers in the network
func (c *Config) UpdateNetworkPeers(network string, peers *models.PeerConnMap) {
	if peers != nil {
		c.ifaceConfig.networkPeerMap[network] = *peers
	}

}

// Config.SavePeer - saves peer to the config
func (c *Config) SavePeer(network string, connConf *models.Conn) {
	if _, ok := c.ifaceConfig.networkPeerMap[network]; !ok {
		c.ifaceConfig.networkPeerMap[network] = make(models.PeerConnMap)
	}
	c.ifaceConfig.networkPeerMap[network][connConf.Key.String()] = connConf
}

// Config.GetPeer - fetches the peer by network and pubkey
func (c *Config) GetPeer(network, peerPubKey string) (models.Conn, bool) {

	if c.CheckIfNetworkExists(network) {
		if peerConn, found := c.ifaceConfig.networkPeerMap[network][peerPubKey]; found {
			return *peerConn, found
		}
	}
	return models.Conn{}, false
}

// Config.UpdatePeer - updates peer by network
func (c *Config) UpdatePeer(network string, updatedPeer *models.Conn) {
	if c.CheckIfNetworkExists(network) {
		if peerConf, found := c.ifaceConfig.networkPeerMap[network][updatedPeer.Key.String()]; found {
			peerConf.Mutex.Lock()
			c.ifaceConfig.networkPeerMap[network][updatedPeer.Key.String()] = updatedPeer
			peerConf.Mutex.Unlock()
		}
	}

}

// Config.ResetPeer - resets the peer connection to proxy
func (c *Config) ResetPeer(network, peerKey string) {
	if c.CheckIfNetworkExists(network) {
		if peerConf, found := c.ifaceConfig.networkPeerMap[network][peerKey]; found {
			peerConf.Mutex.Lock()
			peerConf.ResetConn()
			peerConf.Mutex.Unlock()
		}
	}
}

// Config.RemovePeer - removes the peer from the network peer config
func (c *Config) RemovePeer(network string, peerPubKey string) {
	if c.CheckIfNetworkExists(network) {
		if peerConf, found := c.ifaceConfig.networkPeerMap[network][peerPubKey]; found {
			peerConf.Mutex.Lock()
			peerConf.StopConn()
			peerConf.Mutex.Unlock()
			delete(c.ifaceConfig.networkPeerMap[network], peerPubKey)
		}
	}

}

// Config.DeleteNetworkPeers - deletes all peers in the network from the config
func (c *Config) DeleteNetworkPeers(network string) {
	delete(c.ifaceConfig.networkPeerMap, network)
}

// Config.CheckIfPeerExists - checks if peer exists in the config
func (c *Config) CheckIfPeerExists(network, peerPubKey string) bool {
	if !c.CheckIfNetworkExists(network) {
		return false
	}
	_, found := c.ifaceConfig.networkPeerMap[network][peerPubKey]
	return found
}

// Config.GetNetworkPeerMap - fetches all peers in the network
func (c *Config) GetNetworkPeerMap() map[string]models.PeerConnMap {
	return c.ifaceConfig.networkPeerMap
}

// Config.SavePeerByHash - saves peer by its publicKey hash to the config
func (c *Config) SavePeerByHash(peerInfo *models.RemotePeer) {
	c.ifaceConfig.peerHashMap[models.ConvPeerKeyToHash(peerInfo.PeerKey)] = peerInfo
}

// Config.GetPeerInfoByHash - fetches the peerInfo by its pubKey hash
func (c *Config) GetPeerInfoByHash(peerKeyHash string) (models.RemotePeer, bool) {

	if peerInfo, found := c.ifaceConfig.peerHashMap[peerKeyHash]; found {
		return *peerInfo, found
	}
	return models.RemotePeer{}, false
}

// Config.DeletePeerHash - deletes peer by its pubkey hash from config
func (c *Config) DeletePeerHash(peerKey string) {
	delete(c.ifaceConfig.peerHashMap, models.ConvPeerKeyToHash(peerKey))
}

// Config.GetExtClientInfo - fetches ext. client from the config by it's endpoint
func (c *Config) GetExtClientInfo(udpAddr *net.UDPAddr) (models.RemotePeer, bool) {

	if udpAddr == nil {
		return models.RemotePeer{}, false
	}
	if peerInfo, found := c.ifaceConfig.extSrcIpMap[udpAddr.String()]; found {
		return *peerInfo, found
	}
	return models.RemotePeer{}, false

}

// Config.SaveExtClientInfo - saves the ext. client info to config
func (c *Config) SaveExtClientInfo(peerInfo *models.RemotePeer) {
	c.ifaceConfig.extSrcIpMap[peerInfo.Endpoint.String()] = peerInfo
}

// Config.DeleteExtClientInfo - deletes the ext. client info from the config
func (c *Config) DeleteExtClientInfo(udpAddr *net.UDPAddr) {
	delete(c.ifaceConfig.extSrcIpMap, udpAddr.String())
}

// Config.GetExtClientWaitCfg - fetches the ext. info from wait config
func (c *Config) GetExtClientWaitCfg(peerKey string) (models.RemotePeer, bool) {

	if peerInfo, found := c.ifaceConfig.extClientWaitMap[peerKey]; found {
		return *peerInfo, found
	}
	return models.RemotePeer{}, false
}

// Config.SaveExtclientWaitCfg - saves extclient wait cfg
func (c *Config) SaveExtclientWaitCfg(extPeer *models.RemotePeer) {
	extPeerMapMutex.Lock()
	defer extPeerMapMutex.Unlock()
	c.ifaceConfig.extClientWaitMap[extPeer.PeerKey] = extPeer
}

// Config.DeleteExtWaitCfg - deletes ext. wait cfg
func (c *Config) DeleteExtWaitCfg(peerKey string) {
	if extPeerCfg, ok := c.ifaceConfig.extClientWaitMap[peerKey]; ok {
		extPeerMapMutex.Lock()
		defer extPeerMapMutex.Unlock()
		extPeerCfg.CancelFunc()
		close(extPeerCfg.CommChan)
		delete(c.ifaceConfig.extClientWaitMap, peerKey)
	}
}

// Config.SaveRelayedPeer - saves relayed peer to config
func (c *Config) SaveRelayedPeer(relayedNodePubKey string, peer *models.RemotePeer) {
	if _, ok := c.ifaceConfig.relayPeerMap[models.ConvPeerKeyToHash(relayedNodePubKey)]; !ok {
		c.ifaceConfig.relayPeerMap[models.ConvPeerKeyToHash(relayedNodePubKey)] = make(map[string]*models.RemotePeer)
	}
	c.ifaceConfig.relayPeerMap[models.ConvPeerKeyToHash(relayedNodePubKey)][models.ConvPeerKeyToHash(peer.PeerKey)] = peer
}

// Config.CheckIfRelayedNodeExists - checks if relayed node exists
func (c *Config) CheckIfRelayedNodeExists(peerHash string) bool {
	_, found := c.ifaceConfig.relayPeerMap[peerHash]
	return found
}

// Config.GetRelayedPeer - fectches the relayed peer
func (c *Config) GetRelayedPeer(srcKeyHash, dstPeerHash string) (models.RemotePeer, bool) {

	if c.CheckIfRelayedNodeExists(srcKeyHash) {
		if peer, found := c.ifaceConfig.relayPeerMap[srcKeyHash][dstPeerHash]; found {
			return *peer, found
		}
	} else if c.CheckIfRelayedNodeExists(dstPeerHash) {
		if peer, found := c.ifaceConfig.relayPeerMap[dstPeerHash][dstPeerHash]; found {
			return *peer, found
		}
	}
	return models.RemotePeer{}, false
}

// Config.DeleteRelayedPeers - deletes relayed peer info
func (c *Config) DeleteRelayedPeers(network string) {
	peersMap := c.GetNetworkPeers(network)
	for _, peer := range peersMap {
		if peer.IsRelayed {
			delete(c.ifaceConfig.relayPeerMap, models.ConvPeerKeyToHash(peer.Key.String()))
		}
	}
}

// Config.UpdateListenPortForRelayedPeer - updates listen port for the relayed peer
func (c *Config) UpdateListenPortForRelayedPeer(port int, srcKeyHash, dstPeerHash string) {
	if c.CheckIfRelayedNodeExists(srcKeyHash) {
		if peer, found := c.ifaceConfig.relayPeerMap[srcKeyHash][dstPeerHash]; found {
			peer.Endpoint.Port = port
			c.SaveRelayedPeer(srcKeyHash, peer)
		}
	} else if c.CheckIfRelayedNodeExists(dstPeerHash) {
		if peer, found := c.ifaceConfig.relayPeerMap[dstPeerHash][dstPeerHash]; found {
			peer.Endpoint.Port = port
			c.SaveRelayedPeer(dstPeerHash, peer)
		}
	}
}

// Config.GetInterfaceListenPort - fetches interface listen port from config
func (c *Config) GetInterfaceListenPort() (port int) {
	if !c.IsIfaceNil() {
		port = c.GetIfaceDevice().ListenPort
	}
	return
}

// Config.UpdateWgIface - updates iface config in memory
func (c *Config) UpdateWgIface(wgIface *wg.WGIface) {
	c.ifaceConfig.iface = wgIface
}

// Config.GetNoProxyPeers - fetches peers not using proxy
func (c *Config) GetNoProxyPeers() models.PeerConnMap {
	return c.ifaceConfig.noProxyPeerMap
}

// Config.GetNoProxyPeer - fetches no proxy peer
func (c *Config) GetNoProxyPeer(peerIp net.IP) (models.Conn, bool) {
	if connConf, found := c.ifaceConfig.noProxyPeerMap[peerIp.String()]; found {
		return *connConf, found
	}
	return models.Conn{}, false

}

// Config.SaveNoProxyPeer - adds non proxy peer to config
func (c *Config) SaveNoProxyPeer(peer *models.Conn) {
	c.ifaceConfig.noProxyPeerMap[peer.Config.PeerEndpoint.IP.String()] = peer
}

// Config.DeleteNoProxyPeer - deletes no proxy peers from config
func (c *Config) DeleteNoProxyPeer(peerIP string) {
	if peerConf, found := c.ifaceConfig.noProxyPeerMap[peerIP]; found {
		peerConf.Mutex.Lock()
		peerConf.StopConn()
		peerConf.Mutex.Unlock()
		delete(c.ifaceConfig.noProxyPeerMap, peerIP)
	}
}

// Config.UpdateNoProxyPeers - updates no proxy peers config
func (c *Config) UpdateNoProxyPeers(peers *models.PeerConnMap) {
	if peers != nil {
		c.ifaceConfig.noProxyPeerMap = *peers
	}

}

// Config.GetAllPeersConf - fetches all peers from config
func (c *Config) GetAllPeersConf() map[string]nm_models.PeerMap {
	return c.ifaceConfig.allPeersConf
}

// Config.SetPeers - sets the peers in the config
func (c *Config) SetPeers(network string, peers nm_models.PeerMap) {
	c.ifaceConfig.allPeersConf[network] = peers
}

// Config.GetPeerConf - get peer conf
func (c *Config) GetPeerConf(network, peerKey string) (nm_models.IDandAddr, bool) {
	if peerMap, found := c.ifaceConfig.allPeersConf[network]; found {
		if peer, ok := peerMap[peerKey]; ok {
			return peer, ok
		}
	}
	return nm_models.IDandAddr{}, false
}
