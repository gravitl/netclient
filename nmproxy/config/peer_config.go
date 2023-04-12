package config

import (
	"github.com/gravitl/netclient/nmproxy/models"
	"github.com/gravitl/netclient/nmproxy/wg"
	"github.com/gravitl/netmaker/logger"
	nm_models "github.com/gravitl/netmaker/models"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// wgIfaceConf - interface config
type wgIfaceConf struct {
	iface           *wg.WGIface
	ifaceKeyHash    string
	proxyPeerMap    models.PeerConnMap
	turnMap         map[string]models.TurnCfg
	peerHashMap     map[string]*models.RemotePeer
	relayPeerMap    map[string]map[string]*models.RemotePeer
	allPeersConf    map[string]nm_models.HostPeerMap
	peerSignalChMap map[string](chan nm_models.Signal)
}

// Config.IsIfaceNil - checks if ifconfig is nil in the memory config
func (c *Config) IsIfaceNil() bool {
	return c.ifaceConfig.iface == nil
}

// Config.SetIface - sets the iface value in the config
func (c *Config) SetIface(iface *wg.WGIface) {
	if c != nil {
		c.mutex.Lock()
		c.ifaceConfig.iface = iface
		c.mutex.Unlock()
		c.setIfaceKeyHash()
	}
}

// Config.GetGetIfaceDeviceIface - gets the wg device value
func (c *Config) GetIfaceDevice() wgtypes.Device {
	c.mutex.Lock()
	defer c.mutex.Unlock()
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
		c.mutex.Lock()
		c.ifaceConfig.ifaceKeyHash = models.ConvPeerKeyToHash(c.ifaceConfig.iface.Device.PublicKey.String())
		c.mutex.Unlock()
	}
}

// Config.GetDeviceKeyHash - gets the interface pubkey hash
func (c *Config) GetDeviceKeyHash() string {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	if !c.IsIfaceNil() {
		return c.ifaceConfig.ifaceKeyHash
	}
	return ""
}

// Config.GetDeviceKeys - fetches interface private,pubkey
func (c *Config) GetDeviceKeys() (privateKey wgtypes.Key, publicKey wgtypes.Key) {
	if !c.IsIfaceNil() {
		iface := c.GetIfaceDevice()
		privateKey = iface.PrivateKey
		publicKey = iface.PublicKey
	}
	return
}

// Config.GetDevicePubKey - fetches device public key
func (c *Config) GetDevicePubKey() (publicKey wgtypes.Key) {
	if !c.IsIfaceNil() {
		iface := c.GetIfaceDevice()
		publicKey = iface.PublicKey
	}
	return
}

// Config.GetAllProxyPeers - fetches all peers in the network
func (c *Config) GetAllProxyPeers() models.PeerConnMap {
	return c.ifaceConfig.proxyPeerMap
}

// Config.UpdateProxyPeers - updates all peers in the network
func (c *Config) UpdateProxyPeers(peers *models.PeerConnMap) {
	if peers != nil {
		c.ifaceConfig.proxyPeerMap = *peers
	}
}

// Config.SavePeer - saves peer to the config
func (c *Config) SavePeer(connConf *models.Conn) {
	c.ifaceConfig.proxyPeerMap[connConf.Key.String()] = connConf
}

// Config.GetPeer - fetches the peer by network and pubkey
func (c *Config) GetPeer(peerPubKey string) (models.Conn, bool) {

	if peerConn, found := c.ifaceConfig.proxyPeerMap[peerPubKey]; found {
		return *peerConn, found
	}

	return models.Conn{}, false
}

// Config.UpdatePeer - updates peer by network
func (c *Config) UpdatePeer(updatedPeer *models.Conn) {

	if peerConf, found := c.ifaceConfig.proxyPeerMap[updatedPeer.Key.String()]; found {
		peerConf.Mutex.Lock()
		c.ifaceConfig.proxyPeerMap[updatedPeer.Key.String()] = updatedPeer
		peerConf.Mutex.Unlock()
	}
}

// Config.ResetPeer - resets the peer connection to proxy
func (c *Config) ResetPeer(peerKey string) {

	if peerConf, found := c.ifaceConfig.proxyPeerMap[peerKey]; found {
		peerConf.Mutex.Lock()
		peerConf.ResetConn()
		peerConf.Mutex.Unlock()
	}

}

// Config.RemovePeer - removes the peer from the network peer config
func (c *Config) RemovePeer(peerPubKey string) {

	if peerConf, found := c.ifaceConfig.proxyPeerMap[peerPubKey]; found {

		logger.Log(0, "----> Deleting Peer from proxy: ", peerConf.Key.String())
		peerConf.Mutex.Lock()
		peerConf.StopConn()
		peerConf.Mutex.Unlock()
		delete(c.ifaceConfig.proxyPeerMap, peerPubKey)
		GetCfg().DeletePeerHash(peerConf.Key.String())
		GetCfg().DeleteTurnCfg(peerPubKey)

	}

}

// Config.UpdatePeerNetwork - updates the peer network settings map
func (c *Config) UpdatePeerNetwork(peerPubKey, network string, setting models.Settings) {
	if peerConf, found := c.ifaceConfig.proxyPeerMap[peerPubKey]; found {
		peerConf.Mutex.Lock()
		peerConf.NetworkSettings[network] = setting
		peerConf.Mutex.Unlock()
	}
}

// Config.CheckIfPeerExists - checks if peer exists in the config
func (c *Config) CheckIfPeerExists(peerPubKey string) bool {

	_, found := c.ifaceConfig.proxyPeerMap[peerPubKey]
	return found
}

// Config.GetNetworkPeerMap - fetches all peers in the network
func (c *Config) GetNetworkPeerMap() models.PeerConnMap {
	return c.ifaceConfig.proxyPeerMap
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
func (c *Config) DeleteRelayedPeers() {
	peersMap := c.GetAllProxyPeers()
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

// Config.GetAllPeersIDsAndAddrs - get all peers
func (c *Config) GetAllPeersIDsAndAddrs() map[string]nm_models.HostPeerMap {
	return c.ifaceConfig.allPeersConf
}

// Config.SetPeersIDsAndAddrs - sets the peers in the config
func (c *Config) SetPeersIDsAndAddrs(server string, peers nm_models.HostPeerMap) {
	c.ifaceConfig.allPeersConf[server] = peers
}

// Config.GetPeersIDsAndAddrs - get peer conf
func (c *Config) GetPeersIDsAndAddrs(server, peerKey string) (map[string]nm_models.IDandAddr, bool) {
	if peersIDsAndAddrs, ok := c.ifaceConfig.allPeersConf[server]; ok {
		return peersIDsAndAddrs[peerKey], ok
	}

	return make(map[string]nm_models.IDandAddr), false
}

// Config.DeletePeerAnswerCh - deletes peer answer channel
func (c *Config) DeletePeerAnswerCh(peerKey string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	delete(c.ifaceConfig.peerSignalChMap, peerKey)
}

// Config.IsPeerSignalActive - check if watch is active peer signal channel
func (c *Config) IsPeerSignalActive(peerKey string) bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	_, ok := c.ifaceConfig.peerSignalChMap[peerKey]
	return ok
}

// Config.StorePeerAnswerCh - stores peer's signal channel in the config
func (c *Config) StorePeerAnswerCh(peerKey string, ch chan nm_models.Signal) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.ifaceConfig.peerSignalChMap[peerKey] = ch
}

// Config.ClosePeerAnswerCh - deletes the peer signal channel from config
func (c *Config) ClosePeerAnswerCh(peerKey string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if ch, ok := c.ifaceConfig.peerSignalChMap[peerKey]; ok {
		close(ch)
		delete(c.ifaceConfig.peerSignalChMap, peerKey)
	}
}

// Config.SendSignalToPeerCh - sends signal to peer signal channel
func (c *Config) SendSignalToPeerCh(signal nm_models.Signal) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if ch, ok := c.ifaceConfig.peerSignalChMap[signal.FromHostPubKey]; ok && ch != nil {
		ch <- signal
	}
}

// Config.SetTurnCfg - sets the turn config
func (c *Config) SetTurnCfg(t models.TurnCfg) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.ifaceConfig.turnMap[t.PeerKey] = t
}

// Config.GetTurnCfg - gets the turn config
func (c *Config) GetTurnCfg(peerKey string) (t models.TurnCfg, ok bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	t, ok = c.ifaceConfig.turnMap[peerKey]
	return
}

// Config.DeleteTurnCfg - deletes the turn config
func (c *Config) DeleteTurnCfg(peerKey string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if t, ok := c.ifaceConfig.turnMap[peerKey]; ok {
		t.Client.Close()
		if err := t.Cfg.Conn.Close(); err != nil {
			logger.Log(0, "failed to close listener: ", err.Error())
		}
		delete(c.ifaceConfig.turnMap, peerKey)
	}
}
