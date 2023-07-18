package config

import (
	"context"
	"sync"

	"github.com/gravitl/netclient/nmproxy/models"
	"github.com/gravitl/netclient/nmproxy/wg"
	"github.com/gravitl/netmaker/logger"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// wgIfaceConf - interface config
type wgIfaceConf struct {
	iface        *wg.WGIface
	ifaceKeyHash string
	proxyPeerMap models.PeerConnMap
	hostTurnCfg  *models.TurnCfg
	turnPeerMap  map[string]models.TurnPeerCfg
	peerHashMap  map[string]*models.RemotePeer
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

		GetCfg().DeletePeerTurnCfg(peerPubKey)

	}

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

// Config.GetInterfaceListenPort - fetches interface listen port from config
func (c *Config) GetInterfaceListenPort() (port int) {
	if !c.IsIfaceNil() {
		port = c.GetIfaceDevice().ListenPort
	}
	return
}

// Config.SetTurnCfg - sets the turn config
func (c *Config) SetTurnCfg(t *models.TurnCfg) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.ifaceConfig.hostTurnCfg = t
}

func (c *Config) UpdatePeerTurnAddr(peerKey string, addr string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if t, ok := c.ifaceConfig.turnPeerMap[peerKey]; ok {
		t.PeerTurnAddr = addr
		c.ifaceConfig.turnPeerMap[peerKey] = t
	}
}

// Config.GetTurnCfg - gets the turn config
func (c *Config) GetTurnCfg() (t *models.TurnCfg) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.ifaceConfig.hostTurnCfg
}

// Config.GetPeerTurnCfg - gets the peer turn cfg
func (c *Config) GetPeerTurnCfg(peerKey string) (t models.TurnPeerCfg, ok bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	t, ok = c.ifaceConfig.turnPeerMap[peerKey]
	return
}

// Config.UpdatePeerTurnCfg - updates the peer turn cfg
func (c *Config) UpdatePeerTurnCfg(peerKey string, t models.TurnPeerCfg) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.ifaceConfig.turnPeerMap[peerKey] = t
}

// Config.SetPeerTurnCfg - sets the peer turn cfg
func (c *Config) SetPeerTurnCfg(peerKey string, t models.TurnPeerCfg) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.ifaceConfig.turnPeerMap[peerKey] = t
}

// Config.GetAllTurnPeersCfg - fetches all peers using turn
func (c *Config) GetAllTurnPeersCfg() map[string]models.TurnPeerCfg {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.ifaceConfig.turnPeerMap
}

// Config.DeleteTurnCfg - deletes the turn config
func (c *Config) DeletePeerTurnCfg(peerKey string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	delete(c.ifaceConfig.turnPeerMap, peerKey)
}

func DumpProxyConnsInfo(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case <-DumpSignalChan:
			GetCfg().Dump()
		}
	}
}
