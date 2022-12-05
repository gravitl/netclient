package config

import (
	"net"

	"github.com/gravitl/netclient/nm-proxy/models"
	"github.com/gravitl/netclient/nm-proxy/wg"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	NmProxyPort = 51722
	DefaultCIDR = "127.0.0.1/8"
)

type wgIfaceConf struct {
	iface            *wg.WGIface
	ifaceKeyHash     string
	networkPeerMap   map[string]models.PeerConnMap
	peerHashMap      map[string]*models.RemotePeer
	extSrcIpMap      map[string]*models.RemotePeer
	extClientWaitMap map[string]*models.RemotePeer
	relayPeerMap     map[string]map[string]*models.RemotePeer
}

func (g *GlobalConfig) IsIfaceNil() bool {
	return g.ifaceConfig.iface == nil
}

func (g *GlobalConfig) SetIface(iface *wg.WGIface) {
	g.ifaceConfig.iface = iface
	g.setIfaceKeyHash()
}

func (g *GlobalConfig) GetIface() wgtypes.Device {
	var iface wgtypes.Device
	if g.ifaceConfig.iface != nil {
		iface = *g.ifaceConfig.iface.Device
	}
	return iface
}

func (g *GlobalConfig) setIfaceKeyHash() {
	if !g.IsIfaceNil() {
		g.ifaceConfig.ifaceKeyHash = models.ConvPeerKeyToHash(g.ifaceConfig.iface.Device.PublicKey.String())
	}
}

func (g *GlobalConfig) GetDeviceKeyHash() string {
	if !g.IsIfaceNil() {
		return g.ifaceConfig.ifaceKeyHash
	}
	return ""
}

func (g *GlobalConfig) GetDeviceKeys() (privateKey wgtypes.Key, publicKey wgtypes.Key) {
	if !g.IsIfaceNil() {
		privateKey = g.GetIface().PrivateKey
		publicKey = g.GetIface().PublicKey
	}
	return
}

func (g *GlobalConfig) CheckIfNetworkExists(network string) bool {
	_, found := g.ifaceConfig.networkPeerMap[network]
	return found
}

func (g *GlobalConfig) GetNetworkPeers(network string) models.PeerConnMap {
	return g.ifaceConfig.networkPeerMap[network]
}

func (g *GlobalConfig) UpdateNetworkPeers(network string, peers *models.PeerConnMap) {
	if peers != nil {
		g.ifaceConfig.networkPeerMap[network] = *peers
	}

}

func (g *GlobalConfig) SavePeer(network string, connConf *models.Conn) {
	if _, ok := g.ifaceConfig.networkPeerMap[network]; !ok {
		g.ifaceConfig.networkPeerMap[network] = make(models.PeerConnMap)
	}
	g.ifaceConfig.networkPeerMap[network][connConf.Key.String()] = connConf
}

func (g *GlobalConfig) GetPeer(network, peerPubKey string) (models.Conn, bool) {
	var peerConn *models.Conn
	var found bool
	if g.CheckIfNetworkExists(network) {
		if peerConn, found = g.ifaceConfig.networkPeerMap[network][peerPubKey]; found {
			return *peerConn, found
		}
	}

	return models.Conn{}, found
}

func (g *GlobalConfig) UpdatePeer(network string, updatedPeer *models.Conn) {
	if g.CheckIfNetworkExists(network) {
		if peerConf, found := g.ifaceConfig.networkPeerMap[network][updatedPeer.Key.String()]; found {
			peerConf.Mutex.Lock()
			g.ifaceConfig.networkPeerMap[network][updatedPeer.Key.String()] = updatedPeer
			peerConf.Mutex.Unlock()
		}
	}

}

func (g *GlobalConfig) ResetPeer(network, peerKey string) {
	if g.CheckIfNetworkExists(network) {
		if peerConf, found := g.ifaceConfig.networkPeerMap[network][peerKey]; found {
			peerConf.Mutex.Lock()
			peerConf.ResetConn()
			peerConf.Mutex.Unlock()
		}
	}
}

func (g *GlobalConfig) RemovePeer(network string, peerPubKey string) {
	if g.CheckIfNetworkExists(network) {
		if peerConf, found := g.ifaceConfig.networkPeerMap[network][peerPubKey]; found {
			peerConf.Mutex.Lock()
			peerConf.StopConn()
			peerConf.Mutex.Unlock()
			delete(g.ifaceConfig.networkPeerMap[network], peerPubKey)
		}
	}

}

func (g *GlobalConfig) DeleteNetworkPeers(network string) {
	delete(g.ifaceConfig.networkPeerMap, network)
}

func (g *GlobalConfig) CheckIfPeerExists(network, peerPubKey string) bool {
	if !g.CheckIfNetworkExists(network) {
		return false
	}
	_, found := g.ifaceConfig.networkPeerMap[network][peerPubKey]
	return found
}
func (g *GlobalConfig) GetNetworkPeerMap() map[string]models.PeerConnMap {
	return g.ifaceConfig.networkPeerMap
}

func (g *GlobalConfig) SavePeerByHash(peerInfo *models.RemotePeer) {
	g.ifaceConfig.peerHashMap[models.ConvPeerKeyToHash(peerInfo.PeerKey)] = peerInfo
}

func (g *GlobalConfig) GetPeerInfoByHash(peerKeyHash string) (models.RemotePeer, bool) {
	var peerInfo *models.RemotePeer
	var found bool
	if peerInfo, found = g.ifaceConfig.peerHashMap[peerKeyHash]; found {
		return *peerInfo, found
	}
	return models.RemotePeer{}, found
}

func (g *GlobalConfig) DeletePeerHash(peerKey string) {
	delete(g.ifaceConfig.peerHashMap, models.ConvPeerKeyToHash(peerKey))
}

func (g *GlobalConfig) GetExtClientInfo(udpAddr *net.UDPAddr) (models.RemotePeer, bool) {
	var peerInfo *models.RemotePeer
	var found bool
	if udpAddr == nil {
		return models.RemotePeer{}, found
	}
	if peerInfo, found = g.ifaceConfig.extSrcIpMap[udpAddr.String()]; found {
		return *peerInfo, found
	}
	return models.RemotePeer{}, found

}

func (g *GlobalConfig) SaveExtClientInfo(peerInfo *models.RemotePeer) {
	g.ifaceConfig.extSrcIpMap[peerInfo.Endpoint.String()] = peerInfo
}

func (g *GlobalConfig) DeleteExtClientInfo(udpAddr *net.UDPAddr) {
	delete(g.ifaceConfig.extSrcIpMap, udpAddr.String())
}

func (g *GlobalConfig) GetExtClientWaitCfg(peerKey string) (models.RemotePeer, bool) {
	var peerInfo *models.RemotePeer
	var found bool
	if peerInfo, found = g.ifaceConfig.extClientWaitMap[peerKey]; found {
		return *peerInfo, found
	}
	return *peerInfo, found
}

func (g *GlobalConfig) SaveExtclientWaitCfg(extPeer *models.RemotePeer) {
	g.ifaceConfig.extClientWaitMap[extPeer.PeerKey] = extPeer
}

func (g *GlobalConfig) DeleteExtWaitCfg(peerKey string) {
	if extPeerCfg, ok := g.ifaceConfig.extClientWaitMap[peerKey]; ok {
		extPeerCfg.CancelFunc()
		close(extPeerCfg.CommChan)
		delete(g.ifaceConfig.extClientWaitMap, peerKey)
	}
}

func (g *GlobalConfig) SaveRelayedPeer(relayedNodePubKey string, peer *models.RemotePeer) {
	if _, ok := g.ifaceConfig.relayPeerMap[models.ConvPeerKeyToHash(relayedNodePubKey)]; !ok {
		g.ifaceConfig.relayPeerMap[models.ConvPeerKeyToHash(relayedNodePubKey)] = make(map[string]*models.RemotePeer)
	}
	g.ifaceConfig.relayPeerMap[models.ConvPeerKeyToHash(models.ConvPeerKeyToHash(relayedNodePubKey))][models.ConvPeerKeyToHash(peer.PeerKey)] = peer
}

func (g *GlobalConfig) CheckIfRelayedNodeExists(peerHash string) bool {
	_, found := g.ifaceConfig.relayPeerMap[peerHash]
	return found
}

func (g *GlobalConfig) GetRelayedPeer(srcKeyHash, dstPeerHash string) (models.RemotePeer, bool) {
	var peer *models.RemotePeer
	var found bool
	if g.CheckIfRelayedNodeExists(srcKeyHash) {
		if peer, found = g.ifaceConfig.relayPeerMap[srcKeyHash][dstPeerHash]; found {
			return *peer, found
		}
	}

	return models.RemotePeer{}, found
}

func (g *GlobalConfig) GetInterfaceListenPort() (port int) {
	if !g.IsIfaceNil() {
		port = g.GetIface().ListenPort
	}
	return
}

func (g *GlobalConfig) UpdateWgIface(wgIface *wg.WGIface) {
	g.ifaceConfig.iface = wgIface
}
