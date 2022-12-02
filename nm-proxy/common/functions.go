package common

import (
	"github.com/gravitl/netclient/nm-proxy/models"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func GetPeer(network string, peerKey wgtypes.Key) (*models.Conn, bool) {
	var peerInfo *models.Conn
	found := false
	peerConnMap, ok := GetNetworkMap(network)
	if !ok {
		return nil, found
	}
	peerInfo, found = peerConnMap[peerKey.String()]
	return peerInfo, found

}

func UpdatePeer(network string, peer *models.Conn) {
	peer.Mutex.Lock()
	defer peer.Mutex.Unlock()
	if _, ok := WgIfaceMap.NetworkPeerMap[network]; ok {
		WgIfaceMap.NetworkPeerMap[network][peer.Key.String()] = peer
	}

}

func GetNetworkMap(network string) (models.PeerConnMap, bool) {
	peerConnMap, found := WgIfaceMap.NetworkPeerMap[network]
	return peerConnMap, found
}
