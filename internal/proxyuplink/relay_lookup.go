package proxyuplink

import (
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/networking"
	"github.com/gravitl/netmaker/schema"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// RelayPeerUDPEndpoint returns the WireGuard UDP endpoint (host:port) for the relay node ID,
// using NetworkPeerIDs and HostPeers. Empty if not found.
func RelayPeerUDPEndpoint(relayNodeID string) string {
	if relayNodeID == "" {
		return ""
	}
	peerInfo, err := networking.GetPeerInfo()
	if err != nil {
		return ""
	}
	for _, node := range config.GetNodes() {
		if node.RelayedBy != relayNodeID {
			continue
		}
		pm, ok := peerInfo.NetworkPeerIDs[schema.NetworkID(node.Network)]
		if !ok {
			continue
		}
		for pubKeyStr, ida := range pm {
			if ida.ID != relayNodeID {
				continue
			}
			pk, err := wgtypes.ParseKey(pubKeyStr)
			if err != nil {
				continue
			}
			for _, p := range config.Netclient().HostPeers {
				if p.PublicKey == pk && p.Endpoint != nil {
					return p.Endpoint.String()
				}
			}
		}
	}
	return ""
}
