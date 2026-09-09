package proxyuplink

import (
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/networking"
	"github.com/gravitl/netmaker/schema"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// RelayPeerUDPEndpoint returns the WireGuard UDP endpoint (host:port) for the relay node ID,
// using NetworkPeerIDs and HostPeers. Empty if not found.
// Falls back to cached PeerIDs when peer-info cache was cleared (e.g. disconnect SIGHUP).
//
// Uses the server-published HostPeers endpoint (not EndpointCache). If endpoint detection
// later moves the live WG peer to a private LAN address, Bind.Send will not match this
// divert key and will use UDP directly — which is intentional when LAN works.
func RelayPeerUDPEndpoint(relayNodeID string) string {
	if relayNodeID == "" {
		return ""
	}
	if ep := relayEndpointFromPeerInfo(relayNodeID); ep != "" {
		return ep
	}
	return relayEndpointFromPeerIDs(relayNodeID)
}

func relayEndpointFromPeerInfo(relayNodeID string) string {
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
			if ep := hostPeerEndpoint(pubKeyStr); ep != "" {
				return ep
			}
		}
	}
	return ""
}

func relayEndpointFromPeerIDs(relayNodeID string) string {
	peerIDsMu.RLock()
	defer peerIDsMu.RUnlock()
	for pub, ida := range lastPeerIDs {
		if ida.ID != relayNodeID {
			continue
		}
		if ep := hostPeerEndpoint(pub); ep != "" {
			return ep
		}
	}
	return ""
}

func hostPeerEndpoint(pubKeyStr string) string {
	pk, err := wgtypes.ParseKey(pubKeyStr)
	if err != nil {
		return ""
	}
	host := config.Netclient()
	if host == nil {
		return ""
	}
	for _, p := range host.HostPeers {
		if p.PublicKey == pk && p.Endpoint != nil {
			return p.Endpoint.String()
		}
	}
	return ""
}
