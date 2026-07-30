package proxyuplink

import (
	"sync"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/models"
)

const DefaultListenPort = 443

var (
	peerIDsMu  sync.RWMutex
	lastPeerIDs models.PeerMap
)

// UpdatePeerIDs caches PeerIDs / peer_ids from HostPull or HostPeerUpdate for TCP endpoint lookup.
func UpdatePeerIDs(m models.PeerMap) {
	peerIDsMu.Lock()
	defer peerIDsMu.Unlock()
	if m == nil {
		lastPeerIDs = nil
		return
	}
	cp := make(models.PeerMap, len(m))
	for k, v := range m {
		cp[k] = v
	}
	lastPeerIDs = cp
}

// NeedsUserspaceWG reports whether TCP uplink client or gateway listen requires userspace WireGuard conn.Bind.
func NeedsUserspaceWG() bool {
	for _, n := range config.GetNodes() {
		if n.UseTcpUplink || n.TcpProxyEnabled {
			return true
		}
	}
	return false
}

// FindUplinkClient returns the first local node opted into TCP uplink to its gateway.
func FindUplinkClient() (config.Node, bool) {
	for _, n := range config.GetNodes() {
		if n.UseTcpUplink && n.RelayedBy != "" {
			return n, true
		}
	}
	return config.Node{}, false
}

// FindTCPGateway returns the first local gateway node with TCP uplink listen enabled.
func FindTCPGateway() (node config.Node, listenPort int, ok bool) {
	for _, n := range config.GetNodes() {
		if !n.TcpProxyEnabled {
			continue
		}
		if !(n.IsGw || n.IsRelay || n.IsIngressGateway) {
			continue
		}
		port := n.TcpProxyListenPort
		if port <= 0 {
			port = DefaultListenPort
		}
		return n, port, true
	}
	return config.Node{}, 0, false
}

// TcpProxyEndpointForRelay returns host:port for the gateway node ID from cached PeerIDs.
func TcpProxyEndpointForRelay(relayNodeID string) string {
	if relayNodeID == "" {
		return ""
	}
	peerIDsMu.RLock()
	defer peerIDsMu.RUnlock()
	for _, ida := range lastPeerIDs {
		if ida.ID == relayNodeID && ida.TcpProxyEndpoint != "" {
			return ida.TcpProxyEndpoint
		}
	}
	return ""
}

// PeerPubKeyForNode returns the WireGuard public key string for a node ID from cached PeerIDs.
func PeerPubKeyForNode(nodeID string) string {
	if nodeID == "" {
		return ""
	}
	peerIDsMu.RLock()
	defer peerIDsMu.RUnlock()
	for pub, ida := range lastPeerIDs {
		if ida.ID == nodeID {
			return pub
		}
	}
	return ""
}
