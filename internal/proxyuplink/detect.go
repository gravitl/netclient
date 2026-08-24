package proxyuplink

import (
	"sync"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/models"
)

const DefaultListenPort = 443

var (
	peerIDsMu   sync.RWMutex
	lastPeerIDs models.PeerMap
)

// UpdatePeerIDs caches PeerIDs / peer_ids from HostPull or HostPeerUpdate for TCP endpoint lookup.
// Ignores nil/empty maps so a partial peer update cannot wipe pubkey↔node mappings needed
// for ClientHello / gateway peer route registration after a GW restart.
func UpdatePeerIDs(m models.PeerMap) {
	if len(m) == 0 {
		return
	}
	peerIDsMu.Lock()
	defer peerIDsMu.Unlock()
	cp := make(models.PeerMap, len(m))
	for k, v := range m {
		cp[k] = v
	}
	lastPeerIDs = cp
}

// CachedPeerIDs returns a copy of PeerIDs from the last host pull / peer update.
func CachedPeerIDs() models.PeerMap {
	peerIDsMu.RLock()
	defer peerIDsMu.RUnlock()
	if len(lastPeerIDs) == 0 {
		return nil
	}
	cp := make(models.PeerMap, len(lastPeerIDs))
	for k, v := range lastPeerIDs {
		cp[k] = v
	}
	return cp
}

// NeedsUserspaceWG reports whether TCP uplink client or gateway listen requires userspace WireGuard conn.Bind.
func NeedsUserspaceWG() bool {
	if h := config.Netclient(); h != nil && h.TcpProxyEnabled {
		return true
	}
	for _, n := range config.GetNodes() {
		if n.UseTcpUplink || n.TcpProxyEnabled {
			return true
		}
	}
	return false
}

// FindUplinkClient returns the first local node opted into TCP uplink to its gateway.
// Requires Connected so disconnect stops the TCP client without flipping userspace WG mode.
func FindUplinkClient() (config.Node, bool) {
	for _, n := range config.GetNodes() {
		if n.Connected && n.UseTcpUplink && n.RelayedBy != "" {
			return n, true
		}
	}
	return config.Node{}, false
}

// FindTCPGateway returns the first local gateway node that should listen for TCP uplinks.
// Listen enable/port are host-level (peer update Host); node TcpProxy* is a fallback for older servers.
func FindTCPGateway() (node config.Node, listenPort int, ok bool) {
	host := config.Netclient()
	hostEnabled := host != nil && host.TcpProxyEnabled
	hostPort := 0
	if host != nil {
		hostPort = host.TcpProxyListenPort
	}
	for _, n := range config.GetNodes() {
		if !(n.IsGw || n.IsRelay || n.IsIngressGateway) {
			continue
		}
		if !hostEnabled && !n.TcpProxyEnabled {
			continue
		}
		port := hostPort
		if port <= 0 {
			port = n.TcpProxyListenPort
		}
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
