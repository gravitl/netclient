package proxyuplink

import (
	"sync"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/models"
	"github.com/gravitl/netmaker/schema"
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

// GatewayListenConfig is returned by FindTCPGateway.
type GatewayListenConfig struct {
	Node       config.Node
	ListenPort int
	ListenAddr string
	TLSMode    string
}

// FindTCPGateway returns the first local gateway node that should listen for TCP uplinks.
// Listen enable/port/mode are host-level (peer update Host); node TcpProxy* is a fallback.
func FindTCPGateway() (cfg GatewayListenConfig, ok bool) {
	host := config.Netclient()
	hostEnabled := host != nil && host.TcpProxyEnabled
	hostPort := 0
	hostAddr := ""
	hostMode := ""
	if host != nil {
		hostPort = host.TcpProxyListenPort
		hostAddr = host.TcpProxyListenAddr
		hostMode = host.TcpProxyTLSMode
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
		mode := hostMode
		if mode == "" {
			mode = n.TcpProxyTLSMode
		}
		if mode == "" {
			mode = schema.TcpProxyTLSModeSelfSigned
		}
		return GatewayListenConfig{
			Node:       n,
			ListenPort: port,
			ListenAddr: hostAddr,
			TLSMode:    mode,
		}, true
	}
	return GatewayListenConfig{}, false
}

// TcpProxyEndpointForRelay returns the WSS URL (or legacy host:port) for the gateway node ID.
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

// TcpProxyCertFingerprintForRelay returns the published cert fingerprint for the gateway.
func TcpProxyCertFingerprintForRelay(relayNodeID string) string {
	if relayNodeID == "" {
		return ""
	}
	peerIDsMu.RLock()
	defer peerIDsMu.RUnlock()
	for _, ida := range lastPeerIDs {
		if ida.ID == relayNodeID {
			return ida.TcpProxyCertFingerprint
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
