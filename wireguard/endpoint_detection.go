package wireguard

import (
	"net"
	"sync"

	"github.com/gravitl/netclient/cache"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	"github.com/gravitl/netmaker/schema"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// endpointCacheSnapshotMutex guards lastPeerHostInfo.
var endpointCacheSnapshotMutex sync.Mutex

// lastPeerHostInfo - HostNetworkInfo of the peers in the previous peer update.
// Endpoint-detection cache entries are only valid for the peer state they were
// detected under.
var lastPeerHostInfo models.HostInfoMap

// DropStaleEndpointCaches drops both endpoint-detection cache entries of every
// peer whose state changed since the previous peer update: peers missing from
// or removed by the update, and peers whose HostNetworkInfo ListenPort or
// Interfaces set differs. A cached endpoint was derived from exactly that
// info, so it must not outlive it; dropping lets checkForBetterEndpoint fall
// back to the server endpoint and detection run again.
func DropStaleEndpointCaches(peers []wgtypes.PeerConfig, info models.HostInfoMap) {
	endpointCacheSnapshotMutex.Lock()
	defer endpointCacheSnapshotMutex.Unlock()
	live := make(models.HostInfoMap, len(peers))
	for _, p := range peers {
		if p.Remove {
			continue
		}
		pk := p.PublicKey.String()
		live[pk] = info[pk]
	}
	drop := func(pk string) {
		cache.EndpointCache.Delete(pk)
		cache.SkipEndpointCache.Delete(pk)
	}
	for pk, prev := range lastPeerHostInfo {
		cur, ok := live[pk]
		if !ok || hostNetworkInfoChanged(prev, cur) {
			drop(pk)
		}
	}
	for _, c := range []*sync.Map{&cache.EndpointCache, &cache.SkipEndpointCache} {
		c.Range(func(k, _ any) bool {
			pk, ok := k.(string)
			if !ok {
				return true
			}
			if _, ok := live[pk]; !ok {
				drop(pk)
			}
			return true
		})
	}
	lastPeerHostInfo = live
}

// hostNetworkInfoChanged reports whether the endpoint-relevant peer state
// changed: ListenPort or the Interfaces set, independent of their order.
func hostNetworkInfoChanged(prev, cur models.HostNetworkInfo) bool {
	if prev.ListenPort != cur.ListenPort {
		return true
	}
	return !sameHostInterfaces(prev.Interfaces, cur.Interfaces)
}

// sameHostInterfaces reports whether a and b hold the same interface set.
func sameHostInterfaces(a, b []schema.Iface) bool {
	if len(a) != len(b) {
		return false
	}
	set := make(map[string]struct{}, len(a))
	for _, i := range a {
		set[i.Name+" "+i.Address.String()] = struct{}{}
	}
	for _, i := range b {
		if _, ok := set[i.Name+" "+i.Address.String()]; !ok {
			return false
		}
	}
	return true
}

// HostPeerAllowedIPs returns AllowedIPs from non-removed host peers.
func HostPeerAllowedIPs() []net.IPNet {
	host := config.Netclient()
	if host == nil {
		return nil
	}
	var out []net.IPNet
	for _, p := range host.HostPeers {
		if p.Remove {
			continue
		}
		out = append(out, p.AllowedIPs...)
	}
	return out
}

// EgressRouteCIDRs returns site-egress networks from the models cache
// (including VirtualNAT virtual networks). Used so private-LAN endpoint
// detection does not treat tunnel-reachable VPC IPs as underlays.
func EgressRouteCIDRs() []net.IPNet {
	routes := GetEgressRoutesFromCache()
	if len(routes) == 0 {
		return nil
	}
	var out []net.IPNet
	for _, r := range routes {
		for _, em := range r.EgressRangesWithMetric {
			n := config.ToIPNet(em.Network)
			if em.Nat && em.Mode == schema.VirtualNAT && em.VirtualNetwork != "" {
				n = config.ToIPNet(em.VirtualNetwork)
			}
			if n.IP == nil {
				continue
			}
			out = append(out, n)
		}
	}
	return out
}

// EndpointDetectionSkipCIDRs merges peer AllowedIPs with cached egress CIDRs.
// An IP inside these ranges is reachable via the mesh/egress path, not as a
// direct underlay for WireGuard UDP.
func EndpointDetectionSkipCIDRs(peerAllowed []net.IPNet) []net.IPNet {
	out := make([]net.IPNet, 0, len(peerAllowed)+8)
	out = append(out, peerAllowed...)
	out = append(out, EgressRouteCIDRs()...)
	return out
}

// IPCoveredByCIDRs reports whether ip falls in any of cidrs.
func IPCoveredByCIDRs(ip net.IP, cidrs []net.IPNet) bool {
	if ip == nil || len(cidrs) == 0 {
		return false
	}
	for i := range cidrs {
		if cidrs[i].Contains(ip) {
			return true
		}
	}
	return false
}

// IsMeshRoutedEndpointIP reports whether ip must not be used as a detected
// underlay endpoint (covered by peer AllowedIPs or egress routes).
func IsMeshRoutedEndpointIP(ip net.IP, peerAllowed []net.IPNet) bool {
	return IPCoveredByCIDRs(ip, EndpointDetectionSkipCIDRs(peerAllowed))
}

// DropMeshRoutedEndpointCache removes sticky LAN detections inside mesh/egress
// CIDRs without touching the live device (SetPeers will apply HostPeers next).
func DropMeshRoutedEndpointCache(peerAllowed []net.IPNet) []string {
	cidrs := EndpointDetectionSkipCIDRs(peerAllowed)
	if len(cidrs) == 0 {
		return nil
	}
	var scrubbed []string
	cache.EndpointCache.Range(func(k, v any) bool {
		ev, ok := v.(cache.EndpointCacheValue)
		if !ok || ev.Endpoint == nil || ev.Endpoint.IP == nil {
			return true
		}
		if IPCoveredByCIDRs(ev.Endpoint.IP, cidrs) {
			logger.Log(0, "clearing detected endpoint inside egress/allowed CIDR",
				ev.Endpoint.String(), "peer", fmtPeerKey(k))
			cache.EndpointCache.Delete(k)
			if pk := fmtPeerKey(k); pk != "" {
				scrubbed = append(scrubbed, pk)
			}
		}
		return true
	})
	return scrubbed
}

// ScrubEndpointCacheForMeshRoutes drops bad cached endpoints and restores the
// server-published underlay on the live device (for paths that will not
// immediately SetPeers, e.g. after egress routes are installed).
func ScrubEndpointCacheForMeshRoutes(peerAllowed []net.IPNet) {
	for _, pk := range DropMeshRoutedEndpointCache(peerAllowed) {
		restoreHostPeerPublishedEndpoint(pk)
	}
}

// restoreHostPeerPublishedEndpoint pushes the server HostPeers endpoint back
// onto the live device after a bad LAN detection was cleared.
func restoreHostPeerPublishedEndpoint(peerPubKey string) {
	host := config.Netclient()
	if host == nil || peerPubKey == "" {
		return
	}
	for _, p := range host.HostPeers {
		if p.Remove || p.PublicKey.String() != peerPubKey {
			continue
		}
		if p.Endpoint == nil || p.Endpoint.IP == nil || p.Endpoint.IP.IsUnspecified() {
			return
		}
		_ = UpdatePeer(&wgtypes.PeerConfig{
			PublicKey:                   p.PublicKey,
			Endpoint:                    p.Endpoint,
			AllowedIPs:                  p.AllowedIPs,
			PersistentKeepaliveInterval: p.PersistentKeepaliveInterval,
			ReplaceAllowedIPs:           true,
			UpdateOnly:                  true,
		})
		return
	}
}

func fmtPeerKey(k any) string {
	if s, ok := k.(string); ok {
		return s
	}
	return ""
}
