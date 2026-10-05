package functions

import (
	"strings"
	"sync"
	"time"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/uiapi"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	"golang.org/x/exp/slog"
)

const (
	autoExitFailoverCooldown = 90 * time.Second
	autoExitFailedTTL        = 10 * time.Minute
)

var (
	autoExitFailoverMu   sync.Mutex
	autoExitFailoverBusy bool
	autoExitLastFailover time.Time
	autoExitFailedMu     sync.Mutex
	autoExitFailed       = map[string]time.Time{} // egressID -> when marked failed
)

func init() {
	wireguard.OnIGWRoutingChanged = reconfigureDNSAfterRouting
	wireguard.OnIGWUnhealthy = handleIGWUnhealthyAutoExit
}

// handleIGWUnhealthyAutoExit is the IGW monitor hook: when the current exit is
// marked unhealthy and auto-exit is active (local AUTO or server-required
// auto_select_exit_node), pick the next nearest available exit.
func handleIGWUnhealthyAutoExit(publicKey string) {
	if sessionReleased.Load() {
		return
	}
	user, tenant, ok := desktopSessionIdentity()
	if !ok {
		return
	}
	token := uiapi.SessionAuthToken()
	network := resolveAutoExitNetwork(user, tenant, token)
	if token == "" || network == "" || !autoExitModeActive(user, tenant, network, token) {
		slog.Debug("auto-exit failover skipped: not in auto mode or missing network/token",
			"network", network)
		return
	}

	autoExitFailoverMu.Lock()
	if autoExitFailoverBusy {
		autoExitFailoverMu.Unlock()
		return
	}
	if !autoExitLastFailover.IsZero() && time.Since(autoExitLastFailover) < autoExitFailoverCooldown {
		autoExitFailoverMu.Unlock()
		slog.Info("auto-exit failover skipped: cooldown",
			"remaining", (autoExitFailoverCooldown - time.Since(autoExitLastFailover)).Round(time.Second))
		return
	}
	autoExitFailoverBusy = true
	autoExitFailoverMu.Unlock()

	defer func() {
		autoExitFailoverMu.Lock()
		autoExitFailoverBusy = false
		autoExitFailoverMu.Unlock()
	}()

	if err := failoverAutoExit(network, token, publicKey); err != nil {
		logger.Log(0, "auto-exit failover failed:", err.Error())
		return
	}
	autoExitFailoverMu.Lock()
	autoExitLastFailover = time.Now()
	autoExitFailoverMu.Unlock()
}

// autoExitModeActive is true for local AUTO desired state or when the server
// network requires auto_select_exit_node.
func autoExitModeActive(user, tenant, network, token string) bool {
	if config.GetDesiredAutoExit(user, tenant) {
		return true
	}
	network = strings.TrimSpace(network)
	if network == "" || strings.TrimSpace(token) == "" {
		return false
	}
	required, err := NetworkRequiresAutoExit(network, config.CurrServer, token)
	return err == nil && required
}

// resolveAutoExitNetwork prefers the stored exit network, then any connected
// network that requires server-enforced auto exit.
func resolveAutoExitNetwork(user, tenant, token string) string {
	if n := strings.TrimSpace(config.GetDesiredExitNetwork(user, tenant)); n != "" {
		return n
	}
	if strings.TrimSpace(token) == "" {
		return ""
	}
	for name, node := range config.GetNodes() {
		if !node.Connected {
			continue
		}
		required, err := NetworkRequiresAutoExit(name, config.CurrServer, token)
		if err == nil && required {
			return name
		}
	}
	return ""
}

func failoverAutoExit(network, token, failedPublicKey string) error {
	// Brief settle after LAN restore so overlay metrics probes to alternate
	// exits are less likely to time out and rank a worse peer first.
	time.Sleep(500 * time.Millisecond)

	nodes, err := ListDeviceExitNodes(network, token)
	if err != nil {
		return err
	}
	// List attaches public latencies for GUI/Auto pick. Failover re-ranks on
	// overlay metrics-port RTTs so the next exit is nearest on the live mesh.
	attachExitNodeOverlayLatencies(network, nodes)

	user, tenant := uiapi.SessionIdentity()
	cur := strings.TrimSpace(config.GetDesiredEgressID(user, tenant))

	exclude := failedEgressExcludeSet()
	if cur != "" {
		rememberFailedEgress(cur)
		exclude[cur] = struct{}{}
	}
	for _, id := range egressIDsForPeerKey(failedPublicKey, nodes) {
		rememberFailedEgress(id)
		exclude[id] = struct{}{}
	}
	for i := range nodes {
		if nodes[i].Selected && strings.TrimSpace(nodes[i].EgressID) != "" {
			rememberFailedEgress(nodes[i].EgressID)
			exclude[nodes[i].EgressID] = struct{}{}
		}
	}

	pick, err := selectNearestDeviceExitNodeExcluding(network, token, nodes, exclude)
	if err != nil {
		// Last resort: only exclude the current id so we don't get stuck if the
		// blacklist covered every exit.
		soft := map[string]struct{}{}
		if cur != "" {
			soft[cur] = struct{}{}
		}
		pick, err = selectNearestDeviceExitNodeExcluding(network, token, nodes, soft)
		if err != nil {
			return err
		}
	}

	logger.Log(0, "auto-exit failover: switched to", pick.EgressID, "on", network,
		"(failed peer", failedPublicKey+")")
	slog.Info("auto-exit failover selected next exit",
		"network", network,
		"egress_id", pick.EgressID,
		"failed_peer", failedPublicKey,
	)
	return nil
}

func rememberFailedEgress(egressID string) {
	egressID = strings.TrimSpace(egressID)
	if egressID == "" {
		return
	}
	autoExitFailedMu.Lock()
	defer autoExitFailedMu.Unlock()
	autoExitFailed[egressID] = time.Now()
}

func failedEgressExcludeSet() map[string]struct{} {
	autoExitFailedMu.Lock()
	defer autoExitFailedMu.Unlock()
	now := time.Now()
	out := make(map[string]struct{}, len(autoExitFailed))
	for id, at := range autoExitFailed {
		if now.Sub(at) > autoExitFailedTTL {
			delete(autoExitFailed, id)
			continue
		}
		out[id] = struct{}{}
	}
	return out
}

// autoExitReconcileExclude is the set reconcileDesiredExit uses when re-picking
// nearest. It is the IGW-failure blacklist only — never the in-flight desired
// egress id (manual→Auto clear→assign must not exclude the exit just chosen).
func autoExitReconcileExclude() map[string]struct{} {
	return failedEgressExcludeSet()
}

// egressIDsForPeerKey maps a WireGuard peer public key to exit egress IDs by
// matching overlay Address/Address6 or the peer's underlay AllowedEndpoints.
func egressIDsForPeerKey(publicKey string, nodes []models.DeviceExitNode) []string {
	publicKey = strings.TrimSpace(publicKey)
	if publicKey == "" || wireguard.IsZeroWGPublicKey(publicKey) {
		return nil
	}
	peer, err := wireguard.GetPeer(ncutils.GetInterfaceName(), publicKey)
	if err != nil {
		return nil
	}
	overlayHosts := map[string]struct{}{}
	for _, ipn := range peer.AllowedIPs {
		if ip := ipn.IP; ip != nil && !ip.IsUnspecified() && !ip.IsLoopback() {
			overlayHosts[ip.String()] = struct{}{}
		}
	}
	underlayHost := ""
	if peer.Endpoint != nil {
		underlayHost = publicProbeHost(peer.Endpoint.IP.String())
	}
	var ids []string
	seen := map[string]struct{}{}
	for i := range nodes {
		id := strings.TrimSpace(nodes[i].EgressID)
		if id == "" {
			continue
		}
		match := false
		if addr := strings.TrimSpace(nodes[i].Address); addr != "" {
			if _, ok := overlayHosts[addr]; ok {
				match = true
			}
		}
		if !match {
			if addr := strings.TrimSpace(nodes[i].Address6); addr != "" {
				if _, ok := overlayHosts[addr]; ok {
					match = true
				}
			}
		}
		if !match && underlayHost != "" {
			for _, ep := range nodes[i].AllowedEndpoints {
				if publicProbeHost(ep) == underlayHost {
					match = true
					break
				}
			}
		}
		if !match {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	return ids
}

// resetAutoExitFailoverStateForTest clears failover bookkeeping (unit tests).
func resetAutoExitFailoverStateForTest() {
	autoExitFailoverMu.Lock()
	autoExitFailoverBusy = false
	autoExitLastFailover = time.Time{}
	autoExitFailoverMu.Unlock()
	autoExitFailedMu.Lock()
	autoExitFailed = map[string]time.Time{}
	autoExitFailedMu.Unlock()
}
