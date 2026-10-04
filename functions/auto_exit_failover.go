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
	wireguard.OnIGWUnhealthy = handleIGWUnhealthyAutoExit
}

// handleIGWUnhealthyAutoExit is the IGW monitor hook: when the current exit is
// marked unhealthy and the user is in auto-exit mode, pick the next nearest
// available exit (excluding the failed one).
func handleIGWUnhealthyAutoExit(publicKey string) {
	if sessionReleased.Load() {
		return
	}
	user, tenant, ok := desktopSessionIdentity()
	if !ok || !config.GetDesiredAutoExit(user, tenant) {
		return
	}
	network := strings.TrimSpace(config.GetDesiredExitNetwork(user, tenant))
	token := uiapi.SessionAuthToken()
	if network == "" || token == "" {
		slog.Debug("auto-exit failover skipped: missing network or token")
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

func failoverAutoExit(network, token, failedPublicKey string) error {
	nodes, err := ListDeviceExitNodes(network, token)
	if err != nil {
		return err
	}

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

// egressIDsForPeerKey maps a WireGuard peer public key to exit egress IDs by
// matching the peer's underlay endpoint against AllowedEndpoints.
func egressIDsForPeerKey(publicKey string, nodes []models.DeviceExitNode) []string {
	publicKey = strings.TrimSpace(publicKey)
	if publicKey == "" || wireguard.IsZeroWGPublicKey(publicKey) {
		return nil
	}
	peer, err := wireguard.GetPeer(ncutils.GetInterfaceName(), publicKey)
	if err != nil || peer.Endpoint == nil {
		return nil
	}
	host := publicProbeHost(peer.Endpoint.IP.String())
	if host == "" {
		return nil
	}
	var ids []string
	seen := map[string]struct{}{}
	for i := range nodes {
		id := strings.TrimSpace(nodes[i].EgressID)
		if id == "" {
			continue
		}
		for _, ep := range nodes[i].AllowedEndpoints {
			if publicProbeHost(ep) != host {
				continue
			}
			if _, ok := seen[id]; ok {
				break
			}
			seen[id] = struct{}{}
			ids = append(ids, id)
			break
		}
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
