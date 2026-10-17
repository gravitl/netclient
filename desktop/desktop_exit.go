package desktop

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/uiapi"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
)

// desktopWantsIGW reports whether the active desktop session wants exit routing.
// Headless returns false.
func desktopWantsIGW() bool {
	user, tenant, ok := desktopSessionIdentity()
	return ok && config.GetDesiredWantIGW(user, tenant)
}

// rememberDesiredWantIGW records that the desktop user still wants an exit
// after the server advertised one and local routes were installed.
func rememberDesiredWantIGW() {
	user, tenant, ok := desktopSessionIdentity()
	if !ok {
		return
	}
	_ = config.SetDesiredWantIGW(user, tenant, true)
}

// desktopExitDecision is the desired-state fragment of the IGW decision log.
// Headless has nothing to read and reports that the session is inactive.
func desktopExitDecision() string {
	user, tenant, ok := desktopSessionIdentity()
	if !ok {
		return "desktop_session=false"
	}
	return fmt.Sprintf("want_igw=%v auto_exit=%v desired_egress=%s",
		config.GetDesiredWantIGW(user, tenant),
		config.GetDesiredAutoExit(user, tenant),
		config.GetDesiredEgressID(user, tenant))
}

// desktopWantsExitApply decides whether to install exit routes after an iface
// rebuild. A server-advertised exit always applies. Otherwise a desktop session
// that still wants one applies too. When neither is true, the server is asked
// again and this returns false so the caller leaves routes alone.
func desktopWantsExitApply(pull models.HostPull, pullErr error) bool {
	wantIGW := desktopWantsIGW()
	localDesired := locallyConnectedDesired()
	if wantIGW && localDesired {
		return true
	}
	// Silent here once cost a full session of "connected but no exit": the
	// restore finished clean while the server still advertised no gateway.
	logger.Log(0, fmt.Sprintf(
		"exit apply skipped after reconnect: change_default_gw=%v pull_err=%v want_igw=%v locally_connected_desired=%v",
		pull.ChangeDefaultGw, pullErr != nil, wantIGW, localDesired))
	reconcileDesiredExit()
	return false
}

// exitReconcileInterval bounds how often the client may re-drive the server exit
// selection, so a server that simply has no exit available is not hammered.
const exitReconcileInterval = 30 * time.Second

var lastExitReconcile atomic.Int64

// exitSelectInFlight is true while a clear→assign (or manual select) PUT window
// is open. reconcileDesiredExit skips so ChangeDefaultGw=false from the clear
// half cannot race and re-select a different exit under us.
var exitSelectInFlight atomic.Bool

func beginExitSelect() { exitSelectInFlight.Store(true) }
func endExitSelect()   { exitSelectInFlight.Store(false) }

// reconcileDesiredExit re-selects the exit node on the server when local desired
// state still wants one but the server keeps advertising none.
//
// Logout clears the server selection and login re-selects it. When that PUT is
// lost, or the server has not converged by the time restore gives up, peer
// updates keep arriving with ChangeDefaultGw=false and nothing ever asks again:
// the host sits connected with no exit and split DNS, which reads to the user as
// "DNS was not switched to Netmaker".
//
// This re-drives the *selection* rather than pinning routes locally. Holding a
// local default route against the server is what black-holed traffic when an
// exit genuinely went away; asking the server again keeps it authoritative.
func reconcileDesiredExit() {
	// Logout snapshots want_igw for the next login, so desired state still asks
	// for an exit while the teardown runs. Re-selecting here would undo the
	// server-side clear that logout just issued.
	if sessionReleased.Load() {
		return
	}
	// Manual→Auto (and failover) clear then assign. The clear publishes
	// ChangeDefaultGw=false; do not reconcile over that window.
	if exitSelectInFlight.Load() {
		return
	}
	user, tenant, ok := desktopSessionIdentity()
	if !ok {
		return
	}
	if wireguard.IGWRoutingActive() {
		return
	}
	token := uiapi.SessionAuthToken()
	network := resolveAutoExitNetwork(user, tenant, token)
	autoExit := autoExitModeActive(user, tenant, network, token)
	egressID := strings.TrimSpace(config.GetDesiredEgressID(user, tenant))
	// Server-required auto exit must reconcile even when local want_igw was
	// never set (exit assigned only via EnsureAutoExitNode).
	if !config.GetDesiredWantIGW(user, tenant) && !autoExit {
		return
	}
	if token == "" || network == "" || (egressID == "" && !autoExit) {
		return
	}

	now := time.Now().UnixNano()
	last := lastExitReconcile.Load()
	if last != 0 && time.Duration(now-last) < exitReconcileInterval {
		return
	}
	if !lastExitReconcile.CompareAndSwap(last, now) {
		return
	}

	go func() {
		if exitSelectInFlight.Load() {
			return
		}
		// Auto mode must never call SelectDeviceExitNode: that persists a fixed
		// egress and clears auto_exit. Re-pick nearest using the IGW-failure
		// blacklist only — never exclude the in-flight desired id (manual→Auto
		// clear→assign would otherwise drop the exit we just chose and snap
		// back to the previous one).
		if autoExit {
			logger.Log(0, "exit reconcile: auto-exit re-picking nearest on "+network)
			exclude := autoExitReconcileExclude()
			if _, err := selectNearestDeviceExitNodeExcluding(network, token, nil, exclude); err != nil {
				logger.Log(0, "exit reconcile: auto-exit re-pick failed:", err.Error())
				// Soft retry with no exclude so a full failure blacklist cannot
				// leave the host with no exit when another (including the
				// desired id) is still up.
				if _, err2 := selectNearestDeviceExitNodeExcluding(network, token, nil, nil); err2 != nil {
					logger.Log(0, "exit reconcile: nearest fallback failed:", err2.Error())
				}
			}
			return
		}
		logger.Log(0, fmt.Sprintf(
			"exit reconcile: server advertises no exit while %s is desired on %s; re-selecting",
			egressID, network))
		if _, err := SelectDeviceExitNode(network, token, egressID); err != nil {
			logger.Log(0, "exit reconcile: re-select failed:", err.Error())
		}
	}()
}

func locallyConnectedDesired() bool {
	if !uiapi.IsSessionActive() {
		return false
	}
	user, tenant := uiapi.SessionIdentity()
	desired := filterDesiredNetworks(config.GetDesiredNetworks(user, tenant), uiapi.RestrictToSingleNetwork())
	nodes := config.GetNodes()
	for _, network := range desired {
		if node, ok := nodes[network]; ok && node.Connected {
			return true
		}
	}
	return false
}
