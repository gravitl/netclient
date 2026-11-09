package desktop

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/functions"
	"github.com/gravitl/netclient/uiapi"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
)

// desktopWantsIGW reports whether the active desktop session wants exit routing.
// Headless returns false.
func desktopWantsIGW() bool {
	user, tenant, ok := desktopSessionIdentity()
	return ok && desiredWantsIGW(user, tenant)
}

// desiredWantsIGW is true when want_igw is set, or when a stored egress id /
// auto_exit implies exit intent (partial / older desired state). Without this,
// the first post-connect apply skips with want_igw=false while reconcile later
// re-selects the same egress.
func desiredWantsIGW(user, tenant string) bool {
	if config.GetDesiredWantIGW(user, tenant) {
		return true
	}
	if strings.TrimSpace(config.GetDesiredEgressID(user, tenant)) != "" {
		return true
	}
	return config.GetDesiredAutoExit(user, tenant)
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

// desktopWantsExitApply runs only when the server is not advertising an exit
// (shouldApplyExitAfterReconnect already returned for ChangeDefaultGw=true).
// forceApplyInternetGw cannot install without that flag, so returning true here
// only burned ~10s of retries. When desire still wants an exit, re-drive server
// selection immediately and leave local routes alone.
func desktopWantsExitApply(pull models.HostPull, pullErr error) bool {
	wantIGW := desktopWantsIGW()
	localDesired := locallyConnectedDesired()
	logger.Log(0, fmt.Sprintf(
		"exit apply skipped after reconnect: change_default_gw=%v pull_err=%v want_igw=%v locally_connected_desired=%v",
		pull.ChangeDefaultGw, pullErr != nil, wantIGW, localDesired))
	if wantIGW && localDesired {
		reconcileDesiredExit()
	}
	return false
}

// exitReconcileInterval bounds how often the client may re-drive the server exit
// selection, so a server that simply has no exit available is not hammered.
const exitReconcileInterval = 30 * time.Second

// restoreIGWHoldDeadline bounds how long ChangeDefaultGw=false teardown may be
// deferred for session restore. Longer than exitPhaseDeadline so a normal
// restore can finish; short enough that a hung restore cannot black-hole forever.
const restoreIGWHoldDeadline = 45 * time.Second

var lastExitReconcile atomic.Int64

// exitSelectInFlight is true while a clear→assign (or manual select) PUT window
// is open. reconcileDesiredExit skips so ChangeDefaultGw=false from the clear
// half cannot race and re-select a different exit under us.
var exitSelectInFlight atomic.Bool

// pendingExitReconcile is set when MQTT defers IGW teardown during a hold.
// Cleared when onExitHoldReleased runs after select/restore completes.
var pendingExitReconcile atomic.Bool

func beginExitSelect() { exitSelectInFlight.Store(true) }

func endExitSelect() {
	was := exitSelectInFlight.Swap(false)
	if was {
		onExitHoldReleased()
	}
}

func notePendingExitReconcile() { pendingExitReconcile.Store(true) }

// holdIGWTeardown is true while Desktop still wants an exit and tearing down on
// ChangeDefaultGw=false would open a long gap until reconcile re-selects.
// Covers the clear→assign window and session-restore phases (bounded). Logout
// clears sessionReleased / desire so genuine clears still restore the LAN gateway.
func holdIGWTeardown() bool {
	if sessionReleased.Load() {
		return false
	}
	if !desktopWantsIGW() {
		return false
	}
	if exitSelectInFlight.Load() {
		return true
	}
	return restorePhaseWithinHoldDeadline()
}

// restorePhaseWithinHoldDeadline is true only while Networks/Exit/Routes is
// active and younger than restoreIGWHoldDeadline.
func restorePhaseWithinHoldDeadline() bool {
	switch uiapi.GetRestorePhase() {
	case uiapi.RestorePhaseNetworks, uiapi.RestorePhaseExit, uiapi.RestorePhaseRoutes:
		started := uiapi.RestorePhaseStartedAt()
		if started.IsZero() || time.Since(started) > restoreIGWHoldDeadline {
			return false
		}
		return true
	default:
		return false
	}
}

// onExitHoldReleased runs when exitSelectInFlight clears or restore becomes idle.
// Mid-hold MQTT reconcile is a no-op (in-flight / active IGW); this is where
// deferred teardown either re-drives selection or finishes LAN restore.
func onExitHoldReleased() {
	pending := pendingExitReconcile.Swap(false)
	if sessionReleased.Load() {
		return
	}
	if desktopWantsIGW() {
		// Successful assign: routes live, nothing deferred → skip (avoid a
		// redundant select PUT). Deferred MQTT or failed assign (no IGW) → re-drive.
		if pending || !wireguard.IGWRoutingActive() {
			logger.Log(0, "exit hold released: re-driving exit selection")
			reconcileDesiredExitOpts(true)
		}
		return
	}
	if pending || wireguard.IGWRoutingActive() {
		logger.Log(0, "exit hold released: desire cleared; restoring LAN gateway")
		functions.RestoreInternetGwAndDNS()
	}
}

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
	reconcileDesiredExitOpts(false)
}

// reconcileDesiredExitOpts re-drives exit selection. When allowActiveIGW is true
// (hold just released), skip the IGWRoutingActive guard so a deferred CurrGw
// with server advertising no exit still re-PUTs. Never skip exitSelectInFlight —
// that would race clear→assign.
func reconcileDesiredExitOpts(allowActiveIGW bool) {
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
	if !allowActiveIGW && wireguard.IGWRoutingActive() {
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
			if _, err := selectNearestDeviceExitNodeExcluding(network, token, nil, exclude, true); err != nil {
				logger.Log(0, "exit reconcile: auto-exit re-pick failed:", err.Error())
				// Soft retry with no exclude so a full failure blacklist cannot
				// leave the host with no exit when another (including the
				// desired id) is still up.
				if _, err2 := selectNearestDeviceExitNodeExcluding(network, token, nil, nil, true); err2 != nil {
					logger.Log(0, "exit reconcile: nearest fallback failed:", err2.Error())
				}
			}
			return
		}
		logger.Log(0, fmt.Sprintf(
			"exit reconcile: server advertises no exit while %s is desired on %s; re-selecting",
			egressID, network))
		if _, err := selectDeviceExitNodeForReconcile(network, token, egressID); err != nil {
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
