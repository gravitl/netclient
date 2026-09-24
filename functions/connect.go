package functions

import (
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/daemon"
	"github.com/gravitl/netclient/uiapi"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	"golang.org/x/exp/slog"
)

// Disconnect disconnects a node from the given network
func Disconnect(network string) error {
	return disconnectNetwork(network, true, true)
}

// Connect will attempt to connect a node on given network
func Connect(network string) error {
	return connectNetwork(network, true)
}

func connectNetwork(network string, restart bool) error {
	nodes := config.GetNodes()
	node, ok := nodes[network]
	if !ok {
		return errors.New("no such network")
	}
	if node.Connected {
		return errors.New("node already connected")
	}
	node.Connected = true
	config.UpdateNodeMap(node.Network, node)
	if err := config.WriteNodeConfig(); err != nil {
		return fmt.Errorf("error writing node config %w", err)
	}
	if user, tenant, ok := desktopSessionIdentity(); ok {
		if err := config.RememberDesiredNetwork(user, tenant, network); err != nil {
			slog.Warn("failed to persist desired connection", "network", network, "error", err)
		}
	}
	if err := PublishNodeUpdate(&node); err != nil {
		return err
	}
	if !restart {
		return nil
	}
	return applyConnectionChange("connect")
}

// applyConnectionChange brings the live interface in line with the new node set
// without bouncing the daemon, falling back to a restart only if that fails.
func applyConnectionChange(op string) error {
	if err := applyConnectionChangeInProcess(); err != nil {
		slog.Warn("in-process apply failed; falling back to daemon restart", "op", op, "error", err)
		if err := daemon.Restart(); err != nil {
			if err := daemon.Start(); err != nil {
				return fmt.Errorf("daemon restart failed %w", err)
			}
		}
	}
	return nil
}

func disconnectNetwork(network string, restart, forgetDesired bool) error {
	nodes := config.GetNodes()
	node, ok := nodes[network]
	if !ok {
		return errors.New("no such network")
	}
	if !node.Connected {
		return errors.New("node is already disconnected")
	}
	node.Connected = false
	config.UpdateNodeMap(node.Network, node)
	if err := config.WriteNodeConfig(); err != nil {
		return fmt.Errorf("error writing node config %w", err)
	}
	if forgetDesired {
		if user, tenant, ok := desktopSessionIdentity(); ok {
			if err := config.ForgetDesiredNetwork(user, tenant, network); err != nil {
				slog.Warn("failed to clear desired connection", "network", network, "error", err)
			}
		}
		// Keep exit-node selection (desired + server). Disconnect only drops local
		// IGW routes/DNS below; reconnect/session restore re-applies exit.
	}
	done := logElapsed("disconnect node update publish")
	err := PublishNodeUpdate(&node)
	done()
	if err != nil {
		return err
	}
	if !config.AnyNodeConnected() {
		_ = wireguard.SetPeers(true)
		restoreInternetGwAndDNS()
	}
	if !restart {
		return nil
	}
	return applyConnectionChange("disconnect")
}

// desktopSessionIdentity returns the desktop session identity and whether
// desired-state should be tracked at all.
//
// Desired state exists only to restore what a desktop user had connected across
// login and reboot. Headless netclient (CLI, container, server install) has no
// UI session, so desired-state mutations are skipped: there is no user to key
// the record under, and nothing ever reads it back. The restore paths already
// gate on IsSessionActive, so gating writes on the same predicate keeps the two
// halves consistent.
func desktopSessionIdentity() (username, tenantID string, ok bool) {
	if !uiapi.IsSessionActive() {
		return "", "", false
	}
	username, tenantID = uiapi.SessionIdentity()
	if strings.TrimSpace(username) == "" {
		return "", "", false
	}
	return username, tenantID, true
}

// skipDesiredRestoreOnce is set before logout/handoff disconnect restarts the
// daemon. ApplyDesiredConnectedFlags must not undo that disconnect: the UI
// session is still active until the HTTP handler clears it.
var skipDesiredRestoreOnce atomic.Bool

func skipNextDesiredRestore() {
	skipDesiredRestoreOnce.Store(true)
}

// sessionReleased latches from logout until the next session is configured.
//
// keepLocallyConnected only applies its desired-state filter while a session is
// active, so once logout clears the session that guard disappears: a peer update
// captured before the disconnect revives Connected=true for everything, the
// iface keeps its peers, and the tunnel stays up after logout. Desired state
// cannot arbitrate here either — logout deliberately snapshots the networks so
// the next login can restore them.
var sessionReleased atomic.Bool

// beginSessionRelease suppresses Connected revival and exit reconcile for the
// logout teardown and everything after it, until a new session is configured.
func beginSessionRelease() {
	sessionReleased.Store(true)
}

func endSessionRelease() {
	sessionReleased.Store(false)
}

// RestoreDesiredConnections reconnects networks this user last had connected.
// Used after desktop login. Restarts the daemon once if anything changes.
func RestoreDesiredConnections(username, tenantID string) error {
	endSessionRelease()
	return restoreDesiredConnections(username, tenantID, uiapi.RestrictToSingleNetwork(), true)
}

// ApplyDesiredConnectedFlags sets node.Connected from persisted desired state
// without restarting. Call after Pull and before building the WireGuard iface
// so reboot / daemon reset comes up on the last connected networks.
func ApplyDesiredConnectedFlags() {
	if skipDesiredRestoreOnce.Swap(false) {
		slog.Info("skipping desired connection restore after session release")
		forceDisconnectAllNodes()
		return
	}
	if !uiapi.IsSessionActive() {
		return
	}
	user, tenant := uiapi.SessionIdentity()
	_ = restoreDesiredConnections(user, tenant, uiapi.RestrictToSingleNetwork(), false)
}

func restoreDesiredConnections(username, tenantID string, restrictSingle, restart bool) error {
	desired := filterDesiredNetworks(config.GetDesiredNetworks(username, tenantID), restrictSingle)
	if len(desired) == 0 {
		return nil
	}
	if uiapi.ShouldAbortSessionRestore() {
		return nil
	}
	uiapi.SetRestorePhase(uiapi.RestorePhaseNetworks)
	changed := false
	for _, network := range desired {
		if uiapi.ShouldAbortSessionRestore() {
			return nil
		}
		nodes := config.GetNodes()
		node, ok := nodes[network]
		if !ok || node.Connected {
			continue
		}
		if err := connectNetwork(network, false); err != nil {
			slog.Warn("failed to restore connection", "network", network, "error", err)
			continue
		}
		changed = true
	}
	if !restart {
		return nil
	}
	if uiapi.ShouldAbortSessionRestore() {
		return nil
	}
	egressID := strings.TrimSpace(config.GetDesiredEgressID(username, tenantID))
	exitNetwork := strings.TrimSpace(config.GetDesiredExitNetwork(username, tenantID))
	autoExit := config.GetDesiredAutoExit(username, tenantID)
	wantIGW := config.GetDesiredWantIGW(username, tenantID) || egressID != "" || autoExit
	if !changed && !wantIGW {
		return nil
	}

	// Brief wait for Connected — do not burn the full 10s before exit re-select.
	pull, err := waitForReconnectHostPullTimeout(desired, false, restoreConnectedTimeout)
	if err != nil {
		slog.Warn("host pull after reconnect still stale; continuing restore", "error", err)
	}
	if uiapi.ShouldAbortSessionRestore() {
		return nil
	}
	reassertDesiredConnected(desired)

	if wantIGW {
		uiapi.SetRestorePhase(uiapi.RestorePhaseExit)
		if exitNetwork == "" {
			exitNetwork = desired[len(desired)-1]
		}
		token := uiapi.SessionAuthToken()
		var selErr error
		// A peer update can install the exit while restore is still working. Once
		// routing is live there is nothing to re-select, and continuing would hold
		// the GUI on "Reconnecting exit node" long after the tunnel is usable.
		exitDeadline := time.Now().Add(exitPhaseDeadline)
		exitPhaseDone := func() bool {
			if wireguard.IGWRoutingActive() {
				logger.Log(0, "exit re-select short-circuited: exit routing already active")
				return true
			}
			if time.Now().After(exitDeadline) {
				logger.Log(0, "exit re-select deadline reached; continuing restore")
				return true
			}
			return false
		}
		if token != "" && autoExit {
			for attempt := 1; attempt <= exitReselectAttempts; attempt++ {
				if uiapi.ShouldAbortSessionRestore() {
					return nil
				}
				if exitPhaseDone() {
					selErr = nil
					break
				}
				var node *models.DeviceExitNode
				node, selErr = SelectNearestDeviceExitNode(exitNetwork, token)
				if selErr != nil {
					for _, network := range desired {
						if network == exitNetwork {
							continue
						}
						node, selErr = SelectNearestDeviceExitNode(network, token)
						if selErr == nil {
							exitNetwork = network
							break
						}
					}
				}
				if selErr == nil && node != nil {
					egressID = strings.TrimSpace(node.EgressID)
					slog.Info("auto-selected nearest exit node during session restore",
						"network", exitNetwork, "egress_id", egressID, "attempt", attempt)
					_ = config.SetDesiredAutoExitNode(username, tenantID, exitNetwork, egressID)
					break
				}
				slog.Info("auto exit select not ready yet",
					"network", exitNetwork, "attempt", attempt, "error", selErr)
				time.Sleep(exitReselectInterval)
			}
		} else {
			if egressID == "" && token != "" {
				if sel, err := GetDeviceSelectedExitNode(exitNetwork, token); err == nil && sel != nil {
					egressID = strings.TrimSpace(sel.EgressID)
				}
				if egressID == "" {
					for _, network := range desired {
						sel, err := GetDeviceSelectedExitNode(network, token)
						if err != nil || sel == nil || strings.TrimSpace(sel.EgressID) == "" {
							continue
						}
						egressID = strings.TrimSpace(sel.EgressID)
						exitNetwork = network
						break
					}
				}
			}
			if egressID != "" && token != "" {
				for attempt := 1; attempt <= exitReselectAttempts; attempt++ {
					if uiapi.ShouldAbortSessionRestore() {
						return nil
					}
					if exitPhaseDone() {
						selErr = nil
						break
					}
					if _, selErr = SelectDeviceExitNode(exitNetwork, token, egressID); selErr == nil {
						slog.Info("re-selected exit node during session restore",
							"network", exitNetwork, "egress_id", egressID, "attempt", attempt)
						_ = config.SetDesiredExitNode(username, tenantID, exitNetwork, egressID)
						break
					}
					slog.Info("exit re-select not ready yet",
						"network", exitNetwork, "attempt", attempt, "error", selErr)
					time.Sleep(exitReselectInterval)
				}
			}
		}
		if token == "" || (egressID == "" && !autoExit) {
			slog.Warn("cannot re-select exit node during restore; missing egress id or session token",
				"want_igw", wantIGW, "auto_exit", autoExit, "egress_id", egressID,
				"exit_network", exitNetwork, "has_token", token != "")
		} else if selErr != nil {
			slog.Warn("failed to re-select exit node during restore",
				"network", exitNetwork, "auto_exit", autoExit, "egress_id", egressID, "error", selErr)
		} else {
			uiapi.SetRestorePhase(uiapi.RestorePhaseRoutes)
			// Short wait for ChangeDefaultGw; peer updates may finish routes after we return.
			if igwPull, igwErr := waitForReconnectHostPullTimeout(desired, true, restoreIGWTimeout); igwErr != nil {
				slog.Warn("host pull after exit re-select still stale", "error", igwErr)
				if !pull.ChangeDefaultGw {
					pull = igwPull
				}
			} else {
				pull = igwPull
			}
		}
	}

	if uiapi.ShouldAbortSessionRestore() {
		return nil
	}
	uiapi.SetRestorePhase(uiapi.RestorePhaseRoutes)
	// Apply in-process. A SIGHUP restart tears down routes and re-hole-punches
	// before IGW can be reinstalled, which is the login delay users see.
	if err := applyReconnectInProcess(pull, wantIGW); err != nil {
		slog.Warn("in-process reconnect apply failed; falling back to daemon restart", "error", err)
		if uiapi.ShouldAbortSessionRestore() {
			return nil
		}
		if err := daemon.Restart(); err != nil {
			if err := daemon.Start(); err != nil {
				return fmt.Errorf("daemon restart failed %w", err)
			}
		}
	}
	// Ensure system-wide DNS after exit restore even if Start ran earlier in
	// SplitDNS mode (listener already up; Configure must run again with CurrGw).
	scheduleDNSReconfigure()
	return nil
}

func reassertDesiredConnected(networks []string) {
	for _, network := range networks {
		nodes := config.GetNodes()
		node, ok := nodes[network]
		if !ok || node.Connected {
			continue
		}
		if err := connectNetwork(network, false); err != nil {
			slog.Warn("failed to reassert connection after pull", "network", network, "error", err)
		}
	}
}

func filterDesiredNetworks(desired []string, restrictSingle bool) []string {
	nodes := config.GetNodes()
	out := make([]string, 0, len(desired))
	for _, network := range desired {
		if _, ok := nodes[network]; !ok {
			continue
		}
		out = append(out, network)
	}
	if restrictSingle && len(out) > 1 {
		out = out[len(out)-1:]
	}
	return out
}

func forceDisconnectAllNodes() {
	changed := false
	for network, node := range config.GetNodes() {
		if !node.Connected {
			continue
		}
		node.Connected = false
		config.UpdateNodeMap(network, node)
		changed = true
	}
	if changed {
		if err := config.WriteNodeConfig(); err != nil {
			slog.Warn("failed to persist disconnected state after logout", "error", err)
		}
	}
}

func locallyDisconnectedNetworks() map[string]struct{} {
	out := make(map[string]struct{})
	for network, node := range config.GetNodes() {
		if !node.Connected {
			out[network] = struct{}{}
		}
	}
	return out
}

func keepLocallyDisconnected(networks map[string]struct{}) {
	if len(networks) == 0 {
		return
	}
	for network, node := range config.GetNodes() {
		if _, ok := networks[network]; !ok || !node.Connected {
			continue
		}
		node.Connected = false
		config.UpdateNodeMap(network, node)
	}
}

func locallyConnectedNetworks() map[string]struct{} {
	out := make(map[string]struct{})
	for network, node := range config.GetNodes() {
		if node.Connected {
			out[network] = struct{}{}
		}
	}
	return out
}

// keepLocallyConnected restores Connected=true after a server node sync that still
// reports Connected=false (common right after reconnect/login before the server
// processes PublishNodeUpdate). Without this, AnyNodeConnected() is false and
// peer/pull handlers clear egress and internet-exit routes.
//
// With an active desktop session, only networks still in desired state are
// preserved — otherwise an in-flight peer/pull snapshot taken before user
// disconnect can revive Connected=true and reinstall the exit node.
func keepLocallyConnected(networks map[string]struct{}) {
	if len(networks) == 0 {
		return
	}
	// Post-logout there is no session to filter against, and reviving here would
	// undo the disconnect that logout just performed.
	if sessionReleased.Load() {
		return
	}
	if uiapi.IsSessionActive() {
		user, tenant := uiapi.SessionIdentity()
		desired := filterDesiredNetworks(config.GetDesiredNetworks(user, tenant), uiapi.RestrictToSingleNetwork())
		if len(desired) == 0 {
			return
		}
		allowed := make(map[string]struct{}, len(desired))
		for _, network := range desired {
			allowed[network] = struct{}{}
		}
		filtered := make(map[string]struct{}, len(networks))
		for network := range networks {
			if _, ok := allowed[network]; ok {
				filtered[network] = struct{}{}
			}
		}
		networks = filtered
		if len(networks) == 0 {
			return
		}
	}
	changed := false
	for network, node := range config.GetNodes() {
		if _, ok := networks[network]; !ok || node.Connected {
			continue
		}
		node.Connected = true
		config.UpdateNodeMap(network, node)
		changed = true
		slog.Info("preserving local connection after server node sync", "network", network)
	}
	if changed {
		if err := config.WriteNodeConfig(); err != nil {
			slog.Warn("failed to persist preserved connections", "error", err)
		}
	}
}

// reassertDesiredConnectedFlags forces Connected=true for networks in desired
// state. Covers login restore races where a peer update arrives before/without
// a prior local Connected=true snapshot.
func reassertDesiredConnectedFlags() {
	if !uiapi.IsSessionActive() {
		return
	}
	user, tenant := uiapi.SessionIdentity()
	desired := filterDesiredNetworks(config.GetDesiredNetworks(user, tenant), uiapi.RestrictToSingleNetwork())
	if len(desired) == 0 {
		return
	}
	keep := make(map[string]struct{}, len(desired))
	for _, network := range desired {
		keep[network] = struct{}{}
	}
	keepLocallyConnected(keep)
}
