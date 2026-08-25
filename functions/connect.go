package functions

import (
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/daemon"
	"github.com/gravitl/netclient/uiapi"
	"github.com/gravitl/netclient/wireguard"
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
	user, tenant := uiapi.SessionIdentity()
	if err := config.RememberDesiredNetwork(user, tenant, network); err != nil {
		slog.Warn("failed to persist desired connection", "network", network, "error", err)
	}
	if err := PublishNodeUpdate(&node); err != nil {
		return err
	}
	if !restart {
		return nil
	}
	if err := daemon.Restart(); err != nil {
		if err := daemon.Start(); err != nil {
			return fmt.Errorf("daemon restart failed %w", err)
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
		user, tenant := uiapi.SessionIdentity()
		if err := config.ForgetDesiredNetwork(user, tenant, network); err != nil {
			slog.Warn("failed to clear desired connection", "network", network, "error", err)
		}
	}
	if err := PublishNodeUpdate(&node); err != nil {
		return err
	}
	if !config.AnyNodeConnected() {
		_ = wireguard.SetPeers(true)
		if nc := config.Netclient(); nc != nil && (len(nc.CurrGwNmIP) > 0 || len(nc.CurrGwNmIP6) > 0) {
			if err := wireguard.RestoreInternetGw(); err != nil {
				slog.Warn("failed to restore default gateway after disconnect", "error", err)
			}
		}
	}
	if !restart {
		return nil
	}
	if err := daemon.Restart(); err != nil {
		fmt.Println("daemon restart failed", err)
		if err := daemon.Start(); err != nil {
			fmt.Println("daemon failed to start", err)
		}
	}
	return nil
}

// skipDesiredRestoreOnce is set before logout/handoff disconnect restarts the
// daemon. ApplyDesiredConnectedFlags must not undo that disconnect: the UI
// session is still active until the HTTP handler clears it.
var skipDesiredRestoreOnce atomic.Bool

func skipNextDesiredRestore() {
	skipDesiredRestoreOnce.Store(true)
}

// RestoreDesiredConnections reconnects networks this user last had connected.
// Used after desktop login. Restarts the daemon once if anything changes.
func RestoreDesiredConnections(username, tenantID string) error {
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
	changed := false
	for _, network := range desired {
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
	wantIGW := config.GetDesiredWantIGW(username, tenantID)
	if !changed && !wantIGW {
		return nil
	}
	// Apply in-process. A SIGHUP restart tears down routes and re-hole-punches
	// before IGW can be reinstalled, which is the login delay users see.
	pull, err := waitForReconnectHostPull(desired, wantIGW)
	if err != nil {
		slog.Warn("host pull after reconnect still stale; applying with last pull", "error", err)
	}
	reassertDesiredConnected(desired)
	if err := applyReconnectInProcess(pull, wantIGW); err != nil {
		slog.Warn("in-process reconnect apply failed; falling back to daemon restart", "error", err)
		if err := daemon.Restart(); err != nil {
			if err := daemon.Start(); err != nil {
				return fmt.Errorf("daemon restart failed %w", err)
			}
		}
	}
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
