package functions

import (
	"context"
	"fmt"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/dns"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	"golang.org/x/exp/slog"
)

func init() {
	// Headless and desktop both reapply OS DNS when the exit health monitor
	// installs or removes routes. The desktop package sets only the unhealthy
	// auto-exit hook.
	wireguard.OnIGWRoutingChanged = dns.ReconfigureAfterRouting
}

// GUI is filled by the desktop package at init when built with -tags desktop.
// A nil field is the default headless path: no session, no uiapi listener, no
// demote for re-login, no desired-state filter, no exit re-select.
var GUI struct {
	PrepareConnect        func(network string) string
	RememberConnection    func(network string)
	ForgetConnection      func(network string)
	FinishConnect         func(network, token string)
	FilterPreserved       func(keep map[string]struct{}) map[string]struct{}
	ReassertDesired       func()
	WantsIGW              func() bool
	WantsUnadvertisedExit func(pull models.HostPull, pullErr error) bool
	// HoldIGWTeardown skips ChangeDefaultGw=false RestoreInternetGw while a
	// desktop exit select or session restore still wants an exit. Nil on headless.
	HoldIGWTeardown func() bool
	RememberWantIGW func()
	ReconcileExit   func()
	ExitDecision    func() string
	ApplyStartup          func()
	RefreshHostPull       func(prev models.HostPull, prevErr error) (models.HostPull, error)
	ForgetNetwork         func(network string)

	// Desktop-only control plane. Nil on headless builds.
	StartUIAPI                 func(ctx context.Context)
	StopUIAPI                  func() error
	RefreshUIAPI               func()
	ForceLogout                func()
	IsSessionActive            func() bool
	EnsureSessionLoaded        func()
	KeepServerDomainForRelogin func() bool
}

func callPrepareDesktopConnect(network string) string {
	if GUI.PrepareConnect == nil {
		return ""
	}
	return GUI.PrepareConnect(network)
}

func callRememberDesiredConnection(network string) {
	if GUI.RememberConnection != nil {
		GUI.RememberConnection(network)
	}
}

func callForgetDesiredConnection(network string) {
	if GUI.ForgetConnection != nil {
		GUI.ForgetConnection(network)
	}
}

func callFinishDesktopConnect(network, token string) {
	if GUI.FinishConnect != nil {
		GUI.FinishConnect(network, token)
	}
}

func callDesktopWantsIGW() bool {
	if GUI.WantsIGW == nil {
		return false
	}
	return GUI.WantsIGW()
}

func callHoldIGWTeardown() bool {
	if GUI.HoldIGWTeardown == nil {
		return false
	}
	return GUI.HoldIGWTeardown()
}

func callRememberDesiredWantIGW() {
	if GUI.RememberWantIGW != nil {
		GUI.RememberWantIGW()
	}
}

func callReconcileExitIfDesired() {
	if GUI.ReconcileExit != nil {
		GUI.ReconcileExit()
	}
}

func callDesktopExitDecision() string {
	if GUI.ExitDecision == nil {
		return "desktop_session=false"
	}
	return GUI.ExitDecision()
}

func callApplyStartupConnections() {
	if GUI.ApplyStartup != nil {
		GUI.ApplyStartup()
	}
}

func callRefreshHostPullAfterReconnect(prev models.HostPull, prevErr error) (models.HostPull, error) {
	if GUI.RefreshHostPull == nil {
		return prev, prevErr
	}
	return GUI.RefreshHostPull(prev, prevErr)
}

func callForgetDesiredNetwork(network string) {
	if GUI.ForgetNetwork != nil {
		GUI.ForgetNetwork(network)
	}
}

// DesktopSessionActive reports whether a Desktop UI session is loaded.
// Headless builds (nil hooks) always return false.
func DesktopSessionActive() bool {
	callEnsureSessionLoaded()
	return callIsSessionActive()
}

// shouldApplyExitAfterReconnect installs a server-advertised exit. Otherwise
// the desktop hook may re-drive selection when desire still wants an exit.
// A nil hook does not install and does not re-select. The hook must not return
// true when ChangeDefaultGw is false: forceApplyInternetGw cannot install then
// and would only burn the apply retry budget.
func shouldApplyExitAfterReconnect(pull models.HostPull, pullErr error) bool {
	if pullErr == nil && pull.ChangeDefaultGw {
		return true
	}
	if GUI.WantsUnadvertisedExit != nil {
		return GUI.WantsUnadvertisedExit(pull, pullErr)
	}
	logger.Log(0, fmt.Sprintf(
		"exit apply skipped after reconnect: change_default_gw=%v pull_err=%v want_igw=%v locally_connected_desired=%v",
		pull.ChangeDefaultGw, pullErr != nil, false, false))
	return false
}

// PreserveConnectionsAfterSync replaces the local node map with the server's
// list, then puts back Connected flags that were already true locally.
//
// That unfiltered restore is the reconnect race: the server often still reports
// Connected=false until it processes PublishNodeUpdate. When the desktop
// package is linked, FilterPreserved applies the logout latch and desired-network
// filter before the restore. Headless leaves the snapshot unchanged.
func PreserveConnectionsAfterSync(nodes []models.Node) {
	keepDisconnected := locallyDisconnectedNetworks()
	keepConnected := locallyConnectedNetworks()
	config.SetNodes(nodes)
	keepLocallyDisconnected(keepDisconnected)
	if GUI.FilterPreserved != nil {
		keepConnected = GUI.FilterPreserved(keepConnected)
	}
	keepLocallyConnected(keepConnected)
	if GUI.ReassertDesired != nil {
		GUI.ReassertDesired()
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
// reports Connected=false. Session filtering happens before this, in the desktop hook.
func keepLocallyConnected(networks map[string]struct{}) {
	if len(networks) == 0 {
		return
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

// KeepLocallyConnected is the desktop package's entry to the unfiltered restore.
func KeepLocallyConnected(networks map[string]struct{}) {
	keepLocallyConnected(networks)
}
