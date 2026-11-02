package functions

import (
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/dns"
	"github.com/gravitl/netclient/internal/proxyuplink"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
)

// logElapsed returns a function that logs how long the labelled phase took.
// Only used on the interactive connect/disconnect/exit paths, where a slow step
// is something the user waits on.
func logElapsed(label string) func() {
	start := time.Now()
	return func() {
		logger.Log(0, fmt.Sprintf("%s took %s", label, time.Since(start).Round(time.Millisecond)))
	}
}

// logIGWDecision records the inputs that decide whether exit routing survives an
// update, so a teardown can be traced to a specific branch from the logs.
func logIGWDecision(src string, changeDefaultGw bool) {
	nc := config.Netclient()
	var currGw string
	if nc != nil {
		currGw = fmt.Sprintf("%v/%v", nc.CurrGwNmIP, nc.CurrGwNmIP6)
	}
	// Desired-state getters re-read the JSON store; desktopExitDecision skips
	// them when no desktop session is active.
	desired := callDesktopExitDecision()
	// logger.Log, not slog.Info: slog runs at Warn unless verbosity is raised
	// (cmd/root.go), which silently discarded these when they were needed.
	logger.Log(1, fmt.Sprintf("igw decision: src=%s any_node_connected=%v change_default_gw=%v curr_gw=%s %s",
		src, config.AnyNodeConnected(), changeDefaultGw, currGw, desired))
}

// restoreInternetGwAndDNS restores LAN default routes and always re-applies OS
// DNS so exit-node full DNS cannot stick after clear/disconnect.
//
// CurrGwNmIP is not a reliable signal that the OS routes are gone. A route
// delete can fail after the flag is cleared, and logout then skips teardown
// while 0.0.0.0/1 still blackholes the API for the whole retry budget.
func restoreInternetGwAndDNS() {
	nc := config.Netclient()
	if nc == nil {
		dns.ScheduleReconfigure()
		return
	}
	hadGw := len(nc.CurrGwNmIP) > 0 || len(nc.CurrGwNmIP6) > 0
	if hadGw {
		logger.Log(0, "tearing down internet gateway (restore requested)")
	}
	done := logElapsed("internet gateway teardown")
	if err := wireguard.RestoreInternetGw(); err != nil {
		slog.Warn("failed to restore default gateway", "error", err)
	}
	if hadGw {
		done()
	}
	dns.ScheduleReconfigure()
}

var pullForReconnect = Pull

const (
	reconnectPullTimeout  = 10 * time.Second
	reconnectPullInterval = 250 * time.Millisecond
	// Bounds on reinstalling exit routes after an iface rebuild. The deadline is
	// what actually holds: attempts are cheap only when the server answers fast.
	igwApplyAttempts = 12
	igwApplyInterval = 150 * time.Millisecond
	igwApplyDeadline = 10 * time.Second
)

func hostPullHasConnectedNetworks(pull models.HostPull, networks []string) bool {
	if len(networks) == 0 {
		return false
	}
	byNet := make(map[string]models.Node, len(pull.Nodes))
	for _, node := range pull.Nodes {
		byNet[node.Network] = node
	}
	for _, network := range networks {
		node, ok := byNet[network]
		if !ok || !node.Connected {
			return false
		}
	}
	return true
}

func hostPullReadyForReconnect(pull models.HostPull, networks []string, wantIGW bool) bool {
	if !hostPullHasConnectedNetworks(pull, networks) {
		return false
	}
	if !wantIGW {
		return true
	}
	if !pull.ChangeDefaultGw {
		return false
	}
	gw4, gw6 := wireguard.NormalizeIGWNexthops(pull.DefaultGwIp, pull.DefaultGwIp6)
	if gw4 == nil && gw6 == nil {
		return false
	}
	_, ok := wireguard.FindInternetGwPeer(pull.Peers, gw4, gw6)
	return ok
}

func waitForReconnectHostPull(networks []string, wantIGW bool) (models.HostPull, error) {
	return waitForReconnectHostPullTimeout(networks, wantIGW, reconnectPullTimeout)
}

func waitForReconnectHostPullTimeout(networks []string, wantIGW bool, timeout time.Duration) (models.HostPull, error) {
	var last models.HostPull
	var lastErr error
	if timeout <= 0 {
		timeout = reconnectPullTimeout
	}
	deadline := time.Now().Add(timeout)
	for attempt := 1; ; attempt++ {
		resp, _, _, err := pullForReconnect(false, true, false)
		if err != nil {
			lastErr = err
			slog.Warn("failed to pull after reconnect", "attempt", attempt, "error", err)
		} else {
			last = resp
			lastErr = nil
			if hostPullReadyForReconnect(resp, networks, wantIGW) {
				return resp, nil
			}
			slog.Info("host pull has not reflected reconnect yet",
				"attempt", attempt, "want_igw", wantIGW, "change_default_gw", resp.ChangeDefaultGw)
		}
		if time.Now().Add(reconnectPullInterval).After(deadline) {
			break
		}
		time.Sleep(reconnectPullInterval)
	}
	if lastErr != nil {
		return last, lastErr
	}
	if wantIGW {
		return last, fmt.Errorf("host pull has not reflected exit-node routing after reconnect")
	}
	return last, fmt.Errorf("host pull has not reflected connected networks after reconnect")
}

// applyReconnectInProcess brings the live iface and exit routes up without a
// daemon SIGHUP (hole-punch + iface recreate is what delayed internet after login).
func applyReconnectInProcess(pull models.HostPull, wantIGW bool) error {
	nc := wireguard.NewNCIface(config.Netclient(), config.GetNodes())
	if err := nc.Configure(); err != nil {
		slog.Warn("configure iface after reconnect failed; trying create", "error", err)
		if err := nc.Create(); err != nil {
			return err
		}
		if err := nc.Configure(); err != nil {
			return err
		}
	}
	if len(pull.Peers) > 0 {
		config.UpdateHostPeers(pull.Peers)
	}
	if err := wireguard.SetPeers(true); err != nil {
		return err
	}
	if proxyuplink.ActiveServer() != nil {
		proxyuplink.RefreshTCPPeerRoutes()
	}
	if len(pull.EgressRoutes) > 0 {
		wireguard.SetEgressRoutes(pull.EgressRoutes)
		wireguard.SetEgressRoutesInCache(pull.EgressRoutes)
	} else if len(pull.Nodes) > 0 {
		wireguard.RemoveEgressRoutes()
		wireguard.SetEgressRoutesInCache([]models.EgressNetworkRoutes{})
	}
	if wantIGW || pull.ChangeDefaultGw {
		done := logElapsed("exit route apply")
		applyInternetGwAfterReconnect(pull, nil)
		done()
	}
	// After iface addresses exist: rebind DNS for every connected network.
	// Session restore and reconnect used to skip this (only interactive
	// connect/disconnect synced), so a second network never got a :53 listener
	// without a daemon restart. OS DNS apply must follow the sync, not precede it.
	dns.SyncForNodeChange()
	dns.ScheduleReconfigure()
	return nil
}

// applyConnectionChangeInProcess rebuilds the live interface, peers, routes and
// DNS for the node set left by a connect or disconnect.
//
// This replaces daemon.Restart() on those paths. The restart was only ever
// rebuilding the interface: MQ subscriptions are set up for every joined node
// regardless of Connected, so flipping that flag changes nothing about them.
// Paying for a full daemon soft reset (or WinSW HardRestart) is worse than
// an in-process iface rebuild on every connect/disconnect.
//
// wantIGW must be false on disconnect: an empty pull + desktop want_igw would
// burn igwApplyDeadline (~10s) retrying forceApplyInternetGw. Remaining exit
// routes are reinstalled locally via ReapplyInternetGwAfterIfaceRecreate.
func applyConnectionChangeInProcess(wantIGW bool) error {
	// Connect and disconnect block the UI for the whole apply, so keep the phase
	// costs visible: the expensive parts are network-dependent and only show up
	// on real links.
	defer logElapsed("connection change apply")()

	// No host pull here. PublishNodeUpdate already told the server; the next
	// MQTT peer update carries peers/routes/exit. Pulling blocked the UI for
	// seconds on every connect/disconnect while cached peers were enough to
	// rebuild the iface.
	logger.Log(0, "connection change: skipping host pull (using cached peers; wait for MQTT peer update)")
	hadIGW := wireguard.IGWRoutingActive()
	if err := applyReconnectInProcess(models.HostPull{}, wantIGW); err != nil {
		return err
	}
	// Iface rebuild drops OS default routes while CurrGwNmIP may still be set
	// (disconnect of a non-exit network with exit still desired on another).
	if !wantIGW && hadIGW && wireguard.IGWRoutingActive() {
		wireguard.ReapplyInternetGwAfterIfaceRecreate()
		dns.ScheduleReconfigure()
	}
	return nil
}

func applyInternetGwAfterReconnect(pull models.HostPull, pullErr error) {
	if !config.AnyNodeConnected() {
		logger.Log(0, "exit apply skipped after reconnect: no node connected")
		return
	}
	// Server-advertised exits always install. A desktop session that still wants
	// an exit installs too; otherwise the server is asked again and we return.
	if !shouldApplyExitAfterReconnect(pull, pullErr) {
		return
	}
	var lastErr error
	resp := pull
	deadline := time.Now().Add(igwApplyDeadline)
	for attempt := 1; attempt <= igwApplyAttempts; attempt++ {
		if attempt > 1 {
			// Attempts alone do not bound this loop: every retry re-pulls (which
			// retries internally) and forceApplyInternetGw tears the routes down
			// and reinstalls them, so on a slow link the full attempt budget can
			// hold an interactive connect for a minute.
			if time.Now().After(deadline) {
				logger.Log(0, fmt.Sprintf("exit apply deadline reached after %d attempts", attempt-1))
				break
			}
			time.Sleep(igwApplyInterval)
			if p, _, _, err := pullForReconnect(false, true, false); err == nil {
				resp = p
				config.UpdateHostPeers(p.Peers)
				_ = wireguard.SetPeers(true)
			}
		}
		if err := forceApplyInternetGw(resp); err != nil {
			lastErr = err
			slog.Info("retrying exit-node routes after reconnect",
				"attempt", attempt, "error", err)
			continue
		}
		callRememberDesiredWantIGW()
		kickInternetGwHandshake(resp)
		return
	}
	if lastErr != nil {
		logger.Log(0, "failed to apply exit-node routes after reconnect:", lastErr.Error())
		callReconcileExitIfDesired()
	}
}

func forceApplyInternetGw(pull models.HostPull) error {
	if !pull.ChangeDefaultGw {
		return fmt.Errorf("change_default_gw is false")
	}
	gw4, gw6 := wireguard.NormalizeIGWNexthops(pull.DefaultGwIp, pull.DefaultGwIp6)
	if gw4 == nil && gw6 == nil {
		return fmt.Errorf("missing internet gateway nexthop")
	}
	igw, ok := wireguard.FindInternetGwPeer(pull.Peers, gw4, gw6)
	if !ok {
		igw, ok = wireguard.FindInternetGwPeer(config.Netclient().HostPeers, gw4, gw6)
	}
	if !ok {
		return fmt.Errorf("internet gateway peer not found")
	}
	if len(config.Netclient().CurrGwNmIP) > 0 || len(config.Netclient().CurrGwNmIP6) > 0 {
		_ = wireguard.RestoreInternetGw()
	}
	if err := wireguard.SetInternetGw(igw.PublicKey.String(), gw4, gw6); err != nil {
		return err
	}
	dns.ScheduleReconfigure()
	return nil
}

func kickInternetGwHandshake(pull models.HostPull) {
	gw4, gw6 := wireguard.NormalizeIGWNexthops(pull.DefaultGwIp, pull.DefaultGwIp6)
	ip := gw4
	if len(ip) == 0 {
		ip = gw6
	}
	if len(ip) == 0 {
		return
	}
	go func() {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip.String(), "443"), 2*time.Second)
		if err == nil {
			_ = conn.Close()
		}
	}()
}

// LogElapsed logs how long the labelled phase took. Desktop logout uses it.
func LogElapsed(label string) func() { return logElapsed(label) }

// RestoreInternetGwAndDNS restores LAN default routes and reapplies OS DNS.
func RestoreInternetGwAndDNS() { restoreInternetGwAndDNS() }

// ApplyReconnectInProcess brings the live iface and exit routes up without a daemon restart.
func ApplyReconnectInProcess(pull models.HostPull, wantIGW bool) error {
	return applyReconnectInProcess(pull, wantIGW)
}

// WaitForReconnectHostPull polls until the host pull reflects the reconnect.
func WaitForReconnectHostPull(networks []string, wantIGW bool) (models.HostPull, error) {
	return waitForReconnectHostPull(networks, wantIGW)
}

// WaitForReconnectHostPullTimeout is WaitForReconnectHostPull with an explicit deadline.
func WaitForReconnectHostPullTimeout(networks []string, wantIGW bool, timeout time.Duration) (models.HostPull, error) {
	return waitForReconnectHostPullTimeout(networks, wantIGW, timeout)
}

// HostPullReadyForReconnect reports whether a pull already shows the networks connected.
func HostPullReadyForReconnect(pull models.HostPull, networks []string, wantIGW bool) bool {
	return hostPullReadyForReconnect(pull, networks, wantIGW)
}

// HostPullHasConnectedNetworks reports whether the pull lists those networks as connected.
func HostPullHasConnectedNetworks(pull models.HostPull, networks []string) bool {
	return hostPullHasConnectedNetworks(pull, networks)
}
