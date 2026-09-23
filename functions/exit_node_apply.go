package functions

import (
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/dns"
	"github.com/gravitl/netclient/internal/proxyuplink"
	"github.com/gravitl/netclient/uiapi"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
)

// reconfigureDNSAfterRouting re-runs OS DNS setup after exit-node routing changes.
// SplitDNS flips with CurrGwNmIP even when nameserver lists are unchanged.
// Always call this after clearing an exit — even if CurrGwNmIP was already nil —
// so system DNS is not left pointing at the Netmaker listener.
func reconfigureDNSAfterRouting() {
	// Exit apply often runs before DNS Start during daemon bring-up.
	if dns.GetDNSServerInstance().AddrStr == "" {
		if server := config.GetServer(config.CurrServer); server != nil && server.ManageDNS {
			dns.GetDNSServerInstance().Start()
		}
	}
	if dns.GetDNSServerInstance().AddrStr == "" {
		// Listener still down: strip any leftover full-DNS we installed.
		if err := dns.ResetOSConfig(); err != nil {
			slog.Warn("failed to reset os dns after routing change", "error", err)
		}
		dns.FlushCache()
		return
	}
	// Listener already up: Configure refreshes SplitDNS↔full from CurrGwNmIP
	// (Start is a no-op for bind when AddrStr is set).
	if err := dns.Configure(); err != nil {
		// Do not ResetOSConfig here — a transient Configure failure would wipe
		// working DNS, especially on macOS where only loopback is published.
		slog.Warn("failed to reconfigure dns after routing change", "error", err)
		return
	}
	dns.FlushCache()
}

// logIGWDecision records the inputs that decide whether exit routing survives an
// update, so a teardown can be traced to a specific branch from the logs.
func logIGWDecision(src string, changeDefaultGw bool) {
	nc := config.Netclient()
	var currGw string
	if nc != nil {
		currGw = fmt.Sprintf("%v/%v", nc.CurrGwNmIP, nc.CurrGwNmIP6)
	}
	desired := "desktop_session=false"
	// Each desired-state getter re-reads the JSON store, so skip them headless
	// where they can only ever report the zero value.
	if user, tenant, ok := desktopSessionIdentity(); ok {
		desired = fmt.Sprintf("want_igw=%v auto_exit=%v desired_egress=%s",
			config.GetDesiredWantIGW(user, tenant),
			config.GetDesiredAutoExit(user, tenant),
			config.GetDesiredEgressID(user, tenant))
	}
	// logger.Log, not slog.Info: slog runs at Warn unless verbosity is raised
	// (cmd/root.go), which silently discarded these when they were needed.
	logger.Log(0, fmt.Sprintf("igw decision: src=%s any_node_connected=%v change_default_gw=%v curr_gw=%s %s",
		src, config.AnyNodeConnected(), changeDefaultGw, currGw, desired))
}

// restoreInternetGwAndDNS restores LAN default routes (if still installed) and
// always re-applies OS DNS so exit-node full DNS cannot stick after clear/disconnect.
func restoreInternetGwAndDNS() {
	if nc := config.Netclient(); nc != nil && (len(nc.CurrGwNmIP) > 0 || len(nc.CurrGwNmIP6) > 0) {
		logger.Log(0, "tearing down internet gateway (restore requested)")
		if err := wireguard.RestoreInternetGw(); err != nil {
			slog.Warn("failed to restore default gateway", "error", err)
		}
	}
	reconfigureDNSAfterRouting()
}

var pullForReconnect = Pull

const (
	reconnectPullTimeout  = 10 * time.Second
	reconnectPullInterval = 250 * time.Millisecond
	// Shorter waits during session restore so login isn't blocked on slow server convergence.
	restoreConnectedTimeout = 4 * time.Second
	restoreIGWTimeout       = 4 * time.Second
	exitReselectAttempts    = 8
	exitReselectInterval    = 300 * time.Millisecond
	// exitPhaseDeadline bounds the whole exit re-select phase in wall-clock time.
	// The attempt counter alone does not: each device API call retries internally,
	// so on a degraded link (which is normal mid-exit-switchover) eight attempts
	// can run for minutes while the GUI sits on "Reconnecting exit node".
	exitPhaseDeadline = 20 * time.Second
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
		applyInternetGwAfterReconnect(pull, nil)
	}
	// Always refresh OS DNS after reconnect apply — exit restore may have just
	// set CurrGw (full DNS) or listeners may have started after an earlier no-op.
	reconfigureDNSAfterRouting()
	return nil
}

func applyInternetGwAfterReconnect(pull models.HostPull, pullErr error) {
	if !config.AnyNodeConnected() {
		logger.Log(0, "exit apply skipped after reconnect: no node connected")
		return
	}
	// Headless has no desired state: only a server-advertised exit applies below.
	user, tenant, hasSession := desktopSessionIdentity()
	wantIGW := hasSession && config.GetDesiredWantIGW(user, tenant)
	if pullErr == nil && pull.ChangeDefaultGw {
		// Server already advertised an exit; reinstall OS routes after iface recreate.
	} else if !(wantIGW && locallyConnectedDesired()) {
		// Silent here once cost a full session of "connected but no exit": the
		// restore finished clean while the server still advertised no gateway.
		logger.Log(0, fmt.Sprintf(
			"exit apply skipped after reconnect: change_default_gw=%v pull_err=%v want_igw=%v locally_connected_desired=%v",
			pull.ChangeDefaultGw, pullErr != nil, wantIGW, locallyConnectedDesired()))
		reconcileDesiredExit()
		return
	}
	var lastErr error
	resp := pull
	for attempt := 1; attempt <= 12; attempt++ {
		if attempt > 1 {
			time.Sleep(150 * time.Millisecond)
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
		if hasSession {
			_ = config.SetDesiredWantIGW(user, tenant, true)
		}
		kickInternetGwHandshake(resp)
		return
	}
	if lastErr != nil {
		logger.Log(0, "failed to apply exit-node routes after reconnect:", lastErr.Error())
		reconcileDesiredExit()
	}
}

// exitReconcileInterval bounds how often the client may re-drive the server exit
// selection, so a server that simply has no exit available is not hammered.
const exitReconcileInterval = 30 * time.Second

var lastExitReconcile atomic.Int64

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
	user, tenant, ok := desktopSessionIdentity()
	if !ok {
		return
	}
	if wireguard.IGWRoutingActive() {
		return
	}
	if !config.GetDesiredWantIGW(user, tenant) {
		return
	}
	autoExit := config.GetDesiredAutoExit(user, tenant)
	egressID := strings.TrimSpace(config.GetDesiredEgressID(user, tenant))
	network := strings.TrimSpace(config.GetDesiredExitNetwork(user, tenant))
	token := uiapi.SessionAuthToken()
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
		if autoExit && egressID == "" {
			logger.Log(0, "exit reconcile: re-selecting nearest exit on "+network)
			if _, err := SelectNearestDeviceExitNode(network, token); err != nil {
				logger.Log(0, "exit reconcile: nearest re-select failed:", err.Error())
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
	reconfigureDNSAfterRouting()
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

func refreshHostPullAfterReconnect(prev models.HostPull, prevErr error) (models.HostPull, error) {
	if !uiapi.IsSessionActive() {
		return prev, prevErr
	}
	user, tenant := uiapi.SessionIdentity()
	desired := filterDesiredNetworks(config.GetDesiredNetworks(user, tenant), uiapi.RestrictToSingleNetwork())
	if len(desired) == 0 {
		return prev, prevErr
	}
	nodes := config.GetNodes()
	anyConnected := false
	for _, network := range desired {
		if node, ok := nodes[network]; ok && node.Connected {
			anyConnected = true
			break
		}
	}
	if !anyConnected {
		return prev, prevErr
	}
	wantIGW := config.GetDesiredWantIGW(user, tenant)
	if prevErr == nil && hostPullReadyForReconnect(prev, desired, wantIGW) {
		return prev, nil
	}
	resp, err := waitForReconnectHostPull(desired, wantIGW)
	if err != nil {
		if prevErr == nil && (resp.ChangeDefaultGw || hostPullHasConnectedNetworks(resp, desired)) {
			return resp, nil
		}
		if prevErr == nil {
			return prev, prevErr
		}
		return resp, err
	}
	return resp, nil
}
