package functions

import (
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
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

// logElapsed returns a function that logs how long the labelled phase took.
// Only used on the interactive connect/disconnect/exit paths, where a slow step
// is something the user waits on.
func logElapsed(label string) func() {
	start := time.Now()
	return func() {
		logger.Log(0, fmt.Sprintf("%s took %s", label, time.Since(start).Round(time.Millisecond)))
	}
}

var (
	dnsApplyMu      sync.Mutex
	dnsApplyPending bool
	dnsApplyRunning bool
)

// scheduleDNSReconfigure applies OS DNS off the caller's goroutine, coalescing
// bursts into a single pass over the latest state.
//
// Installing OS DNS on macOS shells out to networksetup for every network
// service, and we necessarily do it while the network stack is mid-reconfigure —
// right after exit routes move. Measured there a single pass costs 7-15s, against
// 0.12s on an idle system, and connect/disconnect/logout blocked on it for their
// whole duration. Desired state is recomputed inside the apply, so coalescing
// converges on the final state instead of replaying intermediate ones.
//
// Callers that must observe DNS installed before returning should still call
// reconfigureDNSAfterRouting directly.
func scheduleDNSReconfigure() {
	dnsApplyMu.Lock()
	defer dnsApplyMu.Unlock()
	dnsApplyPending = true
	if dnsApplyRunning {
		return
	}
	dnsApplyRunning = true
	go func() {
		for {
			dnsApplyMu.Lock()
			if !dnsApplyPending {
				dnsApplyRunning = false
				dnsApplyMu.Unlock()
				return
			}
			dnsApplyPending = false
			dnsApplyMu.Unlock()
			reconfigureDNSAfterRouting()
		}
	}()
}

// reconfigureDNSAfterRouting re-runs OS DNS setup after exit-node routing changes.
// SplitDNS flips with CurrGwNmIP even when nameserver lists are unchanged.
// Always call this after clearing an exit — even if CurrGwNmIP was already nil —
// so system DNS is not left pointing at the Netmaker listener.
func reconfigureDNSAfterRouting() {
	defer logElapsed("dns reconfigure")()
	// Exit apply often runs before DNS Start during daemon bring-up.
	if dns.GetDNSServerInstance().ListenerAddr() == "" {
		if server := config.GetServer(config.CurrServer); server != nil && server.ManageDNS {
			dns.GetDNSServerInstance().Start()
		}
	}
	if dns.GetDNSServerInstance().ListenerAddr() == "" {
		// Listener still down: strip any leftover full-DNS we installed.
		done := logElapsed("os dns reset")
		err := dns.ResetOSConfig()
		done()
		if err != nil {
			slog.Warn("failed to reset os dns after routing change", "error", err)
		}
		flushDNSCacheTimed()
		return
	}
	// Listener already up: Configure refreshes SplitDNS↔full from CurrGwNmIP
	// (Start is a no-op for bind when AddrStr is set).
	done := logElapsed("os dns configure")
	err := dns.Configure()
	done()
	if err != nil {
		// Do not ResetOSConfig here — a transient Configure failure would wipe
		// working DNS, especially on macOS where only loopback is published.
		slog.Warn("failed to reconfigure dns after routing change", "error", err)
		return
	}
	flushDNSCacheTimed()
}

func flushDNSCacheTimed() {
	defer logElapsed("dns cache flush")()
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
		done := logElapsed("internet gateway teardown")
		if err := wireguard.RestoreInternetGw(); err != nil {
			slog.Warn("failed to restore default gateway", "error", err)
		}
		done()
	}
	scheduleDNSReconfigure()
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
	// Always refresh OS DNS after reconnect apply — exit restore may have just
	// set CurrGw (full DNS) or listeners may have started after an earlier no-op.
	scheduleDNSReconfigure()
	return nil
}

// applyConnectionChangeInProcess rebuilds the live interface, peers, routes and
// DNS for the node set left by a connect or disconnect.
//
// This replaces daemon.Restart() on those paths. The restart was only ever
// rebuilding the interface: MQ subscriptions are set up for every joined node
// regardless of Connected, so flipping that flag changes nothing about them.
// Paying for a full service cycle is especially bad on Windows, where Restart()
// is a WinSW stop/start that costs about a minute before peers can handshake.
func applyConnectionChangeInProcess() error {
	// Connect and disconnect block the UI for the whole apply, so keep the phase
	// costs visible: the expensive parts are network-dependent and only show up
	// on real links.
	defer logElapsed("connection change apply")()

	var pull models.HostPull
	// Only pull when something is still connected. Tearing the last network down
	// has nothing left to converge, and the request would block the UI while
	// routes and DNS are mid-flux — which is most of what made disconnect slow.
	if config.AnyNodeConnected() {
		done := logElapsed("connection change pull")
		p, _, _, err := pullForReconnect(false, true, false)
		done()
		if err != nil {
			// Cached peers are still enough to rebuild; routes for a newly
			// connected network catch up on the next peer update.
			logger.Log(0, "pull after connection change failed; applying from cached config:", err.Error())
		} else {
			pull = p
		}
	}
	wantIGW := false
	if user, tenant, ok := desktopSessionIdentity(); ok {
		wantIGW = config.GetDesiredWantIGW(user, tenant)
	}
	if err := applyReconnectInProcess(pull, wantIGW); err != nil {
		return err
	}
	// After the iface is configured, not before: on Linux and Windows the
	// listener binds overlay node addresses, which do not exist yet at entry.
	dns.SyncForNodeChange()
	// Listener binds just changed, so OS DNS has to follow — but off this
	// goroutine. Disconnecting to zero nodes leaves the entries pointing at
	// listeners that are gone until this runs.
	scheduleDNSReconfigure()
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
	scheduleDNSReconfigure()
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
