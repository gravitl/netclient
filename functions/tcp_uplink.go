package functions

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/dns"
	"github.com/gravitl/netclient/internal/proxyuplink"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/models"
	"github.com/gravitl/proxy/uplink"
	"golang.org/x/exp/slog"
)

var (
	tcpUplinkMu    sync.Mutex
	tcpUplinkCtx   context.Context
	tcpClientMgr   *proxyuplink.Manager
	tcpServerMgr   *proxyuplink.ServerManager
	tcpUplinkWasOn bool // previous NeedsUserspaceWG for restart detection
)

// initTCPUplinkContext stores the daemon context used to start/stop TCP uplink sessions.
func initTCPUplinkContext(ctx context.Context) {
	tcpUplinkMu.Lock()
	defer tcpUplinkMu.Unlock()
	tcpUplinkCtx = ctx
	slog.Debug("initTCPUplinkContext ok")
}

// prepareTCPUplinkWireGuard sets userspace Bind requirement from current node flags.
// Call after SetNodes / before nc.Create. Returns whether a daemon restart is needed
// because TCP uplink was toggled while the process was already running on the wrong WG mode.
// TcpProxyListenPort-only changes never require a restart (reconcile rebinds the TCP server).
func prepareTCPUplinkWireGuard(alreadyRunning bool) (needsRestart bool) {
	tcpUplinkMu.Lock()
	defer tcpUplinkMu.Unlock()
	need := proxyuplink.NeedsUserspaceWG()
	wireguard.SetNeedTCPUplinkBind(need)
	slog.Debug("prepareTCPUplinkWireGuard",
		"need_userspace", need,
		"alreadyRunning", alreadyRunning,
		"wasOn", tcpUplinkWasOn)
	for netName, n := range config.GetNodes() {
		slog.Debug("tcp uplink node",
			"network", netName,
			"use_tcp_uplink", n.UseTcpUplink,
			"tcp_proxy_enabled", n.TcpProxyEnabled,
			"relayedby", n.RelayedBy,
			"is_gw", n.IsGw,
			"id", n.ID.String())
	}
	if h := config.Netclient(); h != nil {
		slog.Debug("tcp uplink host",
			"tcp_proxy_enabled", h.TcpProxyEnabled,
			"tcp_proxy_listen_port", h.TcpProxyListenPort)
	}
	// Only flip of userspace-vs-kernel mode needs a daemon restart. Listen port
	// changes are handled by reconcileTCPUplinkServerLocked (stop+start proxy).
	if alreadyRunning && need != tcpUplinkWasOn {
		needsRestart = true
	}
	tcpUplinkWasOn = need
	return needsRestart
}

// StopAllTCPUplink tears down client/server sessions and drains async Bind sends.
// Must run before userspace Device.Close / iface recreate (disable, SIGHUP, shutdown).
func StopAllTCPUplink() {
	tcpUplinkMu.Lock()
	defer tcpUplinkMu.Unlock()
	slog.Debug("StopAllTCPUplink")
	stopTCPClientLocked()
	stopTCPServerLocked()
	wireguard.PrepareUserspaceTeardown()
}

// reconcileTCPUplink starts/stops client and gateway TCP uplink from server-published config.
func reconcileTCPUplink(server *config.Server, peerIDs models.PeerMap) {
	slog.Debug("reconcileTCPUplink enter", "peerIDs_len", len(peerIDs))
	if peerIDs != nil {
		proxyuplink.UpdatePeerIDs(peerIDs)
		for pub, ida := range peerIDs {
			if ida.TcpProxyEndpoint != "" || ida.ID != "" {
				slog.Debug("tcp uplink peerID",
					"pubkey_prefix", pub[:min(8, len(pub))],
					"id", ida.ID,
					"tcp_proxy_endpoint", ida.TcpProxyEndpoint)
			}
		}
	}

	tcpUplinkMu.Lock()
	defer tcpUplinkMu.Unlock()

	ctx := tcpUplinkCtx
	if ctx == nil {
		slog.Debug("reconcileTCPUplink ABORT: tcpUplinkCtx is nil")
		return
	}
	if server == nil {
		server = config.GetServer(config.CurrServer)
	}
	if server == nil {
		slog.Debug("reconcileTCPUplink ABORT: server is nil")
		return
	}

	reconcileTCPUplinkClientLocked(ctx, server)
	reconcileTCPUplinkServerLocked(ctx)
}

func reconcileTCPUplinkClientLocked(ctx context.Context, server *config.Server) {
	node, ok := proxyuplink.FindUplinkClient()
	if !ok {
		slog.Debug("client: no connected local node with use_tcp_uplink+relayedby")
		stopTCPClientLocked()
		return
	}
	slog.Debug("client: found node",
		"node", node.ID.String(),
		"relay", node.RelayedBy,
		"net", node.Network)

	addr := proxyuplink.TcpProxyEndpointForRelay(node.RelayedBy)
	if addr == "" {
		slog.Debug("client: MISSING tcp_proxy_endpoint for relay", "relay", node.RelayedBy)
		slog.Warn("tcp uplink: use_tcp_uplink set but gateway tcp_proxy_endpoint missing",
			"relay", node.RelayedBy, "network", node.Network)
		stopTCPClientLocked()
		return
	}
	slog.Debug("client: endpoint", "addr", addr)
	wireguard.SetTCPUplinkHostRouteIPs(tcpUplinkHostIPsFromAddr(addr))
	// Exit may already be up (IsCurrentIGW skips SetInternetGw); pin TCP proxy now.
	wireguard.RefreshInternetGwHostPins()

	if tcpClientMgr != nil && tcpClientMgr.Addr() == addr && tcpClientMgr.RelayPeerID() == node.RelayedBy {
		slog.Debug("client: already running, refresh UDP endpoint only")
		ensureClientRelayUDPEndpoint(node.RelayedBy)
		wireguard.SetRelayTCPUplink(tcpClientMgr)
		return
	}

	stopTCPClientLocked()

	opts := proxyuplink.Options{
		Addr:          addr,
		TLSServerName: proxyuplink.TLSServerNameFromAddr(addr),
		NodeID:        node.ID.String(),
		RelayPeerID:   node.RelayedBy,
		NetworkID:     node.Network,
		InboundToWG:   wireguard.DeliverRelayTCPInbound,
	}
	mgr, err := proxyuplink.NewManager(opts)
	if err != nil {
		slog.Debug("client: NewManager error", "error", err)
		slog.Error("tcp uplink client", "error", err)
		return
	}
	ensureClientRelayUDPEndpoint(node.RelayedBy)
	wireguard.SetRelayTCPUplink(mgr)
	slog.Debug("client: starting proxy.Client", "addr", addr)
	if err := mgr.Start(ctx, server, config.Netclient(), opts); err != nil {
		wireguard.SetRelayTCPUplink(nil)
		slog.Debug("client: Start FAILED", "error", err)
		slog.Error("tcp uplink client start", "error", err)
		return
	}
	tcpClientMgr = mgr
	// Peers may have been applied just before reconcile; retry endpoint once more.
	ensureClientRelayUDPEndpoint(node.RelayedBy)
	go watchTCPClientHealth(ctx, mgr, node.RelayedBy)
	slog.Debug("client: STARTED ok", "state", mgr.State())
	slog.Info("tcp uplink client started", "addr", addr, "relay", node.RelayedBy, "node", node.ID.String())
}

// watchTCPClientHealth recovers after gateway restart/pull without requiring a client pull:
//   - when TCP becomes Active again, restore HostPeers-based divert + uplink hook
//   - if down too long, recreate the proxy client (resets reconnect/auth state)
//
// Divert stays keyed to the server-published HostPeers endpoint so a working LAN
// address from endpoint detection (different UDP dest) naturally uses UDP instead of TCP.
func watchTCPClientHealth(ctx context.Context, mgr *proxyuplink.Manager, relayPeerID string) {
	wasActive := mgr.State() == uplink.StateActive
	var downSince time.Time
	if !wasActive {
		downSince = time.Now()
	}
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			tcpUplinkMu.Lock()
			if tcpClientMgr != mgr {
				tcpUplinkMu.Unlock()
				return
			}
			active := mgr.State() == uplink.StateActive
			switch {
			case active && !wasActive:
				slog.Info("tcp uplink client reconnected; restoring relay divert", "relay", relayPeerID)
				ensureClientRelayUDPEndpoint(relayPeerID)
				wireguard.SetRelayTCPUplink(mgr)
				downSince = time.Time{}
				wasActive = true
				tcpUplinkMu.Unlock()
			case !active && wasActive:
				slog.Info("tcp uplink client disconnected; waiting for reconnect", "relay", relayPeerID)
				downSince = time.Now()
				wasActive = false
				tcpUplinkMu.Unlock()
			case !active && !downSince.IsZero() && time.Since(downSince) > 30*time.Second:
				slog.Warn("tcp uplink client down too long; recreating client",
					"relay", relayPeerID, "state", mgr.State())
				tcpUplinkMu.Unlock()
				restartTCPUplinkClient()
				return
			default:
				tcpUplinkMu.Unlock()
			}
		}
	}
}

// restartTCPUplinkClient stops and re-reconciles the TCP uplink client.
func restartTCPUplinkClient() {
	tcpUplinkMu.Lock()
	defer tcpUplinkMu.Unlock()
	ctx := tcpUplinkCtx
	server := config.GetServer(config.CurrServer)
	stopTCPClientLocked()
	if ctx == nil || server == nil {
		return
	}
	reconcileTCPUplinkClientLocked(ctx, server)
}

func ensureClientRelayUDPEndpoint(relayPeerID string) {
	ep := proxyuplink.RelayPeerUDPEndpoint(relayPeerID)
	if ep == "" {
		slog.Debug("client: WG UDP endpoint not found yet")
		slog.Warn("tcp uplink: gateway WG UDP endpoint not found yet; will retry on peer update")
		return
	}
	slog.Debug("client: WG UDP endpoint", "endpoint", ep)
	if err := wireguard.SetRelayUDPEndpoint(ep); err != nil {
		slog.Debug("client: SetRelayUDPEndpoint error", "error", err)
		slog.Warn("tcp uplink: set relay UDP endpoint", "endpoint", ep, "error", err)
	}
	// Keep the live WG peer on the HostPeers underlay endpoint so Bind.Send
	// matches the TCP divert key (endpoint detection must not leave a 10.x dest).
	wireguard.RestoreHostPeerEndpoint(ep)
}

func stopTCPClientLocked() {
	if tcpClientMgr == nil {
		wireguard.SetTCPUplinkHostRouteIPs(nil)
		return
	}
	slog.Debug("client: stopping")
	// Clear route first so Bind.Send falls back to UDP immediately.
	wireguard.ClearClientRelay()
	wireguard.SetRelayTCPUplink(nil)
	wireguard.SetTCPUplinkHostRouteIPs(nil)
	mgr := tcpClientMgr
	tcpClientMgr = nil
	stopCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = mgr.Stop(stopCtx)
	slog.Info("tcp uplink client stopped")
}

func tcpUplinkHostIPsFromAddr(addr string) []net.IP {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if host == "" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		slog.Debug("tcp uplink: resolve proxy host for IGW pin", "host", host, "error", err)
		return nil
	}
	return ips
}

// registerTCPUplinkHostIPsFromConfig sets underlay pin candidates from the
// server-published TCP proxy endpoint without starting the client. Used before
// reinstalling 0.0.0.0/0 after a userspace mode flip so TLS is not blackholed.
func registerTCPUplinkHostIPsFromConfig() {
	node, ok := proxyuplink.FindUplinkClient()
	if !ok {
		wireguard.SetTCPUplinkHostRouteIPs(nil)
		return
	}
	addr := proxyuplink.TcpProxyEndpointForRelay(node.RelayedBy)
	if addr == "" {
		wireguard.SetTCPUplinkHostRouteIPs(nil)
		return
	}
	wireguard.SetTCPUplinkHostRouteIPs(tcpUplinkHostIPsFromAddr(addr))
}

func reconcileTCPUplinkServerLocked(ctx context.Context) {
	node, port, ok := proxyuplink.FindTCPGateway()
	if !ok {
		slog.Debug("server: no local gateway with tcp_proxy_enabled")
		stopTCPServerLocked()
		return
	}
	slog.Debug("server: found gateway", "node", node.ID.String(), "port", port)

	if tcpServerMgr != nil && tcpServerMgr.NodeID() == node.ID.String() && tcpServerMgr.ListenPort() == port {
		// Listener may still be up after PrepareUserspaceTeardown cleared the bind hook
		// and peer routes (e.g. resetInterfaceFunc). Re-hook and refresh routes.
		slog.Debug("server: already running; re-hook and refresh peer routes")
		wireguard.SetTCPUplinkServer(tcpServerMgr)
		proxyuplink.RefreshTCPPeerRoutes()
		return
	}

	// Listen-port (or node) change: stop+start TCP proxy only — do not restart WG/daemon.
	if tcpServerMgr != nil {
		slog.Info("tcp uplink: rebinding listen",
			"old_port", tcpServerMgr.ListenPort(),
			"new_port", port,
			"node", node.ID.String())
	}

	stopTCPServerLocked()

	mgr, err := proxyuplink.NewServerManager(node.ID.String(), port)
	if err != nil {
		slog.Debug("server: NewServerManager error", "error", err)
		slog.Error("tcp uplink server", "error", err)
		return
	}
	slog.Debug("server: starting listen", "port", port)
	if err := mgr.Start(ctx); err != nil {
		slog.Debug("server: Start FAILED", "error", err)
		slog.Error("tcp uplink server start", "error", err)
		return
	}
	tcpServerMgr = mgr
	slog.Debug("server: STARTED ok")
	proxyuplink.RefreshTCPPeerRoutes()
}

func stopTCPServerLocked() {
	if tcpServerMgr == nil {
		return
	}
	slog.Debug("server: stopping")
	wireguard.SetTCPUplinkServer(nil)
	wireguard.ClearAllTCPPeerRoutes()
	mgr := tcpServerMgr
	tcpServerMgr = nil
	// Allow session CloseAll + connWG drain (zombies used to block forever).
	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = mgr.Stop(stopCtx)
	slog.Info("tcp uplink server stopped")
}

// maybeRestartForTCPUplink flips userspace↔kernel/NT WireGuard when TCP uplink
// enablement changes. Does an in-process iface recreate (not daemon.Restart):
// on Windows, Restart() is a full WinSW service stop/start and commonly costs
// ~1 minute before peers can handshake again.
// TcpProxyListenPort-only changes return false so callers reconcile the TCP
// server without recreating the WireGuard iface.
func maybeRestartForTCPUplink() bool {
	if !prepareTCPUplinkWireGuard(true) {
		return false
	}
	slog.Info("tcp uplink config changed WireGuard mode; flipping iface in-process")
	flipTCPUplinkWireGuardMode()
	return true
}

// flipTCPUplinkWireGuardMode tears down the current netmaker iface and recreates
// it in the mode required by needTCPUplinkBind (userspace vs kernel/WireGuardNT).
// MQTT and other daemon goroutines keep running.
func flipTCPUplinkWireGuardMode() {
	mNMutex.Lock()
	defer mNMutex.Unlock()

	// Hold off IGW health checks until the new iface is configured; a half-built
	// device has no peers and would read as the exit peer going away.
	defer wireguard.BeginIfaceRebuild()()

	StopAllTCPUplink()

	listenPort := 0
	if cfg := config.Netclient(); cfg != nil {
		listenPort = cfg.ListenPort
	}
	nc := wireguard.GetInterface()
	nc.Close()
	// Short wait — full 5s was leftover from listen-port bump debugging.
	if listenPort > 0 && !ncutils.WaitForUDPPortFree(listenPort, 2*time.Second) {
		slog.Warn("WireGuard UDP listen port still busy after mode-flip Close", "port", listenPort)
	}

	nc = wireguard.NewNCIface(config.Netclient(), config.GetNodes())
	if err := nc.Create(); err != nil {
		slog.Error("tcp uplink mode flip: create iface", "error", err)
		return
	}
	if err := nc.Configure(); err != nil {
		slog.Error("tcp uplink mode flip: configure iface", "error", err)
		return
	}
	if err := wireguard.SetPeers(true); err != nil {
		slog.Error("tcp uplink mode flip: set peers", "error", err)
	}
	wireguard.SetRoutesFromCache()
	// StopAllTCPUplink cleared TCP host pins; register them again BEFORE
	// reinstalling 0.0.0.0/0 so the subsequent TLS dial is not blackholed.
	registerTCPUplinkHostIPsFromConfig()
	// Closing the iface drops OS default routes used for exit-node traffic, but
	// IGWMonitor still reports the old nexthop as current — force reinstall.
	wireguard.ReapplyInternetGwAfterIfaceRecreate()

	server := config.GetServer(config.CurrServer)
	if server == nil {
		return
	}
	reconcileTCPUplink(server, nil)
	if server.ManageDNS {
		dns.GetDNSServerInstance().Stop()
		dns.GetDNSServerInstance().Start()
	}
	select {
	case wireguard.EgressResetCh <- struct{}{}:
	default:
	}
}
