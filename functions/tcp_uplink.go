package functions

import (
	"context"
	"sync"
	"time"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/daemon"
	"github.com/gravitl/netclient/internal/proxyuplink"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/models"
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
		slog.Debug("client: no local node with use_tcp_uplink+relayedby")
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

	if tcpClientMgr != nil && tcpClientMgr.Addr() == addr && tcpClientMgr.RelayPeerID() == node.RelayedBy {
		slog.Debug("client: already running, refresh UDP endpoint only")
		if ep := proxyuplink.RelayPeerUDPEndpoint(node.RelayedBy); ep != "" {
			_ = wireguard.SetRelayUDPEndpoint(ep)
		}
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
	if ep := proxyuplink.RelayPeerUDPEndpoint(node.RelayedBy); ep != "" {
		slog.Debug("client: WG UDP endpoint", "endpoint", ep)
		if err := wireguard.SetRelayUDPEndpoint(ep); err != nil {
			slog.Debug("client: SetRelayUDPEndpoint error", "error", err)
			slog.Warn("tcp uplink: set relay UDP endpoint", "endpoint", ep, "error", err)
		}
	} else {
		slog.Debug("client: WG UDP endpoint not found yet")
		slog.Warn("tcp uplink: gateway WG UDP endpoint not found yet; will retry on peer update")
	}
	wireguard.SetRelayTCPUplink(mgr)
	slog.Debug("client: starting proxy.Client", "addr", addr)
	if err := mgr.Start(ctx, server, config.Netclient(), opts); err != nil {
		wireguard.SetRelayTCPUplink(nil)
		slog.Debug("client: Start FAILED", "error", err)
		slog.Error("tcp uplink client start", "error", err)
		return
	}
	tcpClientMgr = mgr
	slog.Debug("client: STARTED ok", "state", mgr.State())
	slog.Info("tcp uplink client started", "addr", addr, "relay", node.RelayedBy, "node", node.ID.String())
}

func stopTCPClientLocked() {
	if tcpClientMgr == nil {
		return
	}
	slog.Debug("client: stopping")
	// Clear route first so Bind.Send falls back to UDP immediately.
	wireguard.ClearClientRelay()
	wireguard.SetRelayTCPUplink(nil)
	mgr := tcpClientMgr
	tcpClientMgr = nil
	stopCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = mgr.Stop(stopCtx)
	slog.Info("tcp uplink client stopped")
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
		slog.Debug("server: already running")
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
	stopCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = mgr.Stop(stopCtx)
	slog.Info("tcp uplink server stopped")
}

// maybeRestartForTCPUplink restarts the daemon only when userspace WG mode must change
// (enable or disable TCP uplink). TcpProxyListenPort-only changes return false so callers
// reconcile the TCP server in-process without recreating the WireGuard iface.
func maybeRestartForTCPUplink() bool {
	if !prepareTCPUplinkWireGuard(true) {
		return false
	}
	// Tear down TCP before SIGHUP so Device.Close cannot race Bind.Send / recv.
	StopAllTCPUplink()

	fmt.Println("[listen-port-debug] maybeRestartForTCPUplink: scheduling daemon.Restart (userspace mode flip)")
	slog.Debug("WireGuard mode changed; restarting daemon")
	slog.Info("tcp uplink config changed WireGuard mode; restarting daemon")
	_ = daemon.Restart()
	return true
}
