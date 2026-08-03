package functions

import (
	"context"
	"fmt"
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
	fmt.Println("[tcp-uplink-debug] initTCPUplinkContext ok")
}

// prepareTCPUplinkWireGuard sets userspace Bind requirement from current node flags.
// Call after SetNodes / before nc.Create. Returns whether a daemon restart is needed
// because TCP uplink was toggled while the process was already running on the wrong WG mode.
func prepareTCPUplinkWireGuard(alreadyRunning bool) (needsRestart bool) {
	need := proxyuplink.NeedsUserspaceWG()
	wireguard.SetNeedTCPUplinkBind(need)
	fmt.Println("[tcp-uplink-debug] prepareTCPUplinkWireGuard need_userspace=", need, "alreadyRunning=", alreadyRunning, "wasOn=", tcpUplinkWasOn)
	for netName, n := range config.GetNodes() {
		fmt.Println("[tcp-uplink-debug]   node", netName,
			"use_tcp_uplink=", n.UseTcpUplink,
			"tcp_proxy_enabled=", n.TcpProxyEnabled,
			"relayedby=", n.RelayedBy,
			"is_gw=", n.IsGw,
			"id=", n.ID.String())
	}
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
	fmt.Println("[tcp-uplink-debug] StopAllTCPUplink")
	stopTCPClientLocked()
	stopTCPServerLocked()
	wireguard.PrepareUserspaceTeardown()
}

// reconcileTCPUplink starts/stops client and gateway TCP uplink from server-published config.
func reconcileTCPUplink(server *config.Server, peerIDs models.PeerMap) {
	fmt.Println("[tcp-uplink-debug] reconcileTCPUplink enter peerIDs_len=", len(peerIDs))
	if peerIDs != nil {
		proxyuplink.UpdatePeerIDs(peerIDs)
		for pub, ida := range peerIDs {
			if ida.TcpProxyEndpoint != "" || ida.ID != "" {
				fmt.Println("[tcp-uplink-debug]   peerID", pub[:min(8, len(pub))], "…",
					"id=", ida.ID, "tcp_proxy_endpoint=", ida.TcpProxyEndpoint)
			}
		}
	}

	tcpUplinkMu.Lock()
	defer tcpUplinkMu.Unlock()

	ctx := tcpUplinkCtx
	if ctx == nil {
		fmt.Println("[tcp-uplink-debug] reconcileTCPUplink ABORT: tcpUplinkCtx is nil")
		return
	}
	if server == nil {
		server = config.GetServer(config.CurrServer)
	}
	if server == nil {
		fmt.Println("[tcp-uplink-debug] reconcileTCPUplink ABORT: server is nil")
		return
	}

	reconcileTCPUplinkClientLocked(ctx, server)
	reconcileTCPUplinkServerLocked(ctx)
}

func reconcileTCPUplinkClientLocked(ctx context.Context, server *config.Server) {
	node, ok := proxyuplink.FindUplinkClient()
	if !ok {
		fmt.Println("[tcp-uplink-debug] client: no local node with use_tcp_uplink+relayedby")
		stopTCPClientLocked()
		return
	}
	fmt.Println("[tcp-uplink-debug] client: found node", node.ID.String(), "relay=", node.RelayedBy, "net=", node.Network)

	addr := proxyuplink.TcpProxyEndpointForRelay(node.RelayedBy)
	if addr == "" {
		fmt.Println("[tcp-uplink-debug] client: MISSING tcp_proxy_endpoint for relay", node.RelayedBy)
		slog.Warn("tcp uplink: use_tcp_uplink set but gateway tcp_proxy_endpoint missing",
			"relay", node.RelayedBy, "network", node.Network)
		stopTCPClientLocked()
		return
	}
	fmt.Println("[tcp-uplink-debug] client: endpoint=", addr)

	if tcpClientMgr != nil && tcpClientMgr.Addr() == addr && tcpClientMgr.RelayPeerID() == node.RelayedBy {
		fmt.Println("[tcp-uplink-debug] client: already running, refresh UDP endpoint only")
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
		fmt.Println("[tcp-uplink-debug] client: NewManager error=", err)
		slog.Error("tcp uplink client", "error", err)
		return
	}
	if ep := proxyuplink.RelayPeerUDPEndpoint(node.RelayedBy); ep != "" {
		fmt.Println("[tcp-uplink-debug] client: WG UDP endpoint=", ep)
		if err := wireguard.SetRelayUDPEndpoint(ep); err != nil {
			fmt.Println("[tcp-uplink-debug] client: SetRelayUDPEndpoint error=", err)
			slog.Warn("tcp uplink: set relay UDP endpoint", "endpoint", ep, "error", err)
		}
	} else {
		fmt.Println("[tcp-uplink-debug] client: WG UDP endpoint not found yet")
		slog.Warn("tcp uplink: gateway WG UDP endpoint not found yet; will retry on peer update")
	}
	wireguard.SetRelayTCPUplink(mgr)
	fmt.Println("[tcp-uplink-debug] client: starting proxy.Client to", addr)
	if err := mgr.Start(ctx, server, config.Netclient(), opts); err != nil {
		wireguard.SetRelayTCPUplink(nil)
		fmt.Println("[tcp-uplink-debug] client: Start FAILED error=", err)
		slog.Error("tcp uplink client start", "error", err)
		return
	}
	tcpClientMgr = mgr
	fmt.Println("[tcp-uplink-debug] client: STARTED ok state=", mgr.State())
	slog.Info("tcp uplink client started", "addr", addr, "relay", node.RelayedBy, "node", node.ID.String())
}

func stopTCPClientLocked() {
	if tcpClientMgr == nil {
		return
	}
	fmt.Println("[tcp-uplink-debug] client: stopping")
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
		fmt.Println("[tcp-uplink-debug] server: no local gateway with tcp_proxy_enabled")
		stopTCPServerLocked()
		return
	}
	fmt.Println("[tcp-uplink-debug] server: found gateway", node.ID.String(), "port=", port)

	if tcpServerMgr != nil && tcpServerMgr.NodeID() == node.ID.String() && tcpServerMgr.ListenPort() == port {
		fmt.Println("[tcp-uplink-debug] server: already running")
		return
	}

	stopTCPServerLocked()

	mgr, err := proxyuplink.NewServerManager(node.ID.String(), port)
	if err != nil {
		fmt.Println("[tcp-uplink-debug] server: NewServerManager error=", err)
		slog.Error("tcp uplink server", "error", err)
		return
	}
	fmt.Println("[tcp-uplink-debug] server: starting listen :", port)
	if err := mgr.Start(ctx); err != nil {
		fmt.Println("[tcp-uplink-debug] server: Start FAILED error=", err)
		slog.Error("tcp uplink server start", "error", err)
		return
	}
	tcpServerMgr = mgr
	fmt.Println("[tcp-uplink-debug] server: STARTED ok")
}

func stopTCPServerLocked() {
	if tcpServerMgr == nil {
		return
	}
	fmt.Println("[tcp-uplink-debug] server: stopping")
	wireguard.SetTCPUplinkServer(nil)
	wireguard.ClearAllTCPPeerRoutes()
	mgr := tcpServerMgr
	tcpServerMgr = nil
	stopCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = mgr.Stop(stopCtx)
	slog.Info("tcp uplink server stopped")
}

// maybeRestartForTCPUplink restarts the daemon when userspace WG mode must change
// (enable or disable TCP uplink). Returns true if a restart was scheduled; callers
// should skip reconcileTCPUplink.
func maybeRestartForTCPUplink() bool {
	if !prepareTCPUplinkWireGuard(true) {
		return false
	}
	// Tear down TCP before SIGHUP so Device.Close cannot race Bind.Send / recv.
	StopAllTCPUplink()

	fmt.Println("[tcp-uplink-debug] WireGuard mode changed; restarting daemon")
	slog.Info("tcp uplink config changed WireGuard mode; restarting daemon")
	_ = daemon.Restart()
	return true
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
