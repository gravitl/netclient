package functions

import (
	"context"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/internal/proxyuplink"
	"github.com/gravitl/netclient/wireguard"
	"golang.org/x/exp/slog"
)

// startRelayTCPUplink starts a TCP/TLS framed uplink to the relay when NC_RELAY_TCP_UPLINK_ADDR is set.
// It registers relay UDP endpoint routing and wires DeliverRelayTCPInbound / SetRelayTCPUplink for userspace conn.Bind.
func startRelayTCPUplink(ctx context.Context, server *config.Server) {
	addr := proxyuplink.AddrFromEnv()
	if addr == "" {
		return
	}
	if server == nil || server.API == "" {
		slog.Warn("relay tcp uplink: no server API; skipping")
		return
	}

	var relayID, network string
	for _, n := range config.GetNodes() {
		if n.RelayedBy != "" {
			relayID = n.RelayedBy
			network = n.Network
			break
		}
	}
	if relayID == "" {
		slog.Warn("NC_RELAY_TCP_UPLINK_ADDR is set but no relayed node (RelayedBy) found; skipping relay TCP uplink")
		return
	}

	opts := proxyuplink.Options{
		Addr:          addr,
		TLSServerName: proxyuplink.TLSServerNameFromEnv(addr),
		RelayPeerID:   relayID,
		NetworkID:     network,
		InboundToWG:   wireguard.DeliverRelayTCPInbound,
	}

	mgr, err := proxyuplink.NewManager(opts)
	if err != nil {
		slog.Error("relay tcp uplink", "error", err)
		return
	}
	if ep := proxyuplink.RelayPeerUDPEndpoint(relayID); ep != "" {
		if err := wireguard.SetRelayUDPEndpoint(ep); err != nil {
			slog.Warn("relay tcp uplink: set relay UDP endpoint", "endpoint", ep, "error", err)
		}
	} else {
		slog.Warn("relay tcp uplink: relay peer UDP endpoint not found yet; set after peers sync if handshake fails")
	}
	wireguard.SetRelayTCPUplink(mgr)
	if err := mgr.Start(ctx, server, config.Netclient(), opts); err != nil {
		wireguard.SetRelayTCPUplink(nil)
		slog.Error("relay tcp uplink start", "error", err)
		return
	}

	slog.Info("relay tcp uplink started", "addr", addr, "relay_peer_id", relayID, "state", mgr.State())

	go func(m *proxyuplink.Manager) {
		<-ctx.Done()
		wireguard.SetRelayTCPUplink(nil)
		if err := m.Stop(context.Background()); err != nil {
			slog.Debug("relay tcp uplink stop", "error", err)
		}
	}(mgr)
}
