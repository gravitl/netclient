package proxyuplink

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/proxy/uplink"
	"golang.org/x/exp/slog"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// ServerManager owns an uplink.Server on a TCP-uplink-enabled gateway.
type ServerManager struct {
	mu         sync.Mutex
	server     *uplink.Server
	cancel     context.CancelFunc
	nodeID     string
	listenPort int
}

var (
	serverActiveMu sync.Mutex
	serverActive   *ServerManager
)

// ActiveServer returns the running gateway TCP uplink server, or nil.
func ActiveServer() *ServerManager {
	serverActiveMu.Lock()
	defer serverActiveMu.Unlock()
	return serverActive
}

// NewServerManager prepares a gateway TCP uplink listener (Start creates the server).
func NewServerManager(gatewayNodeID string, listenPort int) (*ServerManager, error) {
	if gatewayNodeID == "" {
		return nil, errors.New("proxyuplink: gateway node ID required")
	}
	if listenPort <= 0 {
		listenPort = DefaultListenPort
	}
	return &ServerManager{nodeID: gatewayNodeID, listenPort: listenPort}, nil
}

// Start listens for TCP/TLS uplink clients.
func (m *ServerManager) Start(ctx context.Context) error {
	tlsCfg, err := LoadOrCreateServerTLS()
	if err != nil {
		return fmt.Errorf("proxyuplink server tls: %w", err)
	}

	addr := fmt.Sprintf(":%d", m.listenPort)
	srv, err := uplink.NewServer(uplink.ServerOptions{
		ListenAddr:    addr,
		TLSConfig:     tlsCfg,
		Authenticator: &gatewayAuthenticator{gatewayNodeID: m.nodeID},
		PacketHandler: &gatewayPacketHandler{},
		Logger:        slogAdapter{},
	})
	if err != nil {
		return err
	}

	runCtx, cancel := context.WithCancel(ctx)
	m.mu.Lock()
	m.cancel = cancel
	m.server = srv
	m.mu.Unlock()

	if err := srv.Start(runCtx); err != nil {
		cancel()
		m.mu.Lock()
		m.server = nil
		m.cancel = nil
		m.mu.Unlock()
		return err
	}

	serverActiveMu.Lock()
	serverActive = m
	serverActiveMu.Unlock()

	wireguard.SetTCPUplinkServer(m)
	slog.Info("tcp uplink server started", "listen", addr, "gateway_node", m.nodeID)
	return nil
}

// Stop shuts down the listener.
func (m *ServerManager) Stop(ctx context.Context) error {
	wireguard.SetTCPUplinkServer(nil)
	wireguard.ClearAllTCPPeerRoutes()

	m.mu.Lock()
	cancel := m.cancel
	srv := m.server
	m.cancel = nil
	m.server = nil
	m.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	var err error
	if srv != nil {
		err = srv.Stop(ctx)
	}
	serverActiveMu.Lock()
	if serverActive == m {
		serverActive = nil
	}
	serverActiveMu.Unlock()
	return err
}

// SendToPeer forwards WG ciphertext to an attached TCP uplink client.
func (m *ServerManager) SendToPeer(ctx context.Context, peerID string, pkt []byte) error {
	m.mu.Lock()
	srv := m.server
	m.mu.Unlock()
	if srv == nil {
		return uplink.ErrServerClosed
	}
	return srv.SendToPeer(ctx, peerID, pkt)
}

// ListenPort returns the configured listen port.
func (m *ServerManager) ListenPort() int { return m.listenPort }

// NodeID returns the gateway node ID.
func (m *ServerManager) NodeID() string { return m.nodeID }

type gatewayAuthenticator struct {
	gatewayNodeID string
}

func (a *gatewayAuthenticator) ValidateClientHello(ctx context.Context, hello uplink.ClientHello) (*uplink.AuthResult, error) {
	_ = ctx
	if hello.RelayPeerID != a.gatewayNodeID {
		slog.Warn("tcp uplink auth: relay_peer_id mismatch", "got", hello.RelayPeerID, "want", a.gatewayNodeID)
		return nil, uplink.ErrAuthFailed
	}
	if err := validateWGHelloProof(hello); err != nil {
		slog.Warn("tcp uplink auth: wg proof failed", "node", hello.NodeID, "error", err)
		return nil, uplink.ErrAuthFailed
	}
	gatewayFound := false
	for _, gw := range config.GetNodes() {
		if gw.ID.String() != a.gatewayNodeID {
			continue
		}
		gatewayFound = true
		if len(gw.RelayedNodes) == 0 {
			slog.Warn("tcp uplink auth: RelayedNodes empty", "gateway", a.gatewayNodeID)
			return nil, uplink.ErrAuthFailed
		}
		found := false
		for _, id := range gw.RelayedNodes {
			if id == hello.NodeID {
				found = true
				break
			}
		}
		if !found {
			slog.Warn("tcp uplink auth: node not in RelayedNodes", "node", hello.NodeID)
			return nil, uplink.ErrAuthFailed
		}
		break
	}
	if !gatewayFound {
		slog.Warn("tcp uplink auth: gateway node not found", "gateway", a.gatewayNodeID)
		return nil, uplink.ErrAuthFailed
	}
	if err := registerPeerEndpoint(hello.NodeID); err != nil {
		slog.Debug("tcp uplink: peer endpoint register deferred", "peer", hello.NodeID, "error", err)
	}
	return &uplink.AuthResult{
		PeerID:      hello.NodeID,
		RelayPeerID: hello.RelayPeerID,
		NetworkID:   hello.NetworkID,
	}, nil
}

type gatewayPacketHandler struct{}

func (h *gatewayPacketHandler) HandleInboundPacket(ctx context.Context, peerID string, pkt []byte) error {
	_ = ctx
	ep := wireguard.TCPPeerEndpoint(peerID)
	if ep == "" {
		if err := registerPeerEndpoint(peerID); err != nil {
			slog.Warn("tcp uplink: cannot resolve peer endpoint", "peer", peerID, "error", err)
			return err
		}
		ep = wireguard.TCPPeerEndpoint(peerID)
	}
	if ep == "" {
		return fmt.Errorf("tcp uplink: no endpoint for peer %s", peerID)
	}
	wireguard.DeliverTCPInbound(ep, pkt)
	return nil
}

func registerPeerEndpoint(peerID string) error {
	pub := PeerPubKeyForNode(peerID)
	if pub == "" {
		placeholder := fmt.Sprintf("127.0.0.1:%d", syntheticPort(peerID))
		return wireguard.SetTCPPeerRoute(peerID, placeholder)
	}
	pk, err := wgtypes.ParseKey(pub)
	if err != nil {
		return err
	}
	for _, p := range config.Netclient().HostPeers {
		if p.PublicKey != pk {
			continue
		}
		if p.Endpoint == nil {
			placeholder := fmt.Sprintf("127.0.0.1:%d", syntheticPort(peerID))
			return wireguard.SetTCPPeerRoute(peerID, placeholder)
		}
		return wireguard.SetTCPPeerRoute(peerID, p.Endpoint.String())
	}
	placeholder := fmt.Sprintf("127.0.0.1:%d", syntheticPort(peerID))
	return wireguard.SetTCPPeerRoute(peerID, placeholder)
}

func syntheticPort(peerID string) int {
	h := uint32(0)
	for i := 0; i < len(peerID); i++ {
		h = h*31 + uint32(peerID[i])
	}
	return int(40000 + (h % 10000))
}
