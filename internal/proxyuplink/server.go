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
)

// ServerManager owns an uplink.Server on a TCP-uplink-enabled gateway.
type ServerManager struct {
	mu         sync.Mutex
	server     *uplink.Server
	registry   *uplink.InMemoryRegistry
	cancel     context.CancelFunc
	nodeID     string
	listenPort int
	listenAddr string
	tlsMode    uplink.TLSMode
	certFP     string
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

// ServerManagerOptions configures the gateway uplink listener.
type ServerManagerOptions struct {
	GatewayNodeID string
	ListenPort    int
	ListenAddr    string // optional bind host (e.g. 127.0.0.1); empty = all interfaces
	TLSMode       string // selfsigned|proxy; empty = selfsigned
}

// NewServerManager prepares a gateway uplink listener (Start creates the server).
func NewServerManager(opts ServerManagerOptions) (*ServerManager, error) {
	if opts.GatewayNodeID == "" {
		return nil, errors.New("proxyuplink: gateway node ID required")
	}
	listenPort := opts.ListenPort
	if listenPort <= 0 {
		listenPort = DefaultListenPort
	}
	mode, err := ParseTLSMode(opts.TLSMode)
	if err != nil {
		return nil, err
	}
	return &ServerManager{
		nodeID:     opts.GatewayNodeID,
		listenPort: listenPort,
		listenAddr: opts.ListenAddr,
		tlsMode:    mode,
	}, nil
}

// Start listens for WSS (or WS in proxy mode) uplink clients.
func (m *ServerManager) Start(ctx context.Context) error {
	addr := fmt.Sprintf(":%d", m.listenPort)
	if m.listenAddr != "" {
		addr = fmt.Sprintf("%s:%d", m.listenAddr, m.listenPort)
	}

	srvOpts := uplink.ServerOptions{
		ListenAddr:    addr,
		TLSMode:       m.tlsMode,
		Authenticator: &gatewayAuthenticator{gatewayNodeID: m.nodeID},
		PacketHandler: &gatewayPacketHandler{},
		Logger:        slogAdapter{},
	}

	if m.tlsMode == uplink.TLSModeSelfSigned {
		tlsCfg, fp, err := LoadOrCreateServerTLS()
		if err != nil {
			return fmt.Errorf("proxyuplink server tls: %w", err)
		}
		srvOpts.TLSConfig = tlsCfg
		m.certFP = fp
		// Persist fingerprint onto local host config for control-plane publish.
		if h := config.Netclient(); h != nil && h.TcpProxyCertFingerprint != fp {
			h.TcpProxyCertFingerprint = fp
			h.TcpProxyTLSMode = string(m.tlsMode)
			config.UpdateNetclient(*h)
			_ = config.WriteNetclientConfig()
		}
	}

	reg := uplink.NewInMemoryRegistry()
	srvOpts.SessionRegistry = reg
	srv, err := uplink.NewServer(srvOpts)
	if err != nil {
		return err
	}

	runCtx, cancel := context.WithCancel(ctx)
	m.mu.Lock()
	m.cancel = cancel
	m.server = srv
	m.registry = reg
	m.mu.Unlock()

	if err := srv.Start(runCtx); err != nil {
		cancel()
		m.mu.Lock()
		m.server = nil
		m.cancel = nil
		m.registry = nil
		m.mu.Unlock()
		return err
	}

	serverActiveMu.Lock()
	serverActive = m
	serverActiveMu.Unlock()

	wireguard.SetTCPUplinkServer(m)
	slog.Info("uplink: server started",
		"transport", "wss",
		"listen", addr,
		"gateway_node", m.nodeID,
		"tls_mode", string(m.tlsMode),
		"path", uplink.UplinkWSPath,
	)
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
	m.registry = nil
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

// HasSession reports whether peerID currently has an attached TCP uplink session.
func (m *ServerManager) HasSession(peerID string) bool {
	if peerID == "" {
		return false
	}
	m.mu.Lock()
	reg := m.registry
	m.mu.Unlock()
	if reg == nil {
		return false
	}
	_, ok := reg.Get(peerID)
	return ok
}

// SessionPeerIDs returns peer IDs that currently have a live session.
func (m *ServerManager) SessionPeerIDs() []string {
	m.mu.Lock()
	reg := m.registry
	m.mu.Unlock()
	if reg == nil {
		return nil
	}
	return reg.PeerIDs()
}

// ListenPort returns the configured listen port.
func (m *ServerManager) ListenPort() int { return m.listenPort }

// TLSMode returns the configured TLS mode.
func (m *ServerManager) TLSMode() uplink.TLSMode { return m.tlsMode }

// CertFingerprint returns the self-signed cert fingerprint when applicable.
func (m *ServerManager) CertFingerprint() string { return m.certFP }

// NodeID returns the gateway node ID.
func (m *ServerManager) NodeID() string { return m.nodeID }

type gatewayAuthenticator struct {
	gatewayNodeID string
}

func (a *gatewayAuthenticator) ValidateClientHello(ctx context.Context, hello uplink.ClientHello) (*uplink.AuthResult, error) {
	_ = ctx
	if hello.RelayPeerID != a.gatewayNodeID {
		slog.Warn("uplink: auth relay_peer_id mismatch", "got", hello.RelayPeerID, "want", a.gatewayNodeID)
		return nil, uplink.ErrAuthFailed
	}
	if err := validateWGHelloProof(hello); err != nil {
		slog.Warn("uplink: auth wg proof failed", "node", hello.NodeID, "error", err)
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
	if ep := hostPeerEndpoint(pub); ep != "" {
		return wireguard.SetTCPPeerRoute(peerID, ep)
	}
	placeholder := fmt.Sprintf("127.0.0.1:%d", syntheticPort(peerID))
	return wireguard.SetTCPPeerRoute(peerID, placeholder)
}

// RefreshTCPPeerRoutes re-resolves gateway TCP peer routes from current HostPeers
// for peers that already have a divert mapping plus every peer with a live TCP
// session.
func RefreshTCPPeerRoutes() {
	ids := wireguard.TCPRoutedPeerIDs()
	if srv := ActiveServer(); srv != nil {
		ids = append(ids, srv.SessionPeerIDs()...)
	}
	done := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if id == "" {
			continue
		}
		if _, dup := done[id]; dup {
			continue
		}
		done[id] = struct{}{}
		if err := registerPeerEndpoint(id); err != nil {
			slog.Debug("tcp uplink: refresh peer route", "peer", id, "error", err)
		}
	}
}

func syntheticPort(peerID string) int {
	h := uint32(0)
	for i := 0; i < len(peerID); i++ {
		h = h*31 + uint32(peerID[i])
	}
	return int(40000 + (h % 10000))
}
