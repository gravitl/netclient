package proxyuplink

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strings"
	"sync"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/proxy/uplink"
	"golang.org/x/exp/slog"
)

// Manager owns a WSS uplink.Client to the gateway.
type Manager struct {
	mu     sync.RWMutex
	client *uplink.Client
	cancel context.CancelFunc
	addr   string
	relay  string
}

var (
	activeMu sync.Mutex
	active   *Manager
)

// Active returns the last successfully started Manager, or nil.
func Active() *Manager {
	activeMu.Lock()
	defer activeMu.Unlock()
	return active
}

// Options configures the uplink from server-published settings.
type Options struct {
	// Addr is the WSS endpoint URL (wss://host:port/uplink/v1) or legacy host:port.
	Addr string
	// TLSServerName is TLS SNI (optional; derived from URL when empty).
	TLSServerName string
	// CertFingerprint is the expected SHA-256 hex of the gateway leaf cert (selfsigned).
	CertFingerprint string
	// NodeID is this client's network node ID (ClientHello.node_id).
	NodeID string
	// RelayPeerID is the gateway/relay node ID (required).
	RelayPeerID string
	// NetworkID is the logical network name.
	NetworkID string
	// InboundToWG delivers gateway→client DATA frames into userspace WireGuard.
	InboundToWG func([]byte)
}

// NewManager validates options; the client is created on Start.
func NewManager(opts Options) (*Manager, error) {
	if opts.Addr == "" {
		return nil, errors.New("proxyuplink: Addr is required")
	}
	if opts.RelayPeerID == "" {
		return nil, errors.New("proxyuplink: RelayPeerID is required")
	}
	if opts.NodeID == "" {
		return nil, errors.New("proxyuplink: NodeID is required")
	}
	return &Manager{addr: opts.Addr, relay: opts.RelayPeerID}, nil
}

// Addr returns the dial address / URL.
func (m *Manager) Addr() string {
	return m.addr
}

// RelayPeerID returns the gateway node ID.
func (m *Manager) RelayPeerID() string {
	return m.relay
}

// Start dials the gateway over WSS and runs the framed session until ctx is cancelled or Stop.
func (m *Manager) Start(ctx context.Context, server *config.Server, host *config.Config, opts Options) error {
	_ = server // retained for call-site compatibility; uplink auth uses WG keys, not API JWT
	if host == nil {
		return errors.New("proxyuplink: host config missing")
	}

	sni := opts.TLSServerName
	if sni == "" {
		sni = TLSServerNameFromAddr(opts.Addr)
	}
	tlsCfg := ClientTLSConfig(sni, opts.CertFingerprint)
	c, err := uplink.NewClient(uplink.ClientOptions{
		Addr:       opts.Addr,
		ServerName: sni,
		TLSConfig:  tlsCfg,
		HelloFactory: func() (uplink.ClientHello, error) {
			return buildClientHello(host, opts)
		},
		PacketHandler: func(pkt []byte) error {
			if opts.InboundToWG != nil {
				opts.InboundToWG(pkt)
			}
			return nil
		},
		Logger: slogAdapter{},
	})
	if err != nil {
		return err
	}

	runCtx, cancel := context.WithCancel(ctx)
	m.mu.Lock()
	m.cancel = cancel
	m.client = c
	m.mu.Unlock()

	if err := c.Start(runCtx); err != nil {
		cancel()
		m.mu.Lock()
		m.client = nil
		m.cancel = nil
		m.mu.Unlock()
		return err
	}

	activeMu.Lock()
	active = m
	activeMu.Unlock()
	slog.Info("uplink: client started",
		"transport", "wss",
		"url", opts.Addr,
		"relay", opts.RelayPeerID,
		"node", opts.NodeID,
	)
	return nil
}

// Stop shuts down the client.
func (m *Manager) Stop(ctx context.Context) error {
	m.mu.Lock()
	cancel := m.cancel
	c := m.client
	m.cancel = nil
	m.client = nil
	m.mu.Unlock()

	activeMu.Lock()
	if active == m {
		active = nil
	}
	activeMu.Unlock()

	if cancel != nil {
		cancel()
	}
	if c == nil {
		return nil
	}
	return c.Stop(ctx)
}

// SendPacket sends a WG packet to the gateway.
func (m *Manager) SendPacket(ctx context.Context, pkt []byte) error {
	m.mu.RLock()
	c := m.client
	m.mu.RUnlock()
	if c == nil {
		return uplink.ErrClientClosed
	}
	return c.SendPacket(ctx, pkt)
}

// State returns the uplink client state.
func (m *Manager) State() uplink.ClientState {
	m.mu.RLock()
	c := m.client
	m.mu.RUnlock()
	if c == nil {
		return uplink.StateDisconnected
	}
	return c.State()
}

type slogAdapter struct{}

func (slogAdapter) Debug(msg string, kv ...any) { slog.Debug(msg, kv...) }
func (slogAdapter) Info(msg string, kv ...any)  { slog.Info(msg, kv...) }
func (slogAdapter) Warn(msg string, kv ...any)  { slog.Warn(msg, kv...) }
func (slogAdapter) Error(msg string, kv ...any) { slog.Error(msg, kv...) }

// TLSServerNameFromAddr returns the host part of a WSS URL or host:port for SNI.
func TLSServerNameFromAddr(addr string) string {
	addr = strings.TrimSpace(addr)
	if strings.Contains(addr, "://") {
		u, err := url.Parse(addr)
		if err != nil {
			return ""
		}
		return u.Hostname()
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return host
}
