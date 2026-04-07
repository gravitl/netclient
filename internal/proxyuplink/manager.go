package proxyuplink

import (
	"context"
	"crypto/tls"
	"errors"
	"sync"
	"time"

	"github.com/gravitl/netclient/auth"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/proxy"
	"golang.org/x/exp/slog"
)

// Manager owns a TCP/TLS uplink proxy.Client to the relay.
type Manager struct {
	mu     sync.Mutex
	client *proxy.Client
	cancel context.CancelFunc
}

var (
	activeMu sync.Mutex
	active   *Manager

	inboundMu sync.RWMutex
	inboundFn func([]byte) error
)

// Active returns the last successfully started Manager (e.g. from the daemon), or nil.
func Active() *Manager {
	activeMu.Lock()
	defer activeMu.Unlock()
	return active
}

func setActiveIfCurrent(m *Manager) {
	activeMu.Lock()
	defer activeMu.Unlock()
	active = m
}

func clearActiveIf(m *Manager) {
	activeMu.Lock()
	defer activeMu.Unlock()
	if active == m {
		active = nil
	}
}

// Options configures the uplink (typically from environment + node context).
type Options struct {
	// Addr is host:port of the relay TCP/TLS listener (required).
	Addr string
	// TLSServerName is TLS SNI (optional; recommended).
	TLSServerName string
	// RelayPeerID is the designated relay/gateway node ID (required for ClientHello).
	RelayPeerID string
	// NetworkID is the logical network (optional).
	NetworkID string
	// InboundToWG delivers relay→client DATA frames into userspace WireGuard (e.g. wireguard.DeliverRelayTCPInbound).
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
	return &Manager{}, nil
}

// Start dials the relay and runs the framed session until ctx is cancelled or Stop.
func (m *Manager) Start(ctx context.Context, server *config.Server, host *config.Config, opts Options) error {
	if server == nil || server.API == "" {
		return errors.New("proxyuplink: server config missing")
	}
	if host == nil {
		return errors.New("proxyuplink: host config missing")
	}

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if opts.TLSServerName != "" {
		tlsCfg.ServerName = opts.TLSServerName
	}

	c, err := proxy.NewClient(proxy.ClientOptions{
		Addr:       opts.Addr,
		ServerName: opts.TLSServerName,
		TLSConfig:  tlsCfg,
		HelloFactory: func() (proxy.ClientHello, error) {
			token, err := auth.Authenticate(server, host)
			if err != nil {
				return proxy.ClientHello{}, err
			}
			return proxy.ClientHello{
				Version:     1,
				NodeID:      host.ID.String(),
				RelayPeerID: opts.RelayPeerID,
				NetworkID:   opts.NetworkID,
				Token:       token,
				Timestamp:   time.Now().Unix(),
			}, nil
		},
		PacketHandler: func(pkt []byte) error {
			if opts.InboundToWG != nil {
				opts.InboundToWG(pkt)
			}
			inboundMu.RLock()
			fn := inboundFn
			inboundMu.RUnlock()
			if fn != nil {
				return fn(pkt)
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
	setActiveIfCurrent(m)
	return nil
}

// Stop ends the uplink session.
func (m *Manager) Stop(ctx context.Context) error {
	m.mu.Lock()
	cancel := m.cancel
	c := m.client
	m.cancel = nil
	m.client = nil
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if c != nil {
		err := c.Stop(ctx)
		clearActiveIf(m)
		return err
	}
	clearActiveIf(m)
	return nil
}

// SendPacket sends framed WireGuard ciphertext to the relay.
func (m *Manager) SendPacket(ctx context.Context, pkt []byte) error {
	m.mu.Lock()
	c := m.client
	m.mu.Unlock()
	if c == nil {
		return proxy.ErrClientClosed
	}
	return c.SendPacket(ctx, pkt)
}

// State returns the proxy client state.
func (m *Manager) State() proxy.ClientState {
	m.mu.Lock()
	c := m.client
	m.mu.Unlock()
	if c == nil {
		return proxy.StateDisconnected
	}
	return c.State()
}

// SetInboundHandler registers where to deliver relay→client DATA frames (WireGuard ciphertext).
// Typically wired to userspace WireGuard receive path. Safe to call before Start.
func SetInboundHandler(fn func([]byte) error) {
	inboundMu.Lock()
	defer inboundMu.Unlock()
	inboundFn = fn
}

type slogAdapter struct{}

func (slogAdapter) Debug(msg string, kv ...any) {
	slog.Debug(msg, kv...)
}

func (slogAdapter) Info(msg string, kv ...any) {
	slog.Info(msg, kv...)
}

func (slogAdapter) Warn(msg string, kv ...any) {
	slog.Warn(msg, kv...)
}

func (slogAdapter) Error(msg string, kv ...any) {
	slog.Error(msg, kv...)
}
