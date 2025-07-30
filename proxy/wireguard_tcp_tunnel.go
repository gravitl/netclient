package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/gravitl/netclient/wireguard"
	"golang.org/x/exp/slog"
)

// WireGuardTCPTunnelConfig holds configuration for WireGuard TCP tunneling
type WireGuardTCPTunnelConfig struct {
	LocalPort  int
	RemoteAddr string
	UseTLS     bool
	TLSConfig  *tls.Config
	Timeout    time.Duration
	BindToWG   bool
	UDPOverTCP bool // Enable UDP-over-TCP tunneling
	BufferSize int  // Buffer size for UDP packet handling
}

// WireGuardTCPTunnel represents a TCP tunnel for WireGuard traffic
type WireGuardTCPTunnel struct {
	config *WireGuardTCPTunnelConfig
	proxy  *Proxy
	ctx    context.Context
	cancel context.CancelFunc
}

// NewWireGuardTCPTunnel creates a new WireGuard TCP tunnel
func NewWireGuardTCPTunnel(config *WireGuardTCPTunnelConfig) *WireGuardTCPTunnel {
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.BufferSize == 0 {
		config.BufferSize = 4096
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &WireGuardTCPTunnel{
		config: config,
		ctx:    ctx,
		cancel: cancel,
	}
}

// Start begins the WireGuard TCP tunnel
func (t *WireGuardTCPTunnel) Start() error {
	// Get WireGuard interface information
	wgIface := wireguard.GetInterface()
	if wgIface == nil {
		return fmt.Errorf("no WireGuard interface available")
	}

	// Determine local address to bind to
	var localAddr string
	if t.config.BindToWG {
		// Bind to WireGuard interface IP
		if len(wgIface.Addresses) == 0 {
			return fmt.Errorf("no addresses configured on WireGuard interface")
		}

		// Use the first IPv4 address, fallback to IPv6
		var bindIP net.IP
		for _, addr := range wgIface.Addresses {
			if addr.IP.To4() != nil {
				bindIP = addr.IP
				break
			}
		}
		if bindIP == nil && len(wgIface.Addresses) > 0 {
			bindIP = wgIface.Addresses[0].IP
		}

		if bindIP == nil {
			return fmt.Errorf("no valid IP address found on WireGuard interface")
		}

		localAddr = fmt.Sprintf("%s:%d", bindIP.String(), t.config.LocalPort)
		slog.Info("binding tunnel to WireGuard interface", "address", localAddr)
	} else {
		// Bind to all interfaces
		localAddr = fmt.Sprintf(":%d", t.config.LocalPort)
	}

	// Create underlying proxy with UDP-over-TCP support if enabled
	var proxyConfig *ProxyConfig
	if t.config.UDPOverTCP {
		proxyConfig = &ProxyConfig{
			LocalAddr:  localAddr,
			RemoteAddr: t.config.RemoteAddr,
			UseTLS:     t.config.UseTLS,
			TLSConfig:  t.config.TLSConfig,
			Timeout:    t.config.Timeout,
		}
	} else {
		// Standard TCP proxy
		proxyConfig = &ProxyConfig{
			LocalAddr:  localAddr,
			RemoteAddr: t.config.RemoteAddr,
			UseTLS:     t.config.UseTLS,
			TLSConfig:  t.config.TLSConfig,
			Timeout:    t.config.Timeout,
		}
	}

	t.proxy = NewProxy(proxyConfig)

	// Start the proxy
	if err := t.proxy.Start(); err != nil {
		return fmt.Errorf("failed to start tunnel: %w", err)
	}

	slog.Info("WireGuard TCP tunnel started",
		"local", localAddr,
		"remote", t.config.RemoteAddr,
		"tls", t.config.UseTLS,
		"udp_over_tcp", t.config.UDPOverTCP,
		"bind_to_wg", t.config.BindToWG)

	return nil
}

// Stop gracefully shuts down the WireGuard TCP tunnel
func (t *WireGuardTCPTunnel) Stop() error {
	t.cancel()

	if t.proxy != nil {
		t.proxy.Stop()
	}

	slog.Info("WireGuard TCP tunnel stopped")
	return nil
}

// GetActiveConnections returns the number of active connections
func (t *WireGuardTCPTunnel) GetActiveConnections() int {
	if t.proxy != nil {
		return t.proxy.GetActiveConnections()
	}
	return 0
}

// GetTunnelInfo returns information about the tunnel
func (t *WireGuardTCPTunnel) GetTunnelInfo() map[string]interface{} {
	wgIface := wireguard.GetInterface()
	if wgIface == nil {
		return nil
	}

	info := map[string]interface{}{
		"local_port":   t.config.LocalPort,
		"remote_addr":  t.config.RemoteAddr,
		"use_tls":      t.config.UseTLS,
		"udp_over_tcp": t.config.UDPOverTCP,
		"bind_to_wg":   t.config.BindToWG,
		"timeout":      t.config.Timeout.String(),
		"buffer_size":  t.config.BufferSize,
		"wg_interface": wgIface.Name,
		"wg_mtu":       wgIface.MTU,
		"wg_addresses": []string{},
	}

	for _, addr := range wgIface.Addresses {
		info["wg_addresses"] = append(info["wg_addresses"].([]string), addr.IP.String())
	}

	return info
}

// CreateFirewallBypassTunnel creates a tunnel specifically designed to bypass UDP firewall restrictions
func CreateFirewallBypassTunnel(localPort int, remoteAddr string, useTLS bool) *WireGuardTCPTunnel {
	config := &WireGuardTCPTunnelConfig{
		LocalPort:  localPort,
		RemoteAddr: remoteAddr,
		UseTLS:     useTLS,
		Timeout:    60 * time.Second, // Longer timeout for firewall bypass
		BindToWG:   true,             // Bind to WireGuard interface
		UDPOverTCP: true,             // Enable UDP-over-TCP tunneling
		BufferSize: 8192,             // Larger buffer for UDP packets
	}

	return NewWireGuardTCPTunnel(config)
}

// CreateSecureTunnel creates a tunnel with TLS encryption
func CreateSecureTunnel(localPort int, remoteAddr string, certFile, keyFile string) (*WireGuardTCPTunnel, error) {
	tlsConfig, err := CreateTLSConfig(certFile, keyFile, false)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS config: %w", err)
	}

	config := &WireGuardTCPTunnelConfig{
		LocalPort:  localPort,
		RemoteAddr: remoteAddr,
		UseTLS:     true,
		TLSConfig:  tlsConfig,
		Timeout:    30 * time.Second,
		BindToWG:   true,
		UDPOverTCP: true,
		BufferSize: 4096,
	}

	return NewWireGuardTCPTunnel(config), nil
}
