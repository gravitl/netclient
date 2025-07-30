package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/gravitl/netclient/wireguard"
	"golang.org/x/exp/slog"
)

// WireGuardProxyConfig holds configuration for WireGuard-specific proxy
type WireGuardProxyConfig struct {
	LocalPort  int
	RemoteAddr string
	UseTLS     bool
	TLSConfig  *tls.Config
	Timeout    time.Duration
	BindToWG   bool // Whether to bind to WireGuard interface specifically
}

// WireGuardProxy represents a proxy that works with WireGuard interfaces
type WireGuardProxy struct {
	config *WireGuardProxyConfig
	proxy  *Proxy
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewWireGuardProxy creates a new WireGuard proxy instance
func NewWireGuardProxy(config *WireGuardProxyConfig) *WireGuardProxy {
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &WireGuardProxy{
		config: config,
		ctx:    ctx,
		cancel: cancel,
	}
}

// Start begins the WireGuard proxy
func (wg *WireGuardProxy) Start() error {
	// Get WireGuard interface information
	wgIface := wireguard.GetInterface()
	if wgIface == nil {
		return fmt.Errorf("no WireGuard interface available")
	}

	// Determine local address to bind to
	var localAddr string
	if wg.config.BindToWG {
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

		localAddr = fmt.Sprintf("%s:%d", bindIP.String(), wg.config.LocalPort)
		slog.Info("binding to WireGuard interface", "address", localAddr)
	} else {
		// Bind to all interfaces
		localAddr = fmt.Sprintf(":%d", wg.config.LocalPort)
	}

	// Create underlying proxy
	proxyConfig := &ProxyConfig{
		LocalAddr:  localAddr,
		RemoteAddr: wg.config.RemoteAddr,
		UseTLS:     wg.config.UseTLS,
		TLSConfig:  wg.config.TLSConfig,
		Timeout:    wg.config.Timeout,
	}

	wg.proxy = NewProxy(proxyConfig)

	// Start the proxy
	if err := wg.proxy.Start(); err != nil {
		return fmt.Errorf("failed to start proxy: %w", err)
	}

	slog.Info("WireGuard proxy started",
		"local", localAddr,
		"remote", wg.config.RemoteAddr,
		"tls", wg.config.UseTLS,
		"bind_to_wg", wg.config.BindToWG)

	return nil
}

// Stop gracefully shuts down the WireGuard proxy
func (wg *WireGuardProxy) Stop() error {
	wg.cancel()

	if wg.proxy != nil {
		wg.proxy.Stop()
	}

	slog.Info("WireGuard proxy stopped")
	return nil
}

// GetActiveConnections returns the number of active connections
func (wg *WireGuardProxy) GetActiveConnections() int {
	if wg.proxy != nil {
		return wg.proxy.GetActiveConnections()
	}
	return 0
}

// GetWireGuardInterfaceInfo returns information about the WireGuard interface
func (wg *WireGuardProxy) GetWireGuardInterfaceInfo() map[string]interface{} {
	wgIface := wireguard.GetInterface()
	if wgIface == nil {
		return nil
	}

	info := map[string]interface{}{
		"name":      wgIface.Name,
		"mtu":       wgIface.MTU,
		"addresses": []string{},
	}

	for _, addr := range wgIface.Addresses {
		info["addresses"] = append(info["addresses"].([]string), addr.IP.String())
	}

	return info
}

// GetConfig returns the proxy configuration
func (wg *WireGuardProxy) GetConfig() *WireGuardProxyConfig {
	return wg.config
}

// CreateTLSConfig creates a TLS configuration for the proxy
func CreateTLSConfig(certFile, keyFile string, skipVerify bool) (*tls.Config, error) {
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("certificate and key files are required for TLS")
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %w", err)
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	if skipVerify {
		config.InsecureSkipVerify = true
	}

	return config, nil
}

// CreateClientTLSConfig creates a TLS configuration for client connections
func CreateClientTLSConfig(skipVerify bool) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: skipVerify,
		MinVersion:         tls.VersionTLS12,
	}
}
