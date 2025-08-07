package proxy

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/exp/slog"
)

// ProxyManager manages TCP proxies for WireGuard traffic
type ProxyManager struct {
	proxies map[string]*WireGuardUDPProxy
	mutex   sync.RWMutex
	ctx     context.Context
	cancel  context.CancelFunc
}

// NewProxyManager creates a new proxy manager
func NewProxyManager() *ProxyManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &ProxyManager{
		proxies: make(map[string]*WireGuardUDPProxy),
		ctx:     ctx,
		cancel:  cancel,
	}
}

// StartProxy starts a TCP proxy for a specific peer/endpoint
func (pm *ProxyManager) StartProxy(proxyID string, config *WireGuardUDPProxyConfig) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	// Check if proxy already exists
	if _, exists := pm.proxies[proxyID]; exists {
		slog.Debug("proxy already exists", "id", proxyID)
		return nil
	}

	// Create and start proxy
	proxy := NewWireGuardUDPProxy(config)
	if err := proxy.Start(); err != nil {
		return fmt.Errorf("failed to start proxy %s: %w", proxyID, err)
	}

	// Store proxy
	pm.proxies[proxyID] = proxy

	slog.Info("started TCP proxy",
		"id", proxyID,
		"local_port", config.LocalPort,
		"remote", config.RemoteAddr,
		"tls", config.UseTLS)

	return nil
}

// StopProxy stops a specific proxy
func (pm *ProxyManager) StopProxy(proxyID string) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	if proxy, exists := pm.proxies[proxyID]; exists {
		proxy.Stop()
		delete(pm.proxies, proxyID)
		slog.Info("stopped TCP proxy", "id", proxyID)
	}

	return nil
}

// GetProxy returns a specific proxy
func (pm *ProxyManager) GetProxy(proxyID string) (*WireGuardUDPProxy, bool) {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	proxy, exists := pm.proxies[proxyID]
	return proxy, exists
}

// IsProxyActive checks if a proxy is active
func (pm *ProxyManager) IsProxyActive(proxyID string) bool {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	_, exists := pm.proxies[proxyID]
	return exists
}

// GetActiveProxies returns information about all active proxies
func (pm *ProxyManager) GetActiveProxies() map[string]interface{} {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	activeProxies := make(map[string]interface{})
	for proxyID, proxy := range pm.proxies {
		config := proxy.GetConfig()
		activeProxies[proxyID] = map[string]interface{}{
			"local_port":         config.LocalPort,
			"remote_addr":        config.RemoteAddr,
			"active_connections": proxy.GetActiveConnections(),
			"use_tls":            config.UseTLS,
			"bind_to_wg":         config.BindToWG,
		}
	}
	return activeProxies
}

// StopAllProxies stops all active proxies
func (pm *ProxyManager) StopAllProxies() {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	for proxyID, proxy := range pm.proxies {
		proxy.Stop()
		slog.Info("stopped TCP proxy", "id", proxyID)
	}
	pm.proxies = make(map[string]*WireGuardUDPProxy)
}

// FindAvailablePort finds an available port for a proxy
func (pm *ProxyManager) FindAvailablePort() (int, error) {
	// Try ports in range 49152-65535 (dynamic/private ports)
	for port := 49152; port <= 65535; port++ {
		addr := fmt.Sprintf(":%d", port)
		listener, err := net.Listen("tcp", addr)
		if err == nil {
			listener.Close()
			return port, nil
		}
	}
	return 0, fmt.Errorf("no available ports found")
}

// CreateFirewallBypassConfig creates a configuration for firewall bypass
func (pm *ProxyManager) CreateFirewallBypassConfig(localPort int, remoteAddr string, useTLS bool) *WireGuardUDPProxyConfig {
	return &WireGuardUDPProxyConfig{
		LocalPort:  localPort,
		RemoteAddr: remoteAddr,
		UseTLS:     useTLS,
		Timeout:    60 * time.Second, // Longer timeout for firewall bypass
		BindToWG:   true,             // Bind to WireGuard interface
		BufferSize: 8192,             // Larger buffer for UDP packets
	}
}

// CreateFailoverConfig creates a configuration for failover scenarios
func (pm *ProxyManager) CreateFailoverConfig(remoteAddr string) (*WireGuardUDPProxyConfig, int, error) {
	localPort, err := pm.FindAvailablePort()
	if err != nil {
		return nil, 0, err
	}

	config := &WireGuardUDPProxyConfig{
		LocalPort:  localPort,
		RemoteAddr: remoteAddr,
		UseTLS:     false, // Can be made configurable
		Timeout:    60 * time.Second,
		BindToWG:   true,
		BufferSize: 8192,
	}

	return config, localPort, nil
}

// Global proxy manager instance
var globalProxyManager *ProxyManager

// GetProxyManager returns the global proxy manager instance
func GetProxyManager() *ProxyManager {
	if globalProxyManager == nil {
		globalProxyManager = NewProxyManager()
	}
	return globalProxyManager
}
