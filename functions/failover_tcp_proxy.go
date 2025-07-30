package functions

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/gravitl/netclient/proxy"
	"github.com/gravitl/netclient/wireguard"
	"golang.org/x/exp/slog"
)

// FailoverTCPProxy manages TCP proxy connections for failed UDP peer connections
type FailoverTCPProxy struct {
	peerProxies map[string]*proxy.WireGuardProxy
	mutex       sync.RWMutex
	ctx         context.Context
	cancel      context.CancelFunc
}

// NewFailoverTCPProxy creates a new failover TCP proxy manager
func NewFailoverTCPProxy() *FailoverTCPProxy {
	ctx, cancel := context.WithCancel(context.Background())
	return &FailoverTCPProxy{
		peerProxies: make(map[string]*proxy.WireGuardProxy),
		ctx:         ctx,
		cancel:      cancel,
	}
}

// StartTCPProxyForPeer starts a TCP proxy for a specific peer when UDP fails
func (ftp *FailoverTCPProxy) StartTCPProxyForPeer(peerKey string, peerEndpoint string) error {
	ftp.mutex.Lock()
	defer ftp.mutex.Unlock()

	// Check if proxy already exists for this peer
	if _, exists := ftp.peerProxies[peerKey]; exists {
		slog.Debug("TCP proxy already exists for peer", "peer", peerKey)
		return nil
	}

	// Get WireGuard interface info
	wgIface := wireguard.GetInterface()
	if wgIface == nil {
		return fmt.Errorf("no WireGuard interface available")
	}

	// Find available port for proxy
	localPort, err := findAvailablePort()
	if err != nil {
		return fmt.Errorf("failed to find available port: %w", err)
	}

	// Create proxy configuration for this peer
	config := &proxy.WireGuardProxyConfig{
		LocalPort:  localPort,
		RemoteAddr: peerEndpoint,
		UseTLS:     false, // Can be made configurable
		Timeout:    60 * time.Second,
		BindToWG:   true,
	}

	// Create and start proxy
	peerProxy := proxy.NewWireGuardProxy(config)
	if err := peerProxy.Start(); err != nil {
		return fmt.Errorf("failed to start TCP proxy for peer %s: %w", peerKey, err)
	}

	// Store proxy for this peer
	ftp.peerProxies[peerKey] = peerProxy

	slog.Info("started TCP proxy for failed UDP peer",
		"peer", peerKey,
		"local_port", localPort,
		"remote", peerEndpoint)

	return nil
}

// StopTCPProxyForPeer stops the TCP proxy for a specific peer
func (ftp *FailoverTCPProxy) StopTCPProxyForPeer(peerKey string) error {
	ftp.mutex.Lock()
	defer ftp.mutex.Unlock()

	if peerProxy, exists := ftp.peerProxies[peerKey]; exists {
		peerProxy.Stop()
		delete(ftp.peerProxies, peerKey)
		slog.Info("stopped TCP proxy for peer", "peer", peerKey)
	}

	return nil
}

// GetPeerProxyPort returns the local port used for a peer's TCP proxy
func (ftp *FailoverTCPProxy) GetPeerProxyPort(peerKey string) (int, bool) {
	ftp.mutex.RLock()
	defer ftp.mutex.RUnlock()

	if peerProxy, exists := ftp.peerProxies[peerKey]; exists {
		return peerProxy.GetConfig().LocalPort, true
	}
	return 0, false
}

// IsPeerUsingTCPProxy checks if a peer is currently using TCP proxy
func (ftp *FailoverTCPProxy) IsPeerUsingTCPProxy(peerKey string) bool {
	ftp.mutex.RLock()
	defer ftp.mutex.RUnlock()

	_, exists := ftp.peerProxies[peerKey]
	return exists
}

// GetActiveProxies returns information about all active TCP proxies
func (ftp *FailoverTCPProxy) GetActiveProxies() map[string]interface{} {
	ftp.mutex.RLock()
	defer ftp.mutex.RUnlock()

	activeProxies := make(map[string]interface{})
	for peerKey, peerProxy := range ftp.peerProxies {
		config := peerProxy.GetConfig()
		activeProxies[peerKey] = map[string]interface{}{
			"local_port":         config.LocalPort,
			"remote_addr":        config.RemoteAddr,
			"active_connections": peerProxy.GetActiveConnections(),
		}
	}
	return activeProxies
}

// StopAllProxies stops all active TCP proxies
func (ftp *FailoverTCPProxy) StopAllProxies() {
	ftp.mutex.Lock()
	defer ftp.mutex.Unlock()

	for peerKey, peerProxy := range ftp.peerProxies {
		peerProxy.Stop()
		slog.Info("stopped TCP proxy for peer", "peer", peerKey)
	}
	ftp.peerProxies = make(map[string]*proxy.WireGuardProxy)
}

// findAvailablePort finds an available port for the TCP proxy
func findAvailablePort() (int, error) {
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

// Global failover TCP proxy instance
var failoverTCPProxy *FailoverTCPProxy

// GetFailoverTCPProxy returns the global failover TCP proxy instance
func GetFailoverTCPProxy() *FailoverTCPProxy {
	if failoverTCPProxy == nil {
		failoverTCPProxy = NewFailoverTCPProxy()
	}
	return failoverTCPProxy
}
