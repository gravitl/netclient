package functions

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/proxy"
	"github.com/gravitl/netclient/wireguard"
	"golang.org/x/exp/slog"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// FailoverTCPProxy manages TCP proxy connections for failed UDP peer connections
type FailoverTCPProxy struct {
	proxyManager *proxy.ProxyManager
	mutex        sync.RWMutex
	ctx          context.Context
	cancel       context.CancelFunc
}

// NewFailoverTCPProxy creates a new failover TCP proxy manager
func NewFailoverTCPProxy() *FailoverTCPProxy {
	ctx, cancel := context.WithCancel(context.Background())
	return &FailoverTCPProxy{
		proxyManager: proxy.GetProxyManager(),
		ctx:          ctx,
		cancel:       cancel,
	}
}

// StartTCPProxyForPeer starts a TCP proxy for a specific peer when UDP fails
func (ftp *FailoverTCPProxy) StartTCPProxyForPeer(peerKey string, peerEndpoint string) error {
	ftp.mutex.Lock()
	defer ftp.mutex.Unlock()

	// Check if proxy already exists for this peer
	if ftp.proxyManager.IsProxyActive(peerKey) {
		slog.Debug("TCP proxy already exists for peer", "peer", peerKey)
		return nil
	}

	// Create failover configuration
	config, localPort, err := ftp.proxyManager.CreateFailoverConfig(peerEndpoint)
	if err != nil {
		return fmt.Errorf("failed to create failover config: %w", err)
	}

	// Start proxy using common manager
	if err := ftp.proxyManager.StartProxy(peerKey, config); err != nil {
		return fmt.Errorf("failed to start TCP proxy for peer %s: %w", peerKey, err)
	}

	// Update WireGuard interface to point peer to local TCP proxy
	if err := ftp.updateWireGuardPeerEndpoint(peerKey, localPort); err != nil {
		// Clean up proxy if WireGuard update fails
		ftp.proxyManager.StopProxy(peerKey)
		return fmt.Errorf("failed to update WireGuard peer endpoint: %w", err)
	}

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

	if ftp.proxyManager.IsProxyActive(peerKey) {
		// Restore original WireGuard peer endpoint
		if err := ftp.restoreWireGuardPeerEndpoint(peerKey); err != nil {
			slog.Warn("failed to restore WireGuard peer endpoint", "peer", peerKey, "error", err)
		}

		ftp.proxyManager.StopProxy(peerKey)
		slog.Info("stopped TCP proxy for peer", "peer", peerKey)
	}

	return nil
}

// updateWireGuardPeerEndpoint updates the WireGuard peer to use local TCP proxy
func (ftp *FailoverTCPProxy) updateWireGuardPeerEndpoint(peerKey string, localPort int) error {
	// Get current peer configuration
	peer, err := wireguard.GetPeer(ncutils.GetInterfaceName(), peerKey)
	if err != nil {
		return fmt.Errorf("failed to get peer: %w", err)
	}

	// Get WireGuard interface IP for local endpoint
	wgIface := wireguard.GetInterface()
	if wgIface == nil {
		return fmt.Errorf("no WireGuard interface available")
	}

	var localIP net.IP
	for _, addr := range wgIface.Addresses {
		if addr.IP.To4() != nil {
			localIP = addr.IP
			break
		}
	}
	if localIP == nil && len(wgIface.Addresses) > 0 {
		localIP = wgIface.Addresses[0].IP
	}
	if localIP == nil {
		return fmt.Errorf("no valid IP address found on WireGuard interface")
	}

	// Create new endpoint pointing to local TCP proxy
	localEndpoint := &net.UDPAddr{
		IP:   localIP,
		Port: localPort,
	}

	// Update peer configuration
	peerConfig := wgtypes.PeerConfig{
		PublicKey:                   peer.PublicKey,
		Endpoint:                    localEndpoint,
		PersistentKeepaliveInterval: &peer.PersistentKeepaliveInterval,
		AllowedIPs:                  peer.AllowedIPs,
		PresharedKey:                &peer.PresharedKey,
	}

	// Apply the update
	if err := wireguard.UpdatePeer(&peerConfig); err != nil {
		return fmt.Errorf("failed to update WireGuard peer: %w", err)
	}

	slog.Info("updated WireGuard peer to use TCP proxy",
		"peer", peerKey,
		"endpoint", localEndpoint.String())

	return nil
}

// restoreWireGuardPeerEndpoint restores the original WireGuard peer endpoint
func (ftp *FailoverTCPProxy) restoreWireGuardPeerEndpoint(peerKey string) error {
	// Get current peer configuration
	peer, err := wireguard.GetPeer(ncutils.GetInterfaceName(), peerKey)
	if err != nil {
		return fmt.Errorf("failed to get peer: %w", err)
	}

	// Find the original peer configuration from netclient config
	hostPeers := config.Netclient().HostPeers
	var originalPeer *wgtypes.PeerConfig
	for _, hp := range hostPeers {
		if hp.PublicKey.String() == peerKey {
			originalPeer = &hp
			break
		}
	}

	if originalPeer == nil {
		return fmt.Errorf("original peer configuration not found")
	}

	// Restore original endpoint
	peerConfig := wgtypes.PeerConfig{
		PublicKey:                   peer.PublicKey,
		Endpoint:                    originalPeer.Endpoint,
		PersistentKeepaliveInterval: &peer.PersistentKeepaliveInterval,
		AllowedIPs:                  peer.AllowedIPs,
		PresharedKey:                &peer.PresharedKey,
	}

	// Apply the update
	if err := wireguard.UpdatePeer(&peerConfig); err != nil {
		return fmt.Errorf("failed to restore WireGuard peer: %w", err)
	}

	slog.Info("restored WireGuard peer to original endpoint",
		"peer", peerKey,
		"endpoint", originalPeer.Endpoint.String())

	return nil
}

// GetPeerProxyPort returns the local port used for a peer's TCP proxy
func (ftp *FailoverTCPProxy) GetPeerProxyPort(peerKey string) (int, bool) {
	ftp.mutex.RLock()
	defer ftp.mutex.RUnlock()

	if proxy, exists := ftp.proxyManager.GetProxy(peerKey); exists {
		return proxy.GetConfig().LocalPort, true
	}
	return 0, false
}

// IsPeerUsingTCPProxy checks if a peer is currently using TCP proxy
func (ftp *FailoverTCPProxy) IsPeerUsingTCPProxy(peerKey string) bool {
	ftp.mutex.RLock()
	defer ftp.mutex.RUnlock()

	return ftp.proxyManager.IsProxyActive(peerKey)
}

// GetActiveProxies returns information about all active TCP proxies
func (ftp *FailoverTCPProxy) GetActiveProxies() map[string]interface{} {
	ftp.mutex.RLock()
	defer ftp.mutex.RUnlock()

	return ftp.proxyManager.GetActiveProxies()
}

// StopAllProxies stops all active TCP proxies
func (ftp *FailoverTCPProxy) StopAllProxies() {
	ftp.mutex.Lock()
	defer ftp.mutex.Unlock()

	// Get all active proxies and restore their endpoints
	activeProxies := ftp.proxyManager.GetActiveProxies()
	for proxyID := range activeProxies {
		ftp.restoreWireGuardPeerEndpoint(proxyID)
	}

	ftp.proxyManager.StopAllProxies()
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
