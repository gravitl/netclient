package cmd

import (
	"crypto/tls"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gravitl/netclient/proxy"
	"github.com/spf13/cobra"
	"golang.org/x/exp/slog"
)

var (
	proxyCmd = &cobra.Command{
		Use:   "proxy",
		Short: "Start a TCP proxy with TLS support",
		Long: `Start a TCP proxy that can forward traffic from local WireGuard interface to remote endpoints.
Supports both plain TCP and TLS connections. Ideal for bypassing firewall restrictions where UDP is blocked.`,
		RunE: runProxy,
	}

	// Proxy flags
	localPort      int
	remoteAddr     string
	useTLS         bool
	certFile       string
	keyFile        string
	skipVerify     bool
	bindToWG       bool
	timeout        time.Duration
	firewallBypass bool
	udpOverTCP     bool
	bufferSize     int
)

func init() {
	rootCmd.AddCommand(proxyCmd)

	proxyCmd.Flags().IntVarP(&localPort, "port", "p", 8080, "Local port to listen on")
	proxyCmd.Flags().StringVarP(&remoteAddr, "remote", "r", "", "Remote address to proxy to (required)")
	proxyCmd.Flags().BoolVarP(&useTLS, "tls", "t", false, "Enable TLS for the proxy")
	proxyCmd.Flags().StringVar(&certFile, "cert", "", "Certificate file for TLS (required if TLS is enabled)")
	proxyCmd.Flags().StringVar(&keyFile, "key", "", "Private key file for TLS (required if TLS is enabled)")
	proxyCmd.Flags().BoolVar(&skipVerify, "skip-verify", false, "Skip TLS certificate verification")
	proxyCmd.Flags().BoolVar(&bindToWG, "bind-wg", false, "Bind to WireGuard interface IP instead of all interfaces")
	proxyCmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "Connection timeout")
	proxyCmd.Flags().BoolVar(&firewallBypass, "firewall-bypass", false, "Enable firewall bypass mode (optimized for UDP-over-TCP)")
	proxyCmd.Flags().BoolVar(&udpOverTCP, "udp-over-tcp", false, "Enable UDP-over-TCP tunneling")
	proxyCmd.Flags().IntVar(&bufferSize, "buffer-size", 4096, "Buffer size for packet handling")

	proxyCmd.MarkFlagRequired("remote")
}

func runProxy(cmd *cobra.Command, args []string) error {
	// Validate TLS configuration
	if useTLS {
		if certFile == "" || keyFile == "" {
			return fmt.Errorf("certificate and key files are required when TLS is enabled")
		}
	}

	// Use firewall bypass mode if specified
	if firewallBypass {
		return runFirewallBypassProxy()
	}

	// Create WireGuard proxy configuration
	config := &proxy.WireGuardProxyConfig{
		LocalPort:  localPort,
		RemoteAddr: remoteAddr,
		UseTLS:     useTLS,
		Timeout:    timeout,
		BindToWG:   bindToWG,
	}

	// Setup TLS if enabled
	if useTLS {
		var tlsConfig *tls.Config
		var err error

		if skipVerify {
			tlsConfig = proxy.CreateClientTLSConfig(true)
		} else {
			tlsConfig, err = proxy.CreateTLSConfig(certFile, keyFile, false)
			if err != nil {
				return fmt.Errorf("failed to create TLS config: %w", err)
			}
		}

		config.TLSConfig = tlsConfig
	}

	// Create and start proxy
	wgProxy := proxy.NewWireGuardProxy(config)

	// Get WireGuard interface info for logging
	ifaceInfo := wgProxy.GetWireGuardInterfaceInfo()
	if ifaceInfo != nil {
		slog.Info("WireGuard interface info",
			"name", ifaceInfo["name"],
			"mtu", ifaceInfo["mtu"],
			"addresses", ifaceInfo["addresses"])
	}

	// Start the proxy
	if err := wgProxy.Start(); err != nil {
		return fmt.Errorf("failed to start proxy: %w", err)
	}

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Monitor proxy status
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	slog.Info("proxy running",
		"local_port", localPort,
		"remote", remoteAddr,
		"tls", useTLS,
		"bind_to_wg", bindToWG,
		"firewall_bypass", firewallBypass,
		"udp_over_tcp", udpOverTCP)

	for {
		select {
		case <-sigChan:
			slog.Info("received shutdown signal, stopping proxy...")
			wgProxy.Stop()
			return nil
		case <-ticker.C:
			activeConn := wgProxy.GetActiveConnections()
			slog.Debug("proxy status", "active_connections", activeConn)
		}
	}
}

// runFirewallBypassProxy runs the proxy in firewall bypass mode
func runFirewallBypassProxy() error {
	// Create firewall bypass tunnel
	tunnel := proxy.CreateFirewallBypassTunnel(localPort, remoteAddr, useTLS)

	// Setup TLS if enabled
	if useTLS {
		var tlsConfig *tls.Config
		var err error

		if skipVerify {
			tlsConfig = proxy.CreateClientTLSConfig(true)
		} else {
			tlsConfig, err = proxy.CreateTLSConfig(certFile, keyFile, false)
			if err != nil {
				return fmt.Errorf("failed to create TLS config: %w", err)
			}
		}

		// Update tunnel config with TLS
		tunnelConfig := &proxy.WireGuardTCPTunnelConfig{
			LocalPort:  localPort,
			RemoteAddr: remoteAddr,
			UseTLS:     useTLS,
			TLSConfig:  tlsConfig,
			Timeout:    timeout,
			BindToWG:   bindToWG,
			UDPOverTCP: true,
			BufferSize: bufferSize,
		}
		tunnel = proxy.NewWireGuardTCPTunnel(tunnelConfig)
	}

	// Get tunnel info for logging
	tunnelInfo := tunnel.GetTunnelInfo()
	if tunnelInfo != nil {
		slog.Info("firewall bypass tunnel info",
			"local_port", tunnelInfo["local_port"],
			"remote_addr", tunnelInfo["remote_addr"],
			"use_tls", tunnelInfo["use_tls"],
			"udp_over_tcp", tunnelInfo["udp_over_tcp"],
			"wg_interface", tunnelInfo["wg_interface"])
	}

	// Start the tunnel
	if err := tunnel.Start(); err != nil {
		return fmt.Errorf("failed to start firewall bypass tunnel: %w", err)
	}

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Monitor tunnel status
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	slog.Info("firewall bypass tunnel running",
		"local_port", localPort,
		"remote", remoteAddr,
		"tls", useTLS,
		"bind_to_wg", bindToWG)

	for {
		select {
		case <-sigChan:
			slog.Info("received shutdown signal, stopping tunnel...")
			tunnel.Stop()
			return nil
		case <-ticker.C:
			activeConn := tunnel.GetActiveConnections()
			slog.Debug("tunnel status", "active_connections", activeConn)
		}
	}
}
