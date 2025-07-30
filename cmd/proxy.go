package cmd

import (
	"crypto/tls"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gravitl/netclient/functions"
	"github.com/gravitl/netclient/proxy"
	"github.com/spf13/cobra"
	"golang.org/x/exp/slog"
)

var (
	proxyCmd = &cobra.Command{
		Use:   "proxy",
		Short: "Start a TCP proxy for WireGuard firewall bypass",
		Long: `Start a TCP proxy that can forward WireGuard traffic from local interface to remote endpoints.
Designed for bypassing firewall restrictions where UDP is blocked. Supports firewall bypass and failover integration modes.`,
		RunE: runProxy,
	}

	// Proxy flags
	localPort      int
	remoteAddr     string
	useTLS         bool
	certFile       string
	keyFile        string
	skipVerify     bool
	autoCert       bool
	bindToWG       bool
	timeout        time.Duration
	firewallBypass bool
	udpOverTCP     bool
	showStatus     bool
	bufferSize     int
)

func init() {
	rootCmd.AddCommand(proxyCmd)

	proxyCmd.Flags().IntVarP(&localPort, "port", "p", 8080, "Local port to listen on")
	proxyCmd.Flags().StringVarP(&remoteAddr, "remote", "r", "", "Remote address to proxy to (required)")
	proxyCmd.Flags().BoolVarP(&useTLS, "tls", "t", false, "Enable TLS for the proxy")
	proxyCmd.Flags().StringVar(&certFile, "cert", "", "Certificate file for TLS (auto-generated if not provided)")
	proxyCmd.Flags().StringVar(&keyFile, "key", "", "Private key file for TLS (auto-generated if not provided)")
	proxyCmd.Flags().BoolVar(&skipVerify, "skip-verify", false, "Skip TLS certificate verification")
	// proxyCmd.Flags().BoolVar(&autoCert, "auto-cert", false, "Automatically generate and manage TLS certificates") // TODO: add this back when cert manager is implemented.
	proxyCmd.Flags().BoolVar(&bindToWG, "bind-wg", false, "Bind to WireGuard interface IP instead of all interfaces")
	proxyCmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "Connection timeout")
	proxyCmd.Flags().BoolVar(&firewallBypass, "firewall-bypass", false, "Enable firewall bypass mode (optimized for UDP-over-TCP)")
	proxyCmd.Flags().BoolVar(&udpOverTCP, "udp-over-tcp", false, "Enable UDP-over-TCP tunneling")
	proxyCmd.Flags().BoolVar(&showStatus, "status", false, "Show status of active TCP proxies")

	proxyCmd.Flags().IntVar(&bufferSize, "buffer-size", 4096, "Buffer size for packet handling")

	proxyCmd.MarkFlagRequired("remote")
}

func runProxy(cmd *cobra.Command, args []string) error {
	// Handle TLS configuration
	if useTLS {
		if autoCert {
			// Auto-generate certificates
			tlsConfig, err := proxy.CreateAutoTLSConfig("localhost")
			if err != nil {
				return fmt.Errorf("failed to create auto TLS config: %w", err)
			}
			// Use the auto-generated config directly
			config := &proxy.WireGuardProxyConfig{
				LocalPort:  localPort,
				RemoteAddr: remoteAddr,
				UseTLS:     useTLS,
				TLSConfig:  tlsConfig,
				Timeout:    timeout,
				BindToWG:   bindToWG,
			}
			// Continue with the normal flow using the auto-generated config
			config.TLSConfig = tlsConfig
		} else if certFile == "" || keyFile == "" {
			return fmt.Errorf("certificate and key files are required when TLS is enabled (or use --auto-cert)")
		}
	}

	// Use firewall bypass mode if specified
	if firewallBypass {
		return runFirewallBypassProxy()
	}

	// Show status if requested
	if showStatus {
		return showProxyStatus()
	}

	// Default to firewall bypass mode
	return runFirewallBypassProxy()
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

// showProxyStatus displays the status of active TCP proxies
func showProxyStatus() error {
	failoverProxy := functions.GetFailoverTCPProxy()
	activeProxies := failoverProxy.GetActiveProxies()

	if len(activeProxies) == 0 {
		fmt.Println("No active TCP proxies")
		return nil
	}

	fmt.Println("Active TCP Proxies:")
	fmt.Println("===================")
	for peerKey, proxyInfo := range activeProxies {
		info := proxyInfo.(map[string]interface{})
		fmt.Printf("Peer: %s\n", peerKey)
		fmt.Printf("  Local Port: %v\n", info["local_port"])
		fmt.Printf("  Remote Addr: %v\n", info["remote_addr"])
		fmt.Printf("  Active Connections: %v\n", info["active_connections"])
		fmt.Println()
	}

	return nil
}
