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
	// Get common proxy manager
	proxyManager := proxy.GetProxyManager()

	// Create firewall bypass configuration
	config := proxyManager.CreateFirewallBypassConfig(localPort, remoteAddr, useTLS)

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

		// Update config with TLS
		config.TLSConfig = tlsConfig
		config.Timeout = timeout
		config.BindToWG = bindToWG
		config.BufferSize = bufferSize
	}

	// Start the proxy using common manager
	proxyID := fmt.Sprintf("manual_%d", localPort)
	if err := proxyManager.StartProxy(proxyID, config); err != nil {
		return fmt.Errorf("failed to start firewall bypass proxy: %w", err)
	}

	// Get proxy info for logging
	slog.Info("firewall bypass UDP-over-TCP proxy info",
		"local_port", config.LocalPort,
		"remote_addr", config.RemoteAddr,
		"use_tls", config.UseTLS,
		"bind_to_wg", config.BindToWG,
		"buffer_size", config.BufferSize)

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Monitor tunnel status
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	slog.Info("firewall bypass UDP-over-TCP proxy running",
		"local_port", localPort,
		"remote", remoteAddr,
		"tls", useTLS,
		"bind_to_wg", bindToWG)

	for {
		select {
		case <-sigChan:
			slog.Info("received shutdown signal, stopping proxy...")
			proxyManager.StopProxy(proxyID)
			return nil
		case <-ticker.C:
			if proxy, exists := proxyManager.GetProxy(proxyID); exists {
				activeConn := proxy.GetActiveConnections()
				slog.Debug("proxy status", "active_connections", activeConn)
			}
		}
	}
}

// showProxyStatus displays the status of active TCP proxies
func showProxyStatus() error {
	proxyManager := proxy.GetProxyManager()
	activeProxies := proxyManager.GetActiveProxies()

	if len(activeProxies) == 0 {
		fmt.Println("No active TCP proxies")
		return nil
	}

	fmt.Println("Active TCP Proxies:")
	fmt.Println("===================")
	for proxyID, proxyInfo := range activeProxies {
		info := proxyInfo.(map[string]interface{})
		fmt.Printf("Proxy ID: %s\n", proxyID)
		fmt.Printf("  Local Port: %v\n", info["local_port"])
		fmt.Printf("  Remote Addr: %v\n", info["remote_addr"])
		fmt.Printf("  Active Connections: %v\n", info["active_connections"])
		fmt.Printf("  TLS: %v\n", info["use_tls"])
		fmt.Printf("  Bind to WG: %v\n", info["bind_to_wg"])
		fmt.Println()
	}

	return nil
}
