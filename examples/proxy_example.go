package main

import (
	"crypto/tls"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gravitl/netclient/proxy"
)

func main() {
	// Parse command line flags
	var (
		localPort  = flag.Int("port", 8080, "Local port to listen on")
		remoteAddr = flag.String("remote", "", "Remote address to proxy to (required)")
		useTLS     = flag.Bool("tls", false, "Enable TLS for the proxy")
		certFile   = flag.String("cert", "", "Certificate file for TLS")
		keyFile    = flag.String("key", "", "Private key file for TLS")
		skipVerify = flag.Bool("skip-verify", false, "Skip TLS certificate verification")
		bindToWG   = flag.Bool("bind-wg", false, "Bind to WireGuard interface IP")
		timeout    = flag.Duration("timeout", 30*time.Second, "Connection timeout")
	)
	flag.Parse()

	if *remoteAddr == "" {
		log.Fatal("Remote address is required. Use -remote flag.")
	}

	// Validate TLS configuration
	if *useTLS {
		if *certFile == "" || *keyFile == "" {
			log.Fatal("Certificate and key files are required when TLS is enabled.")
		}
	}

	// Create WireGuard proxy configuration
	config := &proxy.WireGuardProxyConfig{
		LocalPort:  *localPort,
		RemoteAddr: *remoteAddr,
		UseTLS:     *useTLS,
		Timeout:    *timeout,
		BindToWG:   *bindToWG,
	}

	// Setup TLS if enabled
	if *useTLS {
		var tlsConfig *tls.Config
		var err error

		if *skipVerify {
			tlsConfig = proxy.CreateClientTLSConfig(true)
		} else {
			tlsConfig, err = proxy.CreateTLSConfig(*certFile, *keyFile, false)
			if err != nil {
				log.Fatalf("Failed to create TLS config: %v", err)
			}
		}

		config.TLSConfig = tlsConfig
	}

	// Create and start proxy
	wgProxy := proxy.NewWireGuardProxy(config)

	// Get WireGuard interface info for logging
	ifaceInfo := wgProxy.GetWireGuardInterfaceInfo()
	if ifaceInfo != nil {
		log.Printf("WireGuard interface: %s (MTU: %d, Addresses: %v)",
			ifaceInfo["name"], ifaceInfo["mtu"], ifaceInfo["addresses"])
	} else {
		log.Println("No WireGuard interface information available")
	}

	// Start the proxy
	if err := wgProxy.Start(); err != nil {
		log.Fatalf("Failed to start proxy: %v", err)
	}

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Monitor proxy status
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	log.Printf("Proxy started - Local: :%d, Remote: %s, TLS: %v, BindToWG: %v",
		*localPort, *remoteAddr, *useTLS, *bindToWG)

	for {
		select {
		case <-sigChan:
			log.Println("Received shutdown signal, stopping proxy...")
			wgProxy.Stop()
			return
		case <-ticker.C:
			activeConn := wgProxy.GetActiveConnections()
			log.Printf("Active connections: %d", activeConn)
		}
	}
}
