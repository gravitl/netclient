package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/gravitl/netclient/wireguard"
	"golang.org/x/exp/slog"
)

// WireGuardUDPProxyConfig holds configuration for WireGuard UDP-over-TCP proxy
type WireGuardUDPProxyConfig struct {
	LocalPort  int
	RemoteAddr string
	UseTLS     bool
	TLSConfig  *tls.Config
	Timeout    time.Duration
	BindToWG   bool
	BufferSize int
}

// WireGuardUDPProxy represents a UDP-over-TCP proxy for WireGuard traffic
type WireGuardUDPProxy struct {
	config     *WireGuardUDPProxyConfig
	listener   net.Listener
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	activeConn sync.Map
}

// NewWireGuardUDPProxy creates a new WireGuard UDP-over-TCP proxy
func NewWireGuardUDPProxy(config *WireGuardUDPProxyConfig) *WireGuardUDPProxy {
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.BufferSize == 0 {
		config.BufferSize = 8192
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &WireGuardUDPProxy{
		config: config,
		ctx:    ctx,
		cancel: cancel,
	}
}

// Start begins the WireGuard UDP-over-TCP proxy
func (w *WireGuardUDPProxy) Start() error {
	// Get WireGuard interface information
	wgIface := wireguard.GetInterface()
	if wgIface == nil {
		return fmt.Errorf("no WireGuard interface available")
	}

	// Determine local address to bind to
	var localAddr string
	if w.config.BindToWG {
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

		localAddr = fmt.Sprintf("%s:%d", bindIP.String(), w.config.LocalPort)
		slog.Info("binding UDP proxy to WireGuard interface", "address", localAddr)
	} else {
		// Bind to all interfaces
		localAddr = fmt.Sprintf(":%d", w.config.LocalPort)
	}

	// Start TCP listener
	var err error
	if w.config.UseTLS {
		w.listener, err = tls.Listen("tcp", localAddr, w.config.TLSConfig)
	} else {
		w.listener, err = net.Listen("tcp", localAddr)
	}

	if err != nil {
		return fmt.Errorf("failed to start listener: %w", err)
	}

	slog.Info("WireGuard UDP-over-TCP proxy started",
		"local", localAddr,
		"remote", w.config.RemoteAddr,
		"tls", w.config.UseTLS,
		"bind_to_wg", w.config.BindToWG)

	w.wg.Add(1)
	go w.acceptLoop()

	return nil
}

// Stop gracefully shuts down the WireGuard UDP-over-TCP proxy
func (w *WireGuardUDPProxy) Stop() error {
	w.cancel()

	if w.listener != nil {
		w.listener.Close()
	}

	// Close all active connections
	w.activeConn.Range(func(key, value interface{}) bool {
		if conn, ok := value.(net.Conn); ok {
			conn.Close()
		}
		w.activeConn.Delete(key)
		return true
	})

	w.wg.Wait()
	slog.Info("WireGuard UDP-over-TCP proxy stopped")
	return nil
}

// acceptLoop handles incoming TCP connections
func (w *WireGuardUDPProxy) acceptLoop() {
	defer w.wg.Done()

	for {
		select {
		case <-w.ctx.Done():
			return
		default:
			conn, err := w.listener.Accept()
			if err != nil {
				if w.ctx.Err() != nil {
					// Context was cancelled, this is expected
					return
				}
				slog.Error("failed to accept connection", "error", err)
				continue
			}

			w.wg.Add(1)
			go w.handleUDPOverTCP(conn)
		}
	}
}

// handleUDPOverTCP handles UDP-over-TCP tunneling
func (w *WireGuardUDPProxy) handleUDPOverTCP(clientConn net.Conn) {
	defer w.wg.Done()
	defer clientConn.Close()

	// Store connection for cleanup
	connID := fmt.Sprintf("%p", clientConn)
	w.activeConn.Store(connID, clientConn)
	defer w.activeConn.Delete(connID)

	// Connect to remote WireGuard endpoint
	var remoteConn net.Conn
	var err error

	if w.config.UseTLS {
		remoteConn, err = tls.DialWithDialer(
			&net.Dialer{Timeout: w.config.Timeout},
			"tcp",
			w.config.RemoteAddr,
			w.config.TLSConfig,
		)
	} else {
		remoteConn, err = net.DialTimeout("tcp", w.config.RemoteAddr, w.config.Timeout)
	}

	if err != nil {
		slog.Error("failed to connect to remote WireGuard endpoint", "error", err, "remote", w.config.RemoteAddr)
		return
	}
	defer remoteConn.Close()

	slog.Debug("UDP-over-TCP tunnel established",
		"client", clientConn.RemoteAddr(),
		"remote", w.config.RemoteAddr)

	// Start bidirectional data transfer with UDP packet handling
	var wg sync.WaitGroup
	wg.Add(2)

	// Client -> Remote (UDP packets over TCP)
	go func() {
		defer wg.Done()
		buffer := make([]byte, w.config.BufferSize)
		for {
			n, err := clientConn.Read(buffer)
			if err != nil {
				if err != io.EOF {
					slog.Debug("client read error", "error", err)
				}
				break
			}
			if n > 0 {
				// Write UDP packet length + data
				length := uint16(n)
				_, err = remoteConn.Write([]byte{byte(length >> 8), byte(length & 0xFF)})
				if err != nil {
					slog.Debug("failed to write packet length", "error", err)
					break
				}
				_, err = remoteConn.Write(buffer[:n])
				if err != nil {
					slog.Debug("failed to write packet data", "error", err)
					break
				}
			}
		}
		remoteConn.(*net.TCPConn).CloseWrite()
	}()

	// Remote -> Client (UDP packets over TCP)
	go func() {
		defer wg.Done()
		lengthBuffer := make([]byte, 2)
		for {
			// Read packet length
			_, err := io.ReadFull(remoteConn, lengthBuffer)
			if err != nil {
				if err != io.EOF {
					slog.Debug("remote read length error", "error", err)
				}
				break
			}
			length := uint16(lengthBuffer[0])<<8 | uint16(lengthBuffer[1])

			// Read packet data
			buffer := make([]byte, length)
			_, err = io.ReadFull(remoteConn, buffer)
			if err != nil {
				slog.Debug("remote read data error", "error", err)
				break
			}

			// Write to client
			_, err = clientConn.Write(buffer)
			if err != nil {
				slog.Debug("client write error", "error", err)
				break
			}
		}
		clientConn.(*net.TCPConn).CloseWrite()
	}()

	wg.Wait()
	slog.Debug("UDP-over-TCP tunnel closed", "client", clientConn.RemoteAddr())
}

// GetActiveConnections returns the number of active connections
func (w *WireGuardUDPProxy) GetActiveConnections() int {
	count := 0
	w.activeConn.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	return count
}

// GetConfig returns the proxy configuration
func (w *WireGuardUDPProxy) GetConfig() *WireGuardUDPProxyConfig {
	return w.config
}

// CreateFirewallBypassUDPProxy creates a UDP-over-TCP proxy for firewall bypass
func CreateFirewallBypassUDPProxy(localPort int, remoteAddr string, useTLS bool) *WireGuardUDPProxy {
	config := &WireGuardUDPProxyConfig{
		LocalPort:  localPort,
		RemoteAddr: remoteAddr,
		UseTLS:     useTLS,
		Timeout:    60 * time.Second, // Longer timeout for firewall bypass
		BindToWG:   true,             // Bind to WireGuard interface
		BufferSize: 8192,             // Larger buffer for UDP packets
	}

	return NewWireGuardUDPProxy(config)
}
