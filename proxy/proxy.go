package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/exp/slog"
)

// ProxyConfig holds configuration for the TCP proxy
type ProxyConfig struct {
	LocalAddr  string
	RemoteAddr string
	UseTLS     bool
	TLSConfig  *tls.Config
	Timeout    time.Duration
}

// Proxy represents a TCP proxy instance
type Proxy struct {
	config     *ProxyConfig
	listener   net.Listener
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	activeConn sync.Map
}

// NewProxy creates a new TCP proxy instance
func NewProxy(config *ProxyConfig) *Proxy {
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &Proxy{
		config: config,
		ctx:    ctx,
		cancel: cancel,
	}
}

// Start begins listening for connections and proxying them
func (p *Proxy) Start() error {
	var err error
	if p.config.UseTLS {
		p.listener, err = tls.Listen("tcp", p.config.LocalAddr, p.config.TLSConfig)
	} else {
		p.listener, err = net.Listen("tcp", p.config.LocalAddr)
	}

	if err != nil {
		return fmt.Errorf("failed to start listener: %w", err)
	}

	slog.Info("proxy started", "local", p.config.LocalAddr, "remote", p.config.RemoteAddr, "tls", p.config.UseTLS)

	p.wg.Add(1)
	go p.acceptLoop()

	return nil
}

// Stop gracefully shuts down the proxy
func (p *Proxy) Stop() error {
	p.cancel()

	if p.listener != nil {
		p.listener.Close()
	}

	// Close all active connections
	p.activeConn.Range(func(key, value interface{}) bool {
		if conn, ok := value.(net.Conn); ok {
			conn.Close()
		}
		p.activeConn.Delete(key)
		return true
	})

	p.wg.Wait()
	slog.Info("proxy stopped")
	return nil
}

// acceptLoop handles incoming connections
func (p *Proxy) acceptLoop() {
	defer p.wg.Done()

	for {
		select {
		case <-p.ctx.Done():
			return
		default:
			conn, err := p.listener.Accept()
			if err != nil {
				if p.ctx.Err() != nil {
					// Context was cancelled, this is expected
					return
				}
				slog.Error("failed to accept connection", "error", err)
				continue
			}

			p.wg.Add(1)
			go p.handleConnection(conn)
		}
	}
}

// handleConnection handles a single client connection
func (p *Proxy) handleConnection(clientConn net.Conn) {
	defer p.wg.Done()
	defer clientConn.Close()

	// Store connection for cleanup
	connID := fmt.Sprintf("%p", clientConn)
	p.activeConn.Store(connID, clientConn)
	defer p.activeConn.Delete(connID)

	// Connect to remote endpoint
	var remoteConn net.Conn
	var err error

	if p.config.UseTLS {
		remoteConn, err = tls.DialWithDialer(
			&net.Dialer{Timeout: p.config.Timeout},
			"tcp",
			p.config.RemoteAddr,
			p.config.TLSConfig,
		)
	} else {
		remoteConn, err = net.DialTimeout("tcp", p.config.RemoteAddr, p.config.Timeout)
	}

	if err != nil {
		slog.Error("failed to connect to remote", "error", err, "remote", p.config.RemoteAddr)
		return
	}
	defer remoteConn.Close()

	slog.Debug("proxy connection established",
		"client", clientConn.RemoteAddr(),
		"remote", p.config.RemoteAddr)

	// Start bidirectional data transfer
	var wg sync.WaitGroup
	wg.Add(2)

	// Client -> Remote
	go func() {
		defer wg.Done()
		io.Copy(remoteConn, clientConn)
		remoteConn.(*net.TCPConn).CloseWrite()
	}()

	// Remote -> Client
	go func() {
		defer wg.Done()
		io.Copy(clientConn, remoteConn)
		clientConn.(*net.TCPConn).CloseWrite()
	}()

	wg.Wait()
	slog.Debug("proxy connection closed", "client", clientConn.RemoteAddr())
}

// GetActiveConnections returns the number of active connections
func (p *Proxy) GetActiveConnections() int {
	count := 0
	p.activeConn.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	return count
}
