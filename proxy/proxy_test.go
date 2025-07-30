package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"
)

// generateTestCert creates a self-signed certificate for testing
func generateTestCert() (*tls.Config, error) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	// Create certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	// Encode certificate
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// Create TLS config
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// startTestServer starts a simple TCP server for testing
func startTestServer(addr string, tlsConfig *tls.Config) (net.Listener, error) {
	var listener net.Listener
	var err error

	if tlsConfig != nil {
		listener, err = tls.Listen("tcp", addr, tlsConfig)
	} else {
		listener, err = net.Listen("tcp", addr)
	}

	if err != nil {
		return nil, err
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// Echo back any data received
				buffer := make([]byte, 1024)
				for {
					n, err := c.Read(buffer)
					if err != nil {
						return
					}
					c.Write(buffer[:n])
				}
			}(conn)
		}
	}()

	return listener, nil
}

func TestProxyBasic(t *testing.T) {
	// Start test server
	server, err := startTestServer("127.0.0.1:0", nil)
	if err != nil {
		t.Fatalf("Failed to start test server: %v", err)
	}
	defer server.Close()

	serverAddr := server.Addr().String()

	// Create proxy configuration
	config := &ProxyConfig{
		LocalAddr:  "127.0.0.1:0", // Let system choose port
		RemoteAddr: serverAddr,
		UseTLS:     false,
		Timeout:    5 * time.Second,
	}

	// Create and start proxy
	proxy := NewProxy(config)
	if err := proxy.Start(); err != nil {
		t.Fatalf("Failed to start proxy: %v", err)
	}
	defer proxy.Stop()

	// Get proxy address
	proxyAddr := proxy.listener.Addr().String()

	// Test connection through proxy
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("Failed to connect to proxy: %v", err)
	}
	defer conn.Close()

	// Send test data
	testData := []byte("Hello, Proxy!")
	_, err = conn.Write(testData)
	if err != nil {
		t.Fatalf("Failed to write to proxy: %v", err)
	}

	// Read response
	response := make([]byte, len(testData))
	_, err = conn.Read(response)
	if err != nil {
		t.Fatalf("Failed to read from proxy: %v", err)
	}

	// Verify echo
	if string(response) != string(testData) {
		t.Errorf("Expected echo response, got: %s", string(response))
	}
}

func TestProxyTLS(t *testing.T) {
	// Generate test certificate
	tlsConfig, err := generateTestCert()
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	// Start test server with TLS
	server, err := startTestServer("127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatalf("Failed to start test server: %v", err)
	}
	defer server.Close()

	serverAddr := server.Addr().String()

	// Create proxy configuration with TLS
	config := &ProxyConfig{
		LocalAddr:  "127.0.0.1:0",
		RemoteAddr: serverAddr,
		UseTLS:     true,
		TLSConfig:  &tls.Config{InsecureSkipVerify: true},
		Timeout:    5 * time.Second,
	}

	// Create and start proxy
	proxy := NewProxy(config)
	if err := proxy.Start(); err != nil {
		t.Fatalf("Failed to start proxy: %v", err)
	}
	defer proxy.Stop()

	// Test connection through proxy
	conn, err := net.Dial("tcp", proxy.listener.Addr().String())
	if err != nil {
		t.Fatalf("Failed to connect to proxy: %v", err)
	}
	defer conn.Close()

	// Send test data
	testData := []byte("Hello, TLS Proxy!")
	_, err = conn.Write(testData)
	if err != nil {
		t.Fatalf("Failed to write to proxy: %v", err)
	}

	// Read response
	response := make([]byte, len(testData))
	_, err = conn.Read(response)
	if err != nil {
		t.Fatalf("Failed to read from proxy: %v", err)
	}

	// Verify echo
	if string(response) != string(testData) {
		t.Errorf("Expected echo response, got: %s", string(response))
	}
}

func TestProxyGracefulShutdown(t *testing.T) {
	// Start test server
	server, err := startTestServer("127.0.0.1:0", nil)
	if err != nil {
		t.Fatalf("Failed to start test server: %v", err)
	}
	defer server.Close()

	// Create proxy configuration
	config := &ProxyConfig{
		LocalAddr:  "127.0.0.1:0",
		RemoteAddr: server.Addr().String(),
		UseTLS:     false,
		Timeout:    5 * time.Second,
	}

	// Create and start proxy
	proxy := NewProxy(config)
	if err := proxy.Start(); err != nil {
		t.Fatalf("Failed to start proxy: %v", err)
	}

	// Start a connection
	conn, err := net.Dial("tcp", proxy.listener.Addr().String())
	if err != nil {
		t.Fatalf("Failed to connect to proxy: %v", err)
	}

	// Stop proxy while connection is active
	proxy.Stop()

	// Connection should be closed
	_, err = conn.Write([]byte("test"))
	if err == nil {
		t.Error("Expected connection to be closed after proxy shutdown")
	}
}

func TestCreateTLSConfig(t *testing.T) {
	// Test with invalid files
	_, err := CreateTLSConfig("nonexistent.pem", "nonexistent.pem", false)
	if err == nil {
		t.Error("Expected error for nonexistent certificate files")
	}

	// Test with empty files
	_, err = CreateTLSConfig("", "", false)
	if err == nil {
		t.Error("Expected error for empty certificate files")
	}
}

func TestCreateClientTLSConfig(t *testing.T) {
	config := CreateClientTLSConfig(true)
	if config == nil {
		t.Error("Expected non-nil TLS config")
	}
	if !config.InsecureSkipVerify {
		t.Error("Expected InsecureSkipVerify to be true")
	}
}
