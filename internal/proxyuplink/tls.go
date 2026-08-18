package proxyuplink

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/gravitl/netclient/config"
)

const (
	tcpUplinkCertFile = "tcp_uplink_cert.pem"
	tcpUplinkKeyFile  = "tcp_uplink_key.pem"
)

// LoadOrCreateServerTLS loads a persisted self-signed cert for the TCP uplink listener,
// or creates one under the netclient config directory.
func LoadOrCreateServerTLS() (*tls.Config, error) {
	dir := config.GetNetclientPath()
	certPath := filepath.Join(dir, tcpUplinkCertFile)
	keyPath := filepath.Join(dir, tcpUplinkKeyFile)

	if cert, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		return &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}, nil
	}

	certPEM, keyPEM, err := generateSelfSigned()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// ClientTLSConfig returns a TLS client config for Phase 1 TCP uplink.
// Gateways use a locally generated self-signed cert, so verification is skipped.
func ClientTLSConfig(serverName string) *tls.Config {
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // Phase 1: gateway presents self-signed cert
	}
	if serverName != "" {
		cfg.ServerName = serverName
	}
	return cfg
}

func generateSelfSigned() (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{Organization: []string{"Netmaker"}, CommonName: "netmaker-tcp-uplink"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	return certPEM, keyPEM, nil
}
