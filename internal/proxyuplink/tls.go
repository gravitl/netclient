package proxyuplink

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/proxy/uplink"
)

const (
	tcpUplinkCertFile = "tcp_uplink_cert.pem"
	tcpUplinkKeyFile  = "tcp_uplink_key.pem"
)

// LoadOrCreateServerTLS loads a persisted self-signed cert for the uplink listener,
// or creates one under the netclient config directory. The certificate is not
// regenerated on every process restart.
func LoadOrCreateServerTLS() (*tls.Config, string, error) {
	dir := config.GetNetclientPath()
	certPath := filepath.Join(dir, tcpUplinkCertFile)
	keyPath := filepath.Join(dir, tcpUplinkKeyFile)

	if cert, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		fp, err := certFingerprint(&cert)
		if err != nil {
			return nil, "", err
		}
		return &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}, fp, nil
	}

	certPEM, keyPEM, err := generateSelfSigned()
	if err != nil {
		return nil, "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, "", err
	}
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return nil, "", err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, "", err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, "", err
	}
	fp, err := certFingerprint(&cert)
	if err != nil {
		return nil, "", err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, fp, nil
}

func certFingerprint(cert *tls.Certificate) (string, error) {
	if cert == nil || len(cert.Certificate) == 0 {
		return "", fmt.Errorf("empty certificate")
	}
	sum := sha256.Sum256(cert.Certificate[0])
	return hex.EncodeToString(sum[:]), nil
}

// ClientTLSConfig builds TLS client config for WSS dial.
//
// Trust order:
//  1. If expectedFingerprint (SHA-256 hex of leaf) is set → pin that certificate.
//  2. Else use normal system/RootCAs verification (reverse-proxy / public certs).
//  3. Legacy fallback: if host is an IP literal and no fingerprint is set,
//     InsecureSkipVerify is used (Phase-1 self-signed without published pin).
//     This path is temporary and marked for removal once fingerprints are always published.
func ClientTLSConfig(serverName, expectedFingerprint string) *tls.Config {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if serverName != "" {
		cfg.ServerName = serverName
	}
	fp := strings.ToLower(strings.TrimSpace(expectedFingerprint))
	if fp != "" {
		cfg.InsecureSkipVerify = true //nolint:gosec // VerifyPeerCertificate enforces pin
		cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("no peer certificates")
			}
			sum := sha256.Sum256(rawCerts[0])
			got := hex.EncodeToString(sum[:])
			if !strings.EqualFold(got, fp) {
				return fmt.Errorf("uplink certificate fingerprint mismatch")
			}
			return nil
		}
		return cfg
	}
	host := serverName
	if host == "" {
		return cfg // system verify with empty ServerName will fail for wss; caller should set SNI
	}
	if ip := net.ParseIP(host); ip != nil {
		// Temporary legacy path for self-signed gateways before fingerprint publish.
		cfg.InsecureSkipVerify = true //nolint:gosec // DEPRECATED: remove when fingerprints always published
		return cfg
	}
	// Hostname → normal verification (public / reverse-proxy certificates).
	return cfg
}

// ParseTLSMode maps host config to uplink.TLSMode (default selfsigned).
func ParseTLSMode(s string) (uplink.TLSMode, error) {
	return uplink.ParseTLSMode(s)
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
