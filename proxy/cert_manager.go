package proxy

import (
	"crypto/rand"
	"crypto/rsa"
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
)

// CertManager handles automatic certificate generation and management
type CertManager struct {
	certDir string
}

// NewCertManager creates a new certificate manager
func NewCertManager(certDir string) *CertManager {
	if certDir == "" {
		certDir = filepath.Join(os.TempDir(), "netclient-proxy-certs")
	}
	return &CertManager{certDir: certDir}
}

// GenerateSelfSignedCert generates a self-signed certificate for the proxy
func (cm *CertManager) GenerateSelfSignedCert(host string) (*tls.Config, error) {
	// Create cert directory if it doesn't exist
	if err := os.MkdirAll(cm.certDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cert directory: %w", err)
	}

	certFile := filepath.Join(cm.certDir, "proxy.crt")
	keyFile := filepath.Join(cm.certDir, "proxy.key")

	// Check if certificates already exist
	if _, err := os.Stat(certFile); err == nil {
		if _, err := os.Stat(keyFile); err == nil {
			// Certificates exist, load them
			return CreateTLSConfig(certFile, keyFile, false)
		}
	}

	// Generate new certificate
	return cm.createSelfSignedCert(certFile, keyFile, host)
}

// createSelfSignedCert creates a self-signed certificate
func (cm *CertManager) createSelfSignedCert(certFile, keyFile, host string) (*tls.Config, error) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create certificate template
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Netclient Proxy"},
			CommonName:   host,
		},
		NotBefore:             now,
		NotAfter:              now.Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{host, "localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	// Create certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Write certificate to file
	certOut, err := os.Create(certFile)
	if err != nil {
		return nil, fmt.Errorf("failed to create cert file: %w", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return nil, fmt.Errorf("failed to write cert: %w", err)
	}

	// Write private key to file
	keyOut, err := os.Create(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to create key file: %w", err)
	}
	defer keyOut.Close()

	keyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}); err != nil {
		return nil, fmt.Errorf("failed to write key: %w", err)
	}

	// Create TLS config
	return CreateTLSConfig(certFile, keyFile, false)
}

// CreateAutoTLSConfig creates a TLS config with automatically managed certificates
func CreateAutoTLSConfig(host string) (*tls.Config, error) {
	cm := NewCertManager("")
	return cm.GenerateSelfSignedCert(host)
}

// Cleanup removes generated certificates
func (cm *CertManager) Cleanup() error {
	return os.RemoveAll(cm.certDir)
}
