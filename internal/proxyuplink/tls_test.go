package proxyuplink

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"
)

func TestCertFingerprintStableAcrossLoads(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, tcpUplinkCertFile)
	keyPath := filepath.Join(dir, tcpUplinkKeyFile)

	certPEM, keyPEM, err := generateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	c1, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	fp1, err := certFingerprint(&c1)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	fp2, err := certFingerprint(&c2)
	if err != nil {
		t.Fatal(err)
	}
	if fp1 == "" || fp1 != fp2 {
		t.Fatalf("fingerprint changed across loads: %q vs %q", fp1, fp2)
	}
}

func TestParseTLSModeDefault(t *testing.T) {
	m, err := ParseTLSMode("")
	if err != nil {
		t.Fatal(err)
	}
	if string(m) != "selfsigned" {
		t.Fatalf("got %s", m)
	}
	_, err = ParseTLSMode("acme")
	if err == nil {
		t.Fatal("expected error")
	}
}
