package proxyuplink

import (
	"net"
	"os"
	"strings"
)

const (
	// EnvRelayTCPAddr is the relay TCP/TLS listen address (host:port), e.g. "relay.example.com:443".
	// When empty, relay TCP uplink is disabled.
	EnvRelayTCPAddr = "NC_RELAY_TCP_UPLINK_ADDR"
	// EnvRelayTLSServerName sets TLS ServerName (SNI). Defaults to hostname from NC_RELAY_TCP_UPLINK_ADDR.
	EnvRelayTLSServerName = "NC_RELAY_TCP_UPLINK_TLS_SERVER_NAME"
)

// AddrFromEnv returns NC_RELAY_TCP_UPLINK_ADDR if set and non-empty.
func AddrFromEnv() string {
	return strings.TrimSpace(os.Getenv(EnvRelayTCPAddr))
}

// ForceUserspaceWireGuard is true when a TCP relay uplink is configured. Netclient should use
// wireguard-go (userspace) so ciphertext can be routed via conn.Bind to the TCP proxy; kernel
// WireGuard cannot be bridged to the proxy the same way.
func ForceUserspaceWireGuard() bool {
	return AddrFromEnv() != ""
}

// TLSServerNameFromEnv returns SNI for TLS, or the host part of addr if NC_RELAY_TCP_UPLINK_TLS_SERVER_NAME is empty.
func TLSServerNameFromEnv(addr string) string {
	if s := strings.TrimSpace(os.Getenv(EnvRelayTLSServerName)); s != "" {
		return s
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return host
}
