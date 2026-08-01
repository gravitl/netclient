//go:build windows
// +build windows

package wireguard

import "errors"

func clientRelayEndpoint() string { return "" }

// SetRelayUDPEndpoint is a no-op on Windows (TCP uplink Bind not supported).
func SetRelayUDPEndpoint(addr string) error { return nil }

// ClearClientRelay is a no-op on Windows.
func ClearClientRelay() {}

// SetTCPPeerRoute is unsupported on Windows.
func SetTCPPeerRoute(peerID, udpEndpoint string) error {
	return errors.New("tcp uplink bind not supported on windows")
}

// ClearTCPPeerRoute is a no-op on Windows.
func ClearTCPPeerRoute(peerID string) {}

// ClearAllTCPPeerRoutes is a no-op on Windows.
func ClearAllTCPPeerRoutes() {}

// TCPPeerEndpoint is unsupported on Windows.
func TCPPeerEndpoint(peerID string) string { return "" }
