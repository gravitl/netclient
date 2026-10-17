package wireguard

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestPreserveLearnedEndpoint_keepsLiveWhenServerOmits(t *testing.T) {
	key := wgtypes.Key{}
	copy(key[:], []byte("0123456789abcdef0123456789abcdef"))
	liveEP := &net.UDPAddr{IP: net.ParseIP("203.0.113.50"), Port: 51821}
	peer := wgtypes.PeerConfig{PublicKey: key, Endpoint: nil}
	live := map[string]wgtypes.Peer{
		key.String(): {PublicKey: key, Endpoint: liveEP},
	}

	preserveLearnedEndpoint(&peer, live)

	require.NotNil(t, peer.Endpoint)
	assert.Equal(t, "203.0.113.50", peer.Endpoint.IP.String())
	assert.Equal(t, 51821, peer.Endpoint.Port)
}

func TestPreserveLearnedEndpoint_respectsServerEndpoint(t *testing.T) {
	key := wgtypes.Key{}
	copy(key[:], []byte("0123456789abcdef0123456789abcdef"))
	serverEP := &net.UDPAddr{IP: net.ParseIP("198.51.100.10"), Port: 51820}
	liveEP := &net.UDPAddr{IP: net.ParseIP("203.0.113.50"), Port: 51821}
	peer := wgtypes.PeerConfig{PublicKey: key, Endpoint: serverEP}
	live := map[string]wgtypes.Peer{
		key.String(): {PublicKey: key, Endpoint: liveEP},
	}

	preserveLearnedEndpoint(&peer, live)

	require.NotNil(t, peer.Endpoint)
	assert.Equal(t, "198.51.100.10", peer.Endpoint.IP.String())
}

func TestPreserveLearnedEndpoint_clearsUnspecifiedServerEndpoint(t *testing.T) {
	key := wgtypes.Key{}
	copy(key[:], []byte("fedcba9876543210fedcba9876543210"))
	peer := wgtypes.PeerConfig{
		PublicKey: key,
		Endpoint:  &net.UDPAddr{IP: net.IPv4zero, Port: 51820},
	}
	// Treat unspecified as omitted before preserve; helper should still restore live.
	if peer.Endpoint != nil && (peer.Endpoint.IP == nil || peer.Endpoint.IP.IsUnspecified()) {
		peer.Endpoint = nil
	}
	liveEP := &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 40000}
	live := map[string]wgtypes.Peer{
		key.String(): {PublicKey: key, Endpoint: liveEP},
	}
	preserveLearnedEndpoint(&peer, live)
	require.NotNil(t, peer.Endpoint)
	assert.Equal(t, "203.0.113.9", peer.Endpoint.IP.String())
}

func TestHasExplicitEndpoint(t *testing.T) {
	assert.False(t, hasExplicitEndpoint(nil))
	assert.False(t, hasExplicitEndpoint(&net.UDPAddr{Port: 1}))
	assert.False(t, hasExplicitEndpoint(&net.UDPAddr{IP: net.IPv4zero, Port: 1}))
	assert.True(t, hasExplicitEndpoint(&net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 1}))
}
