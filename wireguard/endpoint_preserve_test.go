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

func TestPeersConfigAsDiff(t *testing.T) {
	a, b, c := wgtypes.Key{}, wgtypes.Key{}, wgtypes.Key{}
	copy(a[:], []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
	copy(b[:], []byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"))
	copy(c[:], []byte("cccccccccccccccccccccccccccccccc"))
	ep := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 51821}
	desired := []wgtypes.PeerConfig{{PublicKey: b, Endpoint: ep}, {PublicKey: c, Endpoint: ep}}
	device := map[string]wgtypes.Peer{a.String(): {PublicKey: a}, b.String(): {PublicKey: b}}

	tests := []struct {
		name        string
		replace     bool
		device      map[string]wgtypes.Peer
		peers       []wgtypes.PeerConfig
		wantRemove  []wgtypes.Key
		wantKeep    []wgtypes.Key
		wantReplace bool
		wantAllow   bool
		wantNil     bool
	}{
		{"replace removes absent device peers", true, device, desired, []wgtypes.Key{a}, []wgtypes.Key{b, c}, false, true, false},
		{"replace on empty device removes nothing", true, map[string]wgtypes.Peer{}, desired, nil, []wgtypes.Key{b, c}, false, true, false},
		{"replace with empty list removes every device peer", true, device, nil, []wgtypes.Key{a, b}, nil, false, false, false},
		{"listed remove peer is not removed twice", true, device, []wgtypes.PeerConfig{{PublicKey: a, Remove: true}, {PublicKey: b}}, []wgtypes.Key{a}, []wgtypes.Key{b}, false, true, false},
		{"unreadable device keeps the replace", true, nil, desired, nil, []wgtypes.Key{b, c}, true, false, false},
		{"unreadable device without replace passes through", false, nil, desired, nil, []wgtypes.Key{b, c}, false, false, false},
		{"no replace adds no removals", false, device, desired, nil, []wgtypes.Key{b, c}, false, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := wgtypes.Config{ReplacePeers: tt.replace, Peers: tt.peers}
			out := peersConfigAsDiff(in, tt.device)
			assert.Equal(t, tt.wantReplace, out.ReplacePeers)
			var removed, kept []wgtypes.Key
			for _, p := range out.Peers {
				if p.Remove {
					removed = append(removed, p.PublicKey)
					continue
				}
				kept = append(kept, p.PublicKey)
				assert.Equal(t, tt.wantAllow, p.ReplaceAllowedIPs, "ReplaceAllowedIPs of %s", p.PublicKey)
			}
			assert.Equal(t, tt.wantRemove, removed)
			assert.Equal(t, tt.wantKeep, kept)
			assert.Equal(t, tt.wantNil, out.Peers == nil)
			assert.Equal(t, tt.replace, in.ReplacePeers, "input config was modified")
			assert.False(t, desired[0].ReplaceAllowedIPs, "input peers were modified")
		})
	}
}
