package wireguard

import (
	"net"
	"testing"

	"github.com/gravitl/netclient/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestShouldSkipAllEndpointDetection_currGw(t *testing.T) {
	prev := config.Netclient()
	t.Cleanup(func() {
		if prev != nil {
			config.UpdateNetclient(*prev)
		}
	})

	config.UpdateNetclient(config.Config{})
	assert.False(t, ShouldSkipAllEndpointDetection())

	nc := config.Config{CurrGwNmIP: net.ParseIP("100.64.0.1")}
	config.UpdateNetclient(nc)
	assert.True(t, ShouldSkipAllEndpointDetection())
	assert.True(t, ShouldSkipEndpointDetection("any-key-still-skips-all"))
}

func TestShouldSkipAllEndpointDetection_defaultRoutePeer(t *testing.T) {
	prev := config.Netclient()
	t.Cleanup(func() {
		if prev != nil {
			config.UpdateNetclient(*prev)
		}
	})

	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	_, defNet, err := net.ParseCIDR(IPv4Network)
	require.NoError(t, err)

	config.UpdateNetclient(config.Config{
		HostPeers: []wgtypes.PeerConfig{{
			PublicKey:  key.PublicKey(),
			AllowedIPs: []net.IPNet{*defNet},
		}},
	})
	assert.True(t, ShouldSkipAllEndpointDetection())
	// Non-exit peer pubkey still skipped while any peer has 0.0.0.0/0.
	other, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	assert.True(t, ShouldSkipEndpointDetection(other.PublicKey().String()))
}

func TestShouldSkipEndpointDetection_onlyExitPeerWithoutGlobal(t *testing.T) {
	prev := config.Netclient()
	t.Cleanup(func() {
		if prev != nil {
			config.UpdateNetclient(*prev)
		}
	})

	exitKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	otherKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	_, siteNet, err := net.ParseCIDR("10.0.0.0/16")
	require.NoError(t, err)

	// No CurrGw and no default-route peer → only per-peer egress skip via AllowedIPs
	// is N/A here; without 0.0.0.0/0, neither peer is skipped by exit rules.
	config.UpdateNetclient(config.Config{
		HostPeers: []wgtypes.PeerConfig{
			{PublicKey: exitKey.PublicKey(), AllowedIPs: []net.IPNet{*siteNet}},
			{PublicKey: otherKey.PublicKey(), AllowedIPs: []net.IPNet{*siteNet}},
		},
	})
	assert.False(t, ShouldSkipAllEndpointDetection())
	assert.False(t, ShouldSkipEndpointDetection(otherKey.PublicKey().String()))
}
