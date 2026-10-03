package wireguard

import (
	"net"
	"testing"

	"github.com/gravitl/netclient/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestSetExitNodeUnderlayPinIPs(t *testing.T) {
	t.Cleanup(func() { SetExitNodeUnderlayPinIPs(nil) })

	SetExitNodeUnderlayPinIPs([]net.IP{
		net.ParseIP("203.0.113.10"),
		net.ParseIP("203.0.113.10"), // dedupe
		net.ParseIP("2001:db8::1"),
		net.ParseIP("127.0.0.1"), // skipped
		nil,
	})
	got := exitNodeUnderlayPinIPs()
	require.Len(t, got, 2)
	assert.Equal(t, "203.0.113.10", got[0].String())
	assert.Equal(t, "2001:db8::1", got[1].String())

	SetExitNodeUnderlayPinIPs(nil)
	assert.Empty(t, exitNodeUnderlayPinIPs())
}

func TestNonExitPeerHostIPsIncludesAlternateExit(t *testing.T) {
	selected, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	alternate, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	site, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)

	prev := config.Netclient()
	t.Cleanup(func() {
		if prev != nil {
			config.UpdateNetclient(*prev)
		}
	})

	nc := config.Config{}
	nc.HostPeers = []wgtypes.PeerConfig{
		{
			PublicKey: selected.PublicKey(),
			Endpoint:  &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 51821},
			AllowedIPs: []net.IPNet{
				{IP: net.ParseIP("0.0.0.0"), Mask: net.CIDRMask(0, 32)},
			},
		},
		{
			PublicKey: alternate.PublicKey(),
			Endpoint:  &net.UDPAddr{IP: net.ParseIP("198.51.100.2"), Port: 51821},
			AllowedIPs: []net.IPNet{
				{IP: net.ParseIP("10.0.0.2"), Mask: net.CIDRMask(32, 32)},
			},
		},
		{
			PublicKey: site.PublicKey(),
			Endpoint:  &net.UDPAddr{IP: net.ParseIP("198.51.100.3"), Port: 51821},
			AllowedIPs: []net.IPNet{
				{IP: net.ParseIP("10.20.0.0"), Mask: net.CIDRMask(16, 32)},
			},
		},
	}
	config.UpdateNetclient(nc)

	got := NonExitPeerHostIPs(selected.PublicKey().String())
	gotStr := make([]string, 0, len(got))
	for _, ip := range got {
		gotStr = append(gotStr, ip.String())
	}
	assert.NotContains(t, gotStr, "198.51.100.1", "selected exit underlay is handled separately")
	assert.Contains(t, gotStr, "198.51.100.2", "alternate exit peer underlay must be pinned")
	assert.Contains(t, gotStr, "198.51.100.3", "site-egress peer underlay must be pinned")
}

func TestIGWUnderlayPinIPsIncludesRegisteredExitEndpoints(t *testing.T) {
	t.Cleanup(func() { SetExitNodeUnderlayPinIPs(nil) })
	SetExitNodeUnderlayPinIPs([]net.IP{net.ParseIP("203.0.113.50")})

	selected, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	prev := config.Netclient()
	t.Cleanup(func() {
		if prev != nil {
			config.UpdateNetclient(*prev)
		}
	})
	nc := config.Config{}
	nc.HostPeers = []wgtypes.PeerConfig{
		{
			PublicKey: selected.PublicKey(),
			Endpoint:  &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 51821},
		},
	}
	config.UpdateNetclient(nc)

	got := IGWUnderlayPinIPs(selected.PublicKey().String())
	gotStr := make([]string, 0, len(got))
	for _, ip := range got {
		gotStr = append(gotStr, ip.String())
	}
	assert.Contains(t, gotStr, "198.51.100.1")
	assert.Contains(t, gotStr, "203.0.113.50")
}
