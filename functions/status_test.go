package functions

import (
	"net"
	"testing"
	"time"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestFormatStatusNetworks(t *testing.T) {
	v4, v6 := net.IPNet{}, net.IPNet{}
	ip4, network4, err := net.ParseCIDR("100.64.0.5/16")
	require.NoError(t, err)
	network4.IP = ip4
	v4 = *network4
	ip6, network6, err := net.ParseCIDR("fd00::5/64")
	require.NoError(t, err)
	network6.IP = ip6
	v6 = *network6

	out := formatStatus(statusView{
		Host:       "laptop",
		Server:     "nm.example.com",
		Iface:      "netmaker",
		IfaceUp:    true,
		ListenPort: 51821,
		PublicKey:  "abc",
		Endpoint:   "203.0.113.5",
		Exit:       "100.64.0.1",
		Networks: []networkStatus{{
			Name:   "office",
			Status: "connected",
			IPv4:   v4.String(),
			IPv6:   v6.String(),
			Server: "nm.example.com",
		}, {
			Name:   "lab",
			Status: "disconnected",
			IPv4:   "-",
			IPv6:   "-",
		}},
	})
	assert.Contains(t, out, "Host: laptop\n")
	assert.Contains(t, out, "Interface: netmaker up\n")
	assert.Contains(t, out, "Exit: 100.64.0.1\n")
	assert.Contains(t, out, "office")
	assert.Contains(t, out, "connected")
	assert.Contains(t, out, "100.64.0.5/16")
	assert.Contains(t, out, "lab")
	assert.Contains(t, out, "disconnected")
}

func TestStatusViewSortsNetworks(t *testing.T) {
	t.Cleanup(config.DeleteNodes)
	config.DeleteNodes()
	config.UpdateNodeMap("zeta", config.Node{CommonNode: models.CommonNode{Network: "zeta", Connected: false}})
	config.UpdateNodeMap("alpha", config.Node{CommonNode: models.CommonNode{Network: "alpha", Connected: true}})

	view := statusViewFromConfig("netmaker", nil)
	require.Len(t, view.Networks, 2)
	assert.Equal(t, "alpha", view.Networks[0].Name)
	assert.Equal(t, "connected", view.Networks[0].Status)
	assert.Equal(t, "zeta", view.Networks[1].Name)
}

func TestFormatWGShow(t *testing.T) {
	priv, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	peerKey, err := wgtypes.GenerateKey()
	require.NoError(t, err)
	psk, err := wgtypes.GenerateKey()
	require.NoError(t, err)
	_, allowed, err := net.ParseCIDR("10.0.0.2/32")
	require.NoError(t, err)
	endpoint, err := net.ResolveUDPAddr("udp", "203.0.113.8:51820")
	require.NoError(t, err)
	now := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)

	out := formatWGShow(&wgtypes.Device{
		Name:         "netmaker",
		PrivateKey:   priv,
		PublicKey:    priv.PublicKey(),
		ListenPort:   51821,
		FirewallMark: 0xca6c,
		Peers: []wgtypes.Peer{{
			PublicKey:                   peerKey,
			PresharedKey:                psk,
			Endpoint:                    endpoint,
			AllowedIPs:                  []net.IPNet{*allowed},
			LastHandshakeTime:           now.Add(-90 * time.Second),
			ReceiveBytes:                1024,
			TransmitBytes:               90,
			PersistentKeepaliveInterval: 25 * time.Second,
		}},
	}, now)

	assert.Equal(t, "interface: netmaker\n"+
		"  public key: "+priv.PublicKey().String()+"\n"+
		"  private key: (hidden)\n"+
		"  listening port: 51821\n"+
		"  fwmark: 0xca6c\n"+
		"\n"+
		"peer: "+peerKey.String()+"\n"+
		"  preshared key: (hidden)\n"+
		"  endpoint: 203.0.113.8:51820\n"+
		"  allowed ips: 10.0.0.2/32\n"+
		"  latest handshake: 1 minute, 30 seconds ago\n"+
		"  transfer: 1.00 KiB received, 90 B sent\n"+
		"  persistent keepalive: every 25 seconds\n", out)
	assert.NotContains(t, out, priv.String())
	assert.NotContains(t, out, psk.String())
}

func TestPrettyDurationAndBytes(t *testing.T) {
	assert.Equal(t, "0 seconds", prettyDuration(0))
	assert.Equal(t, "1 second", prettyDuration(time.Second))
	assert.Equal(t, "2 minutes, 5 seconds", prettyDuration(125*time.Second))
	assert.Equal(t, "0 B", prettyBytes(0))
	assert.Equal(t, "1.50 KiB", prettyBytes(1536))
}
