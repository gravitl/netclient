//go:build windows

package wireguard

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWindowsEgressRouteAddrs_singleNetOnLink(t *testing.T) {
	_, ipnet, err := net.ParseCIDR("10.120.0.0/20")
	require.NoError(t, err)
	dest, nextHop, ok := windowsEgressRouteAddrs(ifaceAddress{Network: *ipnet, Metric: 256}, false)
	require.True(t, ok)
	assert.Equal(t, netip.MustParsePrefix("10.120.0.0/20"), dest)
	assert.True(t, nextHop.IsUnspecified(), "single-net must be on-link")
}

func TestWindowsEgressRouteAddrs_multiNetViaGw(t *testing.T) {
	_, ipnet, err := net.ParseCIDR("10.120.0.0/20")
	require.NoError(t, err)
	gw := net.ParseIP("100.76.188.1")
	node := net.ParseIP("100.76.188.3")
	dest, nextHop, ok := windowsEgressRouteAddrs(ifaceAddress{
		Network: *ipnet,
		GwIP:    gw,
		IP:      node,
		Metric:  256,
	}, true)
	require.True(t, ok)
	assert.Equal(t, netip.MustParsePrefix("10.120.0.0/20"), dest)
	assert.Equal(t, netip.MustParseAddr("100.76.188.1"), nextHop)
}
