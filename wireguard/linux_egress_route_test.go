//go:build linux

package wireguard

import (
	"net"
	"testing"

	"github.com/gravitl/netmaker/models"
	"github.com/gravitl/netmaker/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLinuxEgressRouteParams_singleNetOnLink(t *testing.T) {
	_, ipnet, err := net.ParseCIDR("10.120.0.0/20")
	require.NoError(t, err)
	src, gw, metric, ok := linuxEgressRouteParams(ifaceAddress{
		Network: *ipnet,
		Metric:  0,
	}, false)
	require.True(t, ok)
	assert.Nil(t, src, "single-net has no Src")
	assert.Nil(t, gw, "single-net has no Gw")
	assert.Equal(t, EgressRouteMetric, metric)
}

func TestLinuxEgressRouteParams_multiNetSrcAndGw(t *testing.T) {
	_, ipnet, err := net.ParseCIDR("10.120.0.0/20")
	require.NoError(t, err)
	gw := net.ParseIP("100.76.188.1")
	node := net.ParseIP("100.76.188.3")
	src, gotGw, metric, ok := linuxEgressRouteParams(ifaceAddress{
		Network: *ipnet,
		IP:      node,
		GwIP:    gw,
		Metric:  100,
	}, true)
	require.True(t, ok)
	assert.True(t, src.Equal(node))
	assert.True(t, gotGw.Equal(gw))
	assert.Equal(t, 100, metric)
}

func TestLinuxEgressRouteParams_multiNetSkipsIncomplete(t *testing.T) {
	_, ipnet, err := net.ParseCIDR("10.120.0.0/20")
	require.NoError(t, err)
	_, _, _, ok := linuxEgressRouteParams(ifaceAddress{
		Network: *ipnet,
		Metric:  256,
	}, true)
	assert.False(t, ok, "multi-net without Src/Gw must skip")
}

func TestBuildEgressIfaceAddresses_singleVsMulti(t *testing.T) {
	gw := net.ParseIP("100.76.188.1")
	node := net.ParseIP("100.76.188.3")
	routes := []models.EgressNetworkRoutes{{
		PeerKey:       "peer",
		Network:       "net-a",
		EgressGwAddr:  net.IPNet{IP: gw, Mask: net.CIDRMask(32, 32)},
		NodeAddr:      net.IPNet{IP: node, Mask: net.CIDRMask(16, 32)},
		EgressRangesWithMetric: []models.EgressRangeMetric{{
			Network:     "10.120.0.0/20",
			RouteMetric: 256,
		}},
	}}

	single := buildEgressIfaceAddresses(routes, 1)
	require.Len(t, single, 1)
	assert.Nil(t, single[0].IP)
	assert.Nil(t, single[0].GwIP)
	assert.Equal(t, "10.120.0.0/20", single[0].Network.String())

	multi := buildEgressIfaceAddresses(routes, 2)
	require.Len(t, multi, 1)
	assert.True(t, multi[0].IP.Equal(node))
	assert.True(t, multi[0].GwIP.Equal(gw))
	assert.Equal(t, "10.120.0.0/20", multi[0].Network.String())
}

func TestBuildEgressIfaceAddresses_virtualNAT(t *testing.T) {
	gw := net.ParseIP("100.76.188.1")
	node := net.ParseIP("100.76.188.3")
	routes := []models.EgressNetworkRoutes{{
		EgressGwAddr: net.IPNet{IP: gw, Mask: net.CIDRMask(32, 32)},
		NodeAddr:     net.IPNet{IP: node, Mask: net.CIDRMask(16, 32)},
		EgressRangesWithMetric: []models.EgressRangeMetric{{
			Network:        "10.0.0.0/8",
			VirtualNetwork: "100.64.0.0/16",
			Nat:            true,
			Mode:           schema.VirtualNAT,
			RouteMetric:    256,
		}},
	}}
	addrs := buildEgressIfaceAddresses(routes, 2)
	require.Len(t, addrs, 1)
	assert.Equal(t, "100.64.0.0/16", addrs[0].Network.String())
}
