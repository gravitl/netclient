package wireguard

import (
	"net"
	"testing"

	"github.com/gravitl/netclient/cache"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func clearEndpointCache() {
	cache.EndpointCache.Range(func(k, _ any) bool {
		cache.EndpointCache.Delete(k)
		return true
	})
}

func TestEndpointDetectionSkipCIDRs_includesEgress(t *testing.T) {
	prev := GetEgressRoutesFromCache()
	t.Cleanup(func() {
		SetEgressRoutesInCache(prev)
		clearEndpointCache()
	})
	clearEndpointCache()

	_, allowed, err := net.ParseCIDR("100.64.0.1/32")
	require.NoError(t, err)
	SetEgressRoutesInCache([]models.EgressNetworkRoutes{{
		EgressRangesWithMetric: []models.EgressRangeMetric{{
			Network:     "10.114.0.0/20",
			RouteMetric: 256,
		}},
	}})

	cidrs := EndpointDetectionSkipCIDRs([]net.IPNet{*allowed})
	assert.True(t, IPCoveredByCIDRs(net.ParseIP("10.114.0.12"), cidrs))
	assert.True(t, IPCoveredByCIDRs(net.ParseIP("100.64.0.1"), cidrs))
	assert.False(t, IPCoveredByCIDRs(net.ParseIP("192.168.1.5"), cidrs))
}

func TestIsMeshRoutedEndpointIP_egressOnly(t *testing.T) {
	prev := GetEgressRoutesFromCache()
	t.Cleanup(func() {
		SetEgressRoutesInCache(prev)
		clearEndpointCache()
	})
	clearEndpointCache()

	SetEgressRoutesInCache([]models.EgressNetworkRoutes{{
		EgressRangesWithMetric: []models.EgressRangeMetric{{
			Network: "10.114.0.0/20",
		}},
	}})
	assert.True(t, IsMeshRoutedEndpointIP(net.ParseIP("10.114.0.9"), nil))
	assert.False(t, IsMeshRoutedEndpointIP(net.ParseIP("10.0.0.1"), nil))
}

func TestDropMeshRoutedEndpointCache_clearsStickyLAN(t *testing.T) {
	prevRoutes := GetEgressRoutesFromCache()
	prevNC := config.Netclient()
	t.Cleanup(func() {
		SetEgressRoutesInCache(prevRoutes)
		if prevNC != nil {
			config.UpdateNetclient(*prevNC)
		}
		clearEndpointCache()
	})
	clearEndpointCache()
	config.UpdateNetclient(config.Config{})

	// Set egress without going through SetEgressRoutesInCache scrub side effects
	// on unrelated cache entries: seed cache after setting routes.
	egressRoutesCacheMutex.Lock()
	egressRoutes = []models.EgressNetworkRoutes{{
		EgressRangesWithMetric: []models.EgressRangeMetric{{
			Network: "10.114.0.0/20",
		}},
	}}
	egressRoutesCacheMutex.Unlock()

	bad := &net.UDPAddr{IP: net.ParseIP("10.114.0.12"), Port: 51821}
	okEP := &net.UDPAddr{IP: net.ParseIP("192.168.1.50"), Port: 51821}
	cache.EndpointCache.Store("bad-peer", cache.EndpointCacheValue{Endpoint: bad})
	cache.EndpointCache.Store("lan-peer", cache.EndpointCacheValue{Endpoint: okEP})

	dropped := DropMeshRoutedEndpointCache(nil)
	assert.Contains(t, dropped, "bad-peer")
	assert.NotContains(t, dropped, "lan-peer")
	_, badStill := cache.EndpointCache.Load("bad-peer")
	assert.False(t, badStill)
	_, lanStill := cache.EndpointCache.Load("lan-peer")
	assert.True(t, lanStill)
}
