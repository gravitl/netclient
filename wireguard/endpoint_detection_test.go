package wireguard

import (
	"net"
	"testing"

	"github.com/gravitl/netclient/cache"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
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

func TestClearEndpointCachesForRemovedPeers(t *testing.T) {
	t.Cleanup(func() {
		clearEndpointCache()
		cache.SkipEndpointCache.Range(func(k, _ any) bool {
			cache.SkipEndpointCache.Delete(k)
			return true
		})
	})
	clearEndpointCache()

	priv, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	keepPriv, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	removedPK := priv.PublicKey()
	keepPK := keepPriv.PublicKey()

	ep := &net.UDPAddr{IP: net.ParseIP("192.168.1.10"), Port: 51821}
	cache.EndpointCache.Store(removedPK.String(), cache.EndpointCacheValue{Endpoint: ep})
	cache.EndpointCache.Store(keepPK.String(), cache.EndpointCacheValue{Endpoint: ep})
	cache.SkipEndpointCache.Store(removedPK.String(), 2)
	cache.SkipEndpointCache.Store(keepPK.String(), 1)

	ClearEndpointCachesForRemovedPeers([]wgtypes.PeerConfig{
		{PublicKey: removedPK, Remove: true},
		{PublicKey: keepPK, Remove: false},
	})

	_, removedEP := cache.EndpointCache.Load(removedPK.String())
	_, keepEP := cache.EndpointCache.Load(keepPK.String())
	_, removedSkip := cache.SkipEndpointCache.Load(removedPK.String())
	_, keepSkip := cache.SkipEndpointCache.Load(keepPK.String())
	assert.False(t, removedEP)
	assert.True(t, keepEP)
	assert.False(t, removedSkip)
	assert.True(t, keepSkip)
}
