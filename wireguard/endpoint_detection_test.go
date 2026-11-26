package wireguard

import (
	"net"
	"testing"

	"github.com/gravitl/netclient/cache"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/models"
	"github.com/gravitl/netmaker/schema"
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

func clearEndpointDetectionState() {
	clearEndpointCache()
	cache.SkipEndpointCache.Range(func(k, _ any) bool {
		cache.SkipEndpointCache.Delete(k)
		return true
	})
	lastPeerHostInfo = nil
}

func testIface(t *testing.T, name, cidr string) schema.Iface {
	t.Helper()
	ip, ipnet, err := net.ParseCIDR(cidr)
	require.NoError(t, err)
	ipnet.IP = ip
	return schema.Iface{Name: name, Address: *ipnet}
}

func TestDropStaleEndpointCaches(t *testing.T) {
	priv, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	pk := priv.PublicKey()
	otherPriv, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	otherPK := otherPriv.PublicKey()

	eth0 := testIface(t, "eth0", "192.0.2.10/24")
	eth1 := testIface(t, "eth1", "198.51.100.20/24")
	prev := models.HostNetworkInfo{ListenPort: 51821, Interfaces: []schema.Iface{eth0, eth1}}

	cases := []struct {
		name     string
		peers    []wgtypes.PeerConfig
		info     models.HostInfoMap
		wantKept bool
	}{
		{"unchanged state keeps", []wgtypes.PeerConfig{{PublicKey: pk}, {PublicKey: otherPK}}, models.HostInfoMap{pk.String(): prev}, true},
		{"interfaces reordered keep", []wgtypes.PeerConfig{{PublicKey: pk}, {PublicKey: otherPK}}, models.HostInfoMap{pk.String(): {ListenPort: 51821, Interfaces: []schema.Iface{eth1, eth0}}}, true},
		{"listen port change drops", []wgtypes.PeerConfig{{PublicKey: pk}, {PublicKey: otherPK}}, models.HostInfoMap{pk.String(): {ListenPort: 14026, Interfaces: []schema.Iface{eth0, eth1}}}, false},
		{"interfaces change drops", []wgtypes.PeerConfig{{PublicKey: pk}, {PublicKey: otherPK}}, models.HostInfoMap{pk.String(): {ListenPort: 51821, Interfaces: []schema.Iface{eth0}}}, false},
		{"absent from update drops", []wgtypes.PeerConfig{{PublicKey: otherPK}}, models.HostInfoMap{pk.String(): prev}, false},
		{"removed peer drops", []wgtypes.PeerConfig{{PublicKey: pk, Remove: true}, {PublicKey: otherPK}}, models.HostInfoMap{pk.String(): prev}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Cleanup(clearEndpointDetectionState)
			clearEndpointDetectionState()
			ep := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 51821}
			cache.EndpointCache.Store(pk.String(), cache.EndpointCacheValue{Endpoint: ep})
			cache.EndpointCache.Store(otherPK.String(), cache.EndpointCacheValue{Endpoint: ep})
			cache.SkipEndpointCache.Store(pk.String(), 2)
			lastPeerHostInfo = models.HostInfoMap{pk.String(): prev}
			DropStaleEndpointCaches(tc.peers, tc.info)
			_, cachedEP := cache.EndpointCache.Load(pk.String())
			_, cachedSkip := cache.SkipEndpointCache.Load(pk.String())
			_, otherEP := cache.EndpointCache.Load(otherPK.String())
			assert.Equal(t, tc.wantKept, cachedEP, "cached endpoint")
			assert.Equal(t, tc.wantKept, cachedSkip, "skip counter")
			assert.True(t, otherEP, "unchanged peer entry must stay")
		})
	}
}
