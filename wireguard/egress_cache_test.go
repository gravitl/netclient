package wireguard

import (
	"testing"

	"github.com/gravitl/netmaker/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetEgressRoutesFromCache_roundTrip(t *testing.T) {
	prev := GetEgressRoutesFromCache()
	t.Cleanup(func() { SetEgressRoutesInCache(prev) })

	SetEgressRoutesInCache(nil)
	assert.Nil(t, GetEgressRoutesFromCache())

	routes := []models.EgressNetworkRoutes{{
		PeerKey: "peer",
		Network: "net-a",
		EgressRangesWithMetric: []models.EgressRangeMetric{{
			Network:     "10.0.0.0/24",
			RouteMetric: 256,
		}},
	}}
	SetEgressRoutesInCache(routes)
	got := GetEgressRoutesFromCache()
	require.Len(t, got, 1)
	assert.Equal(t, "net-a", got[0].Network)
	assert.Equal(t, "10.0.0.0/24", got[0].EgressRangesWithMetric[0].Network)

	// Mutation of the copy must not affect the cache.
	got[0].Network = "mutated"
	assert.Equal(t, "net-a", GetEgressRoutesFromCache()[0].Network)
}
