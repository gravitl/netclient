package functions

import (
	"testing"

	"github.com/gravitl/netmaker/models"
	"github.com/stretchr/testify/assert"
)

func TestPublicProbeHost(t *testing.T) {
	assert.Equal(t, "", publicProbeHost(""))
	assert.Equal(t, "", publicProbeHost("<nil>"))
	assert.Equal(t, "", publicProbeHost("127.0.0.1"))
	assert.Equal(t, "", publicProbeHost("::1"))
	assert.Equal(t, "", publicProbeHost("0.0.0.0"))
	assert.Equal(t, "203.0.113.10", publicProbeHost("203.0.113.10"))
	assert.Equal(t, "203.0.113.10", publicProbeHost("203.0.113.10:51821"))
	assert.Equal(t, "2001:db8::1", publicProbeHost("[2001:db8::1]:443"))
}

func TestPublicProbeHostsDedupes(t *testing.T) {
	assert.Equal(t, []string{"203.0.113.10", "2001:db8::1"}, publicProbeHosts([]string{
		"203.0.113.10",
		"203.0.113.10:51821",
		"127.0.0.1",
		"2001:db8::1",
	}))
}

func TestMeasurePublicLatencyNoHosts(t *testing.T) {
	// No public endpoints → no probe; does not hit the network.
	assert.Equal(t, exitNodeLatencyNone, measurePublicLatency(nil))
	assert.Equal(t, exitNodeLatencyNone, measurePublicLatency([]string{"127.0.0.1", "0.0.0.0"}))
}

func TestExitNodeEndpointIPs(t *testing.T) {
	got := exitNodeEndpointIPs([]models.DeviceExitNode{
		{AllowedEndpoints: []string{"203.0.113.10", "203.0.113.10:51821", "127.0.0.1"}},
		{AllowedEndpoints: []string{"2001:db8::1"}},
	})
	assert.Equal(t, []string{"203.0.113.10", "2001:db8::1"}, func() []string {
		out := make([]string, len(got))
		for i := range got {
			out[i] = got[i].String()
		}
		return out
	}())
}

func TestExitNodeOverlayProbeAddr(t *testing.T) {
	assert.Equal(t, "", exitNodeOverlayProbeAddr(models.DeviceExitNode{}))
	assert.Equal(t, "", exitNodeOverlayProbeAddr(models.DeviceExitNode{Address: "127.0.0.1"}))
	assert.Equal(t, "10.101.0.5", exitNodeOverlayProbeAddr(models.DeviceExitNode{
		Address:  "10.101.0.5",
		Address6: "fd00::5",
	}))
	assert.Equal(t, "fd00::5", exitNodeOverlayProbeAddr(models.DeviceExitNode{
		Address6: "fd00::5",
	}))
}

func TestMarkNearestExitNodesByLatency(t *testing.T) {
	nodes := []models.DeviceExitNode{
		{EgressID: "far", Status: true, LatencyMs: 80},
		{EgressID: "near", Status: true, LatencyMs: 12},
		{EgressID: "dead", Status: false, LatencyMs: 999},
	}
	markNearestExitNodes(nodes, "")
	assert.False(t, nodes[0].Nearest)
	assert.True(t, nodes[1].Nearest)
	assert.False(t, nodes[2].Nearest)
}

func TestMarkNearestExitNodesSkipsDown(t *testing.T) {
	nodes := []models.DeviceExitNode{
		{EgressID: "down-fast", Status: false, LatencyMs: 1},
		{EgressID: "up-slow", Status: true, LatencyMs: 80},
	}
	markNearestExitNodes(nodes, "")
	assert.False(t, nodes[0].Nearest)
	assert.True(t, nodes[1].Nearest)
}

func TestMarkNearestExitNodesByGeo(t *testing.T) {
	nodes := []models.DeviceExitNode{
		{EgressID: "us", Status: true, Location: "40.7,-74.0"},
		{EgressID: "sg", Status: true, Location: "1.3,103.8"},
	}
	markNearestExitNodes(nodes, "1.35,103.85")
	assert.False(t, nodes[0].Nearest)
	assert.True(t, nodes[1].Nearest)
}

func TestPickNearestAvailableExitNode(t *testing.T) {
	_, ok := pickNearestAvailableExitNode(nil, nil)
	assert.False(t, ok)

	pick, ok := pickNearestAvailableExitNode([]models.DeviceExitNode{
		{EgressID: "down-near", Status: false, Nearest: true, LatencyMs: 5},
		{EgressID: "up-far", Status: true, LatencyMs: 80},
		{EgressID: "up-near", Status: true, Nearest: false, LatencyMs: 12},
	}, nil)
	assert.True(t, ok)
	assert.Equal(t, "up-near", pick.EgressID, "prefer lowest-latency up node when Nearest is down")

	pick, ok = pickNearestAvailableExitNode([]models.DeviceExitNode{
		{EgressID: "up-far", Status: true, Nearest: true, LatencyMs: 80},
		{EgressID: "up-near", Status: true, Nearest: false, LatencyMs: 12},
	}, nil)
	assert.True(t, ok)
	assert.Equal(t, "up-near", pick.EgressID, "lowest latency beats stale Nearest flag")

	pick, ok = pickNearestAvailableExitNode([]models.DeviceExitNode{
		{EgressID: "up-far", Status: true, LatencyMs: 80},
		{EgressID: "up-nearest", Status: true, Nearest: true, LatencyMs: 12},
	}, nil)
	assert.True(t, ok)
	assert.Equal(t, "up-nearest", pick.EgressID)

	_, ok = pickNearestAvailableExitNode([]models.DeviceExitNode{
		{EgressID: "only-down", Status: false, Nearest: true},
	}, nil)
	assert.False(t, ok, "never pick Status=false")

	pick, ok = pickNearestAvailableExitNode([]models.DeviceExitNode{
		{EgressID: "failed", Status: true, Nearest: true, LatencyMs: 5},
		{EgressID: "next", Status: true, LatencyMs: 20},
	}, map[string]struct{}{"failed": {}})
	assert.True(t, ok)
	assert.Equal(t, "next", pick.EgressID, "skip excluded failed exit")

	_, ok = pickNearestAvailableExitNode([]models.DeviceExitNode{
		{EgressID: "only", Status: true, Nearest: true},
	}, map[string]struct{}{"only": {}})
	assert.False(t, ok, "all excluded → no pick")
}
