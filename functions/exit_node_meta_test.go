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

func TestMeasurePublicLatencyEmpty(t *testing.T) {
	assert.Equal(t, int64(0), measurePublicLatency(nil))
	assert.Equal(t, int64(0), measurePublicLatency([]string{"127.0.0.1"}))
}

func TestMarkNearestExitNodesByLatency(t *testing.T) {
	nodes := []models.DeviceExitNode{
		{EgressID: "far", LatencyMs: 80},
		{EgressID: "near", LatencyMs: 12},
		{EgressID: "dead", LatencyMs: 999},
	}
	markNearestExitNodes(nodes, "")
	assert.False(t, nodes[0].Nearest)
	assert.True(t, nodes[1].Nearest)
	assert.False(t, nodes[2].Nearest)
}

func TestMarkNearestExitNodesByGeo(t *testing.T) {
	nodes := []models.DeviceExitNode{
		{EgressID: "us", Location: "40.7,-74.0"},
		{EgressID: "sg", Location: "1.3,103.8"},
	}
	markNearestExitNodes(nodes, "1.35,103.85")
	assert.False(t, nodes[0].Nearest)
	assert.True(t, nodes[1].Nearest)
}
