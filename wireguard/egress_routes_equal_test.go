package wireguard

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckEgressRoutes_unchanged(t *testing.T) {
	_, n, err := net.ParseCIDR("10.104.0.0/20")
	require.NoError(t, err)
	a := []ifaceAddress{{Network: *n, Metric: 256, IP: net.ParseIP("100.95.7.3"), GwIP: net.ParseIP("100.121.42.5")}}
	b := []ifaceAddress{{Network: *n, Metric: 256, IP: net.ParseIP("100.95.7.3"), GwIP: net.ParseIP("100.121.42.5")}}
	assert.True(t, checkEgressRoutes(a, b))
}

func TestCheckEgressRoutes_gwChange(t *testing.T) {
	_, n, err := net.ParseCIDR("10.104.0.0/20")
	require.NoError(t, err)
	onLink := []ifaceAddress{{Network: *n, Metric: 256}}
	viaGW := []ifaceAddress{{Network: *n, Metric: 256, IP: net.ParseIP("100.95.7.3"), GwIP: net.ParseIP("100.121.42.5")}}
	assert.False(t, checkEgressRoutes(onLink, viaGW), "on-link vs via-GW must not skip replace")
}
