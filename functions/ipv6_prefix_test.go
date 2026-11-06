package functions

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIPv6SameNetworkPrefix(t *testing.T) {
	a := net.ParseIP("2a00:f29:228:b258:85dd:8498:2c00:55cc")
	b := net.ParseIP("2a00:f29:228:b258:9dd4:2452:2ae5:9e83")
	c := net.ParseIP("2a00:f29:228:b259:9dd4:2452:2ae5:9e83")
	assert.True(t, ipv6SameNetworkPrefix(a, b), "privacy rotation keeps /64")
	assert.False(t, ipv6SameNetworkPrefix(a, c), "different /64 is a network change")
	assert.False(t, ipv6SameNetworkPrefix(a, nil))
	assert.False(t, ipv6SameNetworkPrefix(nil, b))
	assert.False(t, ipv6SameNetworkPrefix(net.ParseIP("1.2.3.4"), b))
}
