//go:build linux

package wireguard

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"
)

func TestIsIGWProtectedLinuxRoute(t *testing.T) {
	_, half, err := net.ParseCIDR(ipv6HalfDefaultLow)
	assert.NoError(t, err)
	_, overlay, err := net.ParseCIDR("100.64.0.0/24")
	assert.NoError(t, err)

	assert.True(t, isIGWProtectedLinuxRoute(netlink.Route{Table: RouteTableName, Dst: overlay}),
		"table 111 egress/default must survive ApplyAddrs")
	assert.True(t, isIGWProtectedLinuxRoute(netlink.Route{Dst: half}),
		"IPv6 leak half-default must survive ApplyAddrs")
	assert.False(t, isIGWProtectedLinuxRoute(netlink.Route{Dst: overlay}),
		"main-table overlay routes are wiped and reapplied")
}
