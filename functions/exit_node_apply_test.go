package functions

import (
	"net"
	"testing"

	"github.com/gravitl/netmaker/models"
	"github.com/stretchr/testify/assert"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestHostPullReflectsExitNodeChange(t *testing.T) {
	gwA := net.ParseIP("100.64.0.1")
	gwB := net.ParseIP("100.64.0.2")

	t.Run("clear waits until change_default_gw is false", func(t *testing.T) {
		stale := models.HostPull{ChangeDefaultGw: true, DefaultGwIp: gwA}
		assert.False(t, hostPullReflectsExitNodeChange(stale, false, gwA, nil))
		fresh := models.HostPull{ChangeDefaultGw: false}
		assert.True(t, hostPullReflectsExitNodeChange(fresh, false, gwA, nil))
	})

	t.Run("select from none needs a gateway ip", func(t *testing.T) {
		stale := models.HostPull{ChangeDefaultGw: false}
		assert.False(t, hostPullReflectsExitNodeChange(stale, true, nil, nil))
		missingIP := models.HostPull{ChangeDefaultGw: true}
		assert.False(t, hostPullReflectsExitNodeChange(missingIP, true, nil, nil))
		fresh := models.HostPull{ChangeDefaultGw: true, DefaultGwIp: gwA}
		assert.True(t, hostPullReflectsExitNodeChange(fresh, true, nil, nil))
	})

	t.Run("switch A to B treats same nexthop as stale", func(t *testing.T) {
		stale := models.HostPull{ChangeDefaultGw: true, DefaultGwIp: gwA}
		assert.False(t, hostPullReflectsExitNodeChange(stale, true, gwA, nil))
		fresh := models.HostPull{ChangeDefaultGw: true, DefaultGwIp: gwB}
		assert.True(t, hostPullReflectsExitNodeChange(fresh, true, gwA, nil))
	})
}

func TestHostPullReadyForReconnect(t *testing.T) {
	_, defaultNet, err := net.ParseCIDR("0.0.0.0/0")
	assert.NoError(t, err)
	connected := models.HostPull{
		Nodes: []models.Node{{
			CommonNode: models.CommonNode{Network: "net1", Connected: true},
		}},
	}
	disconnected := models.HostPull{
		Nodes: []models.Node{{
			CommonNode: models.CommonNode{Network: "net1", Connected: false},
		}},
	}
	withIGW := models.HostPull{
		ChangeDefaultGw: true,
		DefaultGwIp:     net.ParseIP("100.64.0.1"),
		Peers: []wgtypes.PeerConfig{{
			AllowedIPs: []net.IPNet{*defaultNet},
		}},
		Nodes: []models.Node{{
			CommonNode: models.CommonNode{Network: "net1", Connected: true},
		}},
	}

	assert.False(t, hostPullReadyForReconnect(disconnected, []string{"net1"}, false))
	assert.True(t, hostPullReadyForReconnect(connected, []string{"net1"}, false))
	assert.False(t, hostPullReadyForReconnect(connected, []string{"net1"}, true))
	assert.True(t, hostPullReadyForReconnect(withIGW, []string{"net1"}, true))
}

func TestWaitForReconnectHostPullReturnsWhenIGWReady(t *testing.T) {
	_, defaultNet, err := net.ParseCIDR("0.0.0.0/0")
	assert.NoError(t, err)
	n := 0
	orig := pullForReconnect
	pullForReconnect = func(bool, bool) (models.HostPull, bool, bool, error) {
		n++
		if n < 3 {
			return models.HostPull{
				Nodes: []models.Node{{
					CommonNode: models.CommonNode{Network: "net1", Connected: true},
				}},
			}, false, false, nil
		}
		return models.HostPull{
			ChangeDefaultGw: true,
			DefaultGwIp:     net.ParseIP("100.64.0.1"),
			Peers: []wgtypes.PeerConfig{{
				AllowedIPs: []net.IPNet{*defaultNet},
			}},
			Nodes: []models.Node{{
				CommonNode: models.CommonNode{Network: "net1", Connected: true},
			}},
		}, false, false, nil
	}
	t.Cleanup(func() { pullForReconnect = orig })

	pull, err := waitForReconnectHostPull([]string{"net1"}, true)
	assert.NoError(t, err)
	assert.True(t, pull.ChangeDefaultGw)
	assert.Equal(t, 3, n)
}
