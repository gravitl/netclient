package functions

import (
	"net"
	"testing"

	"github.com/gravitl/netmaker/models"
	"github.com/stretchr/testify/assert"
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
