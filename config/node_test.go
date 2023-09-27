package config

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/exp/slices"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestGetNodePersistentKeepAlive(t *testing.T) {
	t.Run("happy path v4", func(t *testing.T) {
		// define test actual and expected result
		expected := 42 * time.Second

		// setup dummies
		ipV4, _, err := net.ParseCIDR("123.123.123.123/24")
		assert.NoError(t, err)
		node := Node{}
		node.Address.IP = ipV4

		// setup mock that send correct data when correct input is given
		getPeerConfig := func(ip net.IP) (wgtypes.PeerConfig, error) {
			if slices.Equal(ip, ipV4) {
				return wgtypes.PeerConfig{PersistentKeepaliveInterval: &expected}, nil
			}
			return wgtypes.PeerConfig{}, errors.New("no matching ip")
		}

		// run test
		assert.Equal(t, expected, GetNodePersistentKeepAlive(&node, getPeerConfig))
	})

	t.Run("happy path v6", func(t *testing.T) {
		// define test actual and expected result
		expected := 42 * time.Second

		// setup dummies
		ipV6, _, err := net.ParseCIDR("2345:425:2CA1:0000:0000:567:5673:23b5/64")
		assert.NoError(t, err)
		node := Node{}
		node.Address.IP = ipV6

		// setup mock that send correct data when correct input is given
		getPeerConfig := func(ip net.IP) (wgtypes.PeerConfig, error) {
			if slices.Equal(ip, ipV6) {
				return wgtypes.PeerConfig{PersistentKeepaliveInterval: &expected}, nil
			}
			return wgtypes.PeerConfig{}, errors.New("no matching ip")
		}

		// run test
		assert.Equal(t, expected, GetNodePersistentKeepAlive(&node, getPeerConfig))
	})
}
