//go:build linux

package wireguard

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"
)

func TestIsNetclientOwnedLink(t *testing.T) {
	attrs := &netlink.LinkAttrs{Name: "netmaker", Alias: ""}
	assert.True(t, isNetclientOwnedLink(attrs, "netmaker"))

	attrs = &netlink.LinkAttrs{Name: "wg0", Alias: NetclientIfaceAlias}
	assert.True(t, isNetclientOwnedLink(attrs, "netmaker"))

	attrs = &netlink.LinkAttrs{Name: "wg0", Alias: ""}
	assert.False(t, isNetclientOwnedLink(attrs, "netmaker"))
}

func TestIsWireGuardLink(t *testing.T) {
	link := &netLink{attrs: &netlink.LinkAttrs{Name: "netmaker"}}
	assert.True(t, isWireGuardLink(link))
	assert.False(t, isWireGuardLink(nil))
}
