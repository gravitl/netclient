package wireguard

import (
	"net"
	"testing"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIgwSourceIPPrefersExitNetworkAddress(t *testing.T) {
	_, netA, err := net.ParseCIDR("100.121.42.0/24")
	require.NoError(t, err)
	_, netB, err := net.ParseCIDR("100.95.7.0/24")
	require.NoError(t, err)
	addrA := *netA
	addrA.IP = net.ParseIP("100.121.42.7")
	addrB := *netB
	addrB.IP = net.ParseIP("100.95.7.6")

	config.SetNodes([]models.Node{
		{CommonNode: models.CommonNode{
			Network:      "netmaker",
			Connected:    true,
			NetworkRange: *netA,
			Address:      addrA,
		}},
		{CommonNode: models.CommonNode{
			Network:      "test",
			Connected:    true,
			NetworkRange: *netB,
			Address:      addrB,
		}},
	})
	t.Cleanup(config.DeleteNodes)

	gw := net.ParseIP("100.121.42.1")
	src := igwSourceIP(gw)
	require.NotNil(t, src)
	assert.Equal(t, "100.121.42.7", src.String(),
		"exit on netmaker must not use the second network's address as src")
}
