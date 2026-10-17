package functions

import (
	"testing"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeepLocallyConnectedPreservesAfterServerSync(t *testing.T) {
	t.Cleanup(func() {
		config.DeleteNodes()
	})

	config.UpdateNodeMap("netmaker", config.Node{
		CommonNode: models.CommonNode{Network: "netmaker", Connected: true},
	})

	keep := locallyConnectedNetworks()
	assert.Contains(t, keep, "netmaker")

	// Server peer/pull sync still reports disconnected.
	config.SetNodes([]models.Node{{
		CommonNode: models.CommonNode{Network: "netmaker", Connected: false},
	}})
	require.False(t, config.GetNodes()["netmaker"].Connected)

	keepLocallyConnected(keep)
	assert.True(t, config.GetNodes()["netmaker"].Connected,
		"local reconnect must not be wiped by a stale server Connected=false")
}
