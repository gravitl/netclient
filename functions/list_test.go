package functions

import (
	"testing"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSyncNodesFromServerListSkipsEmptyWhenLocalExists(t *testing.T) {
	t.Cleanup(config.DeleteNodes)
	config.DeleteNodes()
	config.UpdateNodeMap("net1", config.Node{
		CommonNode: models.CommonNode{Network: "net1", Connected: true},
	})
	require.Len(t, config.GetNodes(), 1)

	syncNodesFromServerList(nil)
	assert.Len(t, config.GetNodes(), 1, "empty server list must not wipe local nodes")

	syncNodesFromServerList([]models.Node{})
	assert.Len(t, config.GetNodes(), 1, "empty slice must not wipe local nodes")
}

func TestSyncNodesFromServerListAppliesNonEmpty(t *testing.T) {
	t.Cleanup(config.DeleteNodes)
	config.DeleteNodes()
	config.UpdateNodeMap("old", config.Node{
		CommonNode: models.CommonNode{Network: "old", Connected: false},
	})

	syncNodesFromServerList([]models.Node{{
		CommonNode: models.CommonNode{Network: "new", Connected: false},
	}})
	nodes := config.GetNodes()
	require.Len(t, nodes, 1)
	_, hasOld := nodes["old"]
	_, hasNew := nodes["new"]
	assert.False(t, hasOld)
	assert.True(t, hasNew)
}
