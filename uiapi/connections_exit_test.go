package uiapi

import (
	"net"
	"testing"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestActiveExitNetworkNamesOtherConnectedNetwork(t *testing.T) {
	restore := installExitFixture(t)
	defer restore()

	assert.Equal(t, "netmaker", ActiveExitNetwork("poll"))
	assert.Empty(t, ActiveExitNetwork("netmaker"))
}

func TestPrepareConnectAllowsNetworkWhileExitIsActive(t *testing.T) {
	restore := installExitFixture(t)
	defer restore()

	disconnect, err := prepareConnect("poll")
	require.NoError(t, err)
	assert.Empty(t, disconnect)
}

func installExitFixture(t *testing.T) func() {
	t.Helper()
	savedHost := *config.Netclient()
	savedServer := config.CurrServer
	host := savedHost
	host.CurrGwNmIP = net.ParseIP("100.64.0.1")
	config.UpdateNetclient(host)
	config.SetNodes([]models.Node{
		{CommonNode: models.CommonNode{Network: "netmaker", Connected: true}},
		{CommonNode: models.CommonNode{Network: "poll", Connected: false}},
	})
	return func() {
		config.UpdateNetclient(savedHost)
		config.DeleteNodes()
		clearSessionForTest()
		config.CurrServer = savedServer
		SetHandlers(HandlerDeps{})
	}
}
