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

func TestActiveExitNetworkUsesDesireAcrossMultiNet(t *testing.T) {
	restore := installMultiNetExitFixture(t)
	defer restore()

	dir := t.TempDir()
	config.SetDesiredConnectionsDirForTest(dir)
	defer config.SetDesiredConnectionsDirForTest("")
	setupTestSession("api.example.com", "u", "tok")
	session.mu.Lock()
	session.tenantID = "t"
	session.mu.Unlock()
	require.NoError(t, config.SetDesiredExitNode("u", "t", "netmaker", "eg-1"))

	assert.Equal(t, "netmaker", ActiveExitNetwork("test"))
	assert.Empty(t, ActiveExitNetwork("netmaker"))
}

func TestActiveExitNetworkAmbiguousWhenMultiNetNoDesire(t *testing.T) {
	restore := installMultiNetExitFixture(t)
	defer restore()

	// Clear→reselect window: desire cleared, host may still have IGW, both nets up.
	// Must not blame the sibling network (that caused false 409 on exit switch).
	assert.Empty(t, ActiveExitNetwork("netmaker"))
	assert.Empty(t, ActiveExitNetwork("test"))
}

func TestShouldDeferAutoExitClaimAllowsOwner(t *testing.T) {
	restore := installMultiNetExitFixture(t)
	defer restore()

	dir := t.TempDir()
	config.SetDesiredConnectionsDirForTest(dir)
	defer config.SetDesiredConnectionsDirForTest("")
	setupTestSession("api.example.com", "u", "tok")
	session.mu.Lock()
	session.tenantID = "t"
	session.mu.Unlock()
	require.NoError(t, config.SetDesiredExitNode("u", "t", "netmaker", "eg-1"))

	assert.False(t, ShouldDeferAutoExitClaim("netmaker"),
		"owner must still arm/select so routing is not skipped after select")
	assert.True(t, ShouldDeferAutoExitClaim("test"),
		"sibling must not steal the owner's exit")
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

func installMultiNetExitFixture(t *testing.T) func() {
	t.Helper()
	savedHost := *config.Netclient()
	savedServer := config.CurrServer
	host := savedHost
	host.CurrGwNmIP = net.ParseIP("100.64.0.1")
	config.UpdateNetclient(host)
	config.SetNodes([]models.Node{
		{CommonNode: models.CommonNode{Network: "netmaker", Connected: true}},
		{CommonNode: models.CommonNode{Network: "test", Connected: true}},
	})
	return func() {
		config.UpdateNetclient(savedHost)
		config.DeleteNodes()
		clearSessionForTest()
		config.CurrServer = savedServer
		SetHandlers(HandlerDeps{})
	}
}
