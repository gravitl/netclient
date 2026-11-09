package desktop

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/uiapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDesiredWantsIGWIncludesEgressAndAuto(t *testing.T) {
	dir := t.TempDir()
	config.SetDesiredConnectionsDirForTest(dir)
	t.Cleanup(func() { config.SetDesiredConnectionsDirForTest("") })

	assert.False(t, desiredWantsIGW("alice", "t1"))

	require.NoError(t, config.SetDesiredWantIGW("alice", "t1", true))
	assert.True(t, desiredWantsIGW("alice", "t1"))
	require.NoError(t, config.ClearDesiredExitNode("alice", "t1"))
	assert.False(t, desiredWantsIGW("alice", "t1"))

	require.NoError(t, config.SetDesiredExitNode("alice", "t1", "net1", "eg-1"))
	assert.True(t, desiredWantsIGW("alice", "t1"))
	require.NoError(t, config.ClearDesiredExitNode("alice", "t1"))

	require.NoError(t, config.SetDesiredAutoExitNode("alice", "t1", "net1", "eg-near"))
	assert.True(t, desiredWantsIGW("alice", "t1"))
	require.NoError(t, config.ClearDesiredExitNode("alice", "t1"))

	// Partial / older file: egress id without want_igw still counts.
	writePartialDesired(t, dir, "alice", "t1", config.DesiredState{
		Networks:    []string{"net1"},
		WantIGW:     false,
		EgressID:    "eg-stale",
		ExitNetwork: "net1",
	})
	assert.True(t, desiredWantsIGW("alice", "t1"))
}

func TestHoldIGWTeardownWithoutSession(t *testing.T) {
	dir := t.TempDir()
	config.SetDesiredConnectionsDirForTest(dir)
	t.Cleanup(func() { config.SetDesiredConnectionsDirForTest("") })

	sessionReleased.Store(false)
	endExitSelect()
	uiapi.SetRestorePhase("")
	t.Cleanup(func() {
		sessionReleased.Store(false)
		endExitSelect()
		uiapi.SetRestorePhase("")
	})

	require.NoError(t, config.SetDesiredExitNode("alice", "t1", "net1", "eg-1"))
	beginExitSelect()
	uiapi.SetRestorePhase(uiapi.RestorePhaseExit)
	// No active UI session → desktopWantsIGW is false → never hold.
	assert.False(t, holdIGWTeardown())
}

func TestExitAssignUnconfirmed(t *testing.T) {
	assert.True(t, exitAssignUnconfirmed("eg-1", ""))
	assert.True(t, exitAssignUnconfirmed(" eg-1 ", "  "))
	assert.False(t, exitAssignUnconfirmed("", ""))
	assert.False(t, exitAssignUnconfirmed("", "eg-1"))
	assert.False(t, exitAssignUnconfirmed("eg-1", "eg-1"))
}

func writePartialDesired(t *testing.T, dir, user, tenant string, state config.DesiredState) {
	t.Helper()
	store := map[string]map[string]config.DesiredState{
		user: {tenant: state},
	}
	data, err := json.Marshal(store)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "desired_connections.json"), data, 0o600))
}
