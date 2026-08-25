package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDesiredNetworksRememberForgetAndIsolation(t *testing.T) {
	desiredConnectionsDir = t.TempDir()
	t.Cleanup(func() { desiredConnectionsDir = "" })

	require.NoError(t, RememberDesiredNetwork("alice", "t1", "net1"))
	require.NoError(t, RememberDesiredNetwork("alice", "t1", "net2"))
	require.NoError(t, RememberDesiredNetwork("alice", "t1", "net1")) // most recent
	assert.Equal(t, []string{"net2", "net1"}, GetDesiredNetworks("alice", "t1"))

	require.NoError(t, ForgetDesiredNetwork("alice", "t1", "net2"))
	assert.Equal(t, []string{"net1"}, GetDesiredNetworks("alice", "t1"))
	assert.Empty(t, GetDesiredNetworks("bob", "t1"))
	assert.Empty(t, GetDesiredNetworks("alice", "t2"))

	require.NoError(t, SetDesiredNetworks("alice", "t1", []string{"net3", "net3", " net4 "}))
	assert.Equal(t, []string{"net3", "net4"}, GetDesiredNetworks("alice", "t1"))

	require.FileExists(t, filepath.Join(desiredConnectionsDir, desiredConnectionsFile))
}

func TestSnapshotDesiredStateRecordsWantIGW(t *testing.T) {
	desiredConnectionsDir = t.TempDir()
	t.Cleanup(func() { desiredConnectionsDir = "" })

	require.NoError(t, SnapshotDesiredState("alice", "t1", []string{"net1"}, true))
	assert.Equal(t, []string{"net1"}, GetDesiredNetworks("alice", "t1"))
	assert.True(t, GetDesiredWantIGW("alice", "t1"))

	require.NoError(t, SetDesiredNetworks("alice", "t1", []string{"net1", "net2"}))
	assert.True(t, GetDesiredWantIGW("alice", "t1"), "updating networks must keep want_igw")

	require.NoError(t, SetDesiredWantIGW("alice", "t1", false))
	assert.False(t, GetDesiredWantIGW("alice", "t1"))
}

func TestSetDesiredNetworksEmptyPreservesFileForOtherUsers(t *testing.T) {
	desiredConnectionsDir = t.TempDir()
	t.Cleanup(func() { desiredConnectionsDir = "" })

	require.NoError(t, SetDesiredNetworks("alice", "t1", []string{"net1"}))
	require.NoError(t, SetDesiredNetworks("bob", "t1", []string{"net2"}))
	require.NoError(t, SetDesiredNetworks("alice", "t1", nil))
	assert.Empty(t, GetDesiredNetworks("alice", "t1"))
	assert.Equal(t, []string{"net2"}, GetDesiredNetworks("bob", "t1"))
}

func TestSkipWriteWithoutUserSession(t *testing.T) {
	desiredConnectionsDir = t.TempDir()
	t.Cleanup(func() { desiredConnectionsDir = "" })

	require.NoError(t, SnapshotDesiredState("alice", "t1", []string{"netmaker"}, false))
	require.NoError(t, RememberDesiredNetwork("", "t1", "cli-net"))
	require.NoError(t, RememberDesiredNetwork("alice", "", "cli-net"))
	require.NoError(t, SetDesiredWantIGW("", "", true))
	require.NoError(t, SnapshotDesiredState("", "", []string{"cli-net"}, true))

	assert.Equal(t, []string{"netmaker"}, GetDesiredNetworks("alice", "t1"))
	assert.False(t, GetDesiredWantIGW("alice", "t1"))
	assert.Empty(t, GetDesiredNetworks("", ""))
	assert.Empty(t, GetDesiredNetworks("alice", ""))
	_, err := os.Stat(filepath.Join(desiredConnectionsDir, desiredConnectionsFile))
	require.NoError(t, err)
	data, err := os.ReadFile(filepath.Join(desiredConnectionsDir, desiredConnectionsFile))
	require.NoError(t, err)
	assert.NotContains(t, string(data), `"_local"`)
	assert.NotContains(t, string(data), `"cli-net"`)
}

func TestCLIDoesNotCreateDesiredConnectionsFile(t *testing.T) {
	desiredConnectionsDir = t.TempDir()
	t.Cleanup(func() { desiredConnectionsDir = "" })

	require.NoError(t, RememberDesiredNetwork("", "", "net1"))
	require.NoError(t, SetDesiredWantIGW("", "t1", true))
	_, err := os.Stat(filepath.Join(desiredConnectionsDir, desiredConnectionsFile))
	assert.True(t, os.IsNotExist(err))
}

func TestWritesNestedUserTenantShape(t *testing.T) {
	desiredConnectionsDir = t.TempDir()
	t.Cleanup(func() { desiredConnectionsDir = "" })

	require.NoError(t, SnapshotDesiredState("alice", "t1", []string{"net1"}, true))

	data, err := os.ReadFile(filepath.Join(desiredConnectionsDir, desiredConnectionsFile))
	require.NoError(t, err)
	assert.JSONEq(t, `{
		"alice": {
			"t1": {
				"networks": ["net1"],
				"want_igw": true
			}
		}
	}`, string(data))
}
