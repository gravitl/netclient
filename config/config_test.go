package config

import (
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/gravitl/netmaker/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestReadNetclientConfig(t *testing.T) {
	var err error
	type ConfigMin struct {
		Test      bool                                   `yaml:"test"`
		HostPeers map[string][]struct{ UpdateOnly bool } `yaml:"peers"`
	}
	empty := ConfigMin{}
	existing := ConfigMin{
		HostPeers: map[string][]struct{ UpdateOnly bool }{
			"foo1": {
				{UpdateOnly: true},
			},
		},
	}
	data := "test: true\npeers:\n  foo2:\n    - UpdateOnly: false"

	// test empty config
	err = yaml.NewDecoder(strings.NewReader(data)).Decode(&empty)
	assert.NoError(t, err)
	assert.True(t, empty.Test)
	assert.NotEmpty(t, empty.HostPeers["foo2"])

	// test existing config
	assert.NotEmpty(t, existing.HostPeers["foo1"], "foo1 existing before Decode")
	err = yaml.NewDecoder(strings.NewReader(data)).Decode(&existing)
	assert.NoError(t, err)
	assert.True(t, existing.Test)
	// "foo1" tags along from before `Decode`
	assert.NotEmpty(t, existing.HostPeers["foo1"], "foo1 exists after Decode")
	assert.NotEmpty(t, existing.HostPeers["foo2"])
}

// replacedConfig is what the write tests put in netclient.json.
var replacedConfig = Config{Host: schema.Host{ID: uuid.MustParse("6d1c2b9e-0f3a-4c55-9a77-2b8f1e4d6c01"), Name: "one.example.com"}}

// TestWriteAtomicKeepsTheFileWhileReplacing checks that a reader, or a process
// killed at any point, always finds netclient.json in place, and that the
// previous version is what stays in .bak.
func TestWriteAtomicKeepsTheFileWhileReplacing(t *testing.T) {
	file := filepath.Join(t.TempDir(), "netclient.json")
	require.NoError(t, WriteJSONAtomic(file, replacedConfig, file+".lck", 0700))
	previous, err := os.ReadFile(file)
	require.NoError(t, err)
	next := replacedConfig
	next.Name = "two.example.com"
	require.NoError(t, WriteJSONAtomic(file, next, file+".lck", 0700))
	backup, err := os.ReadFile(file + ".bak")
	require.NoError(t, err)
	assert.Equal(t, string(previous), string(backup), "the backup keeps the previous version")
	done := make(chan struct{})
	var missing atomic.Int32
	go func() {
		for {
			select {
			case <-done:
				return
			default:
				if _, err := os.Stat(file); err != nil {
					missing.Add(1)
				}
			}
		}
	}()
	for i := 0; i < 1000; i++ {
		require.NoError(t, WriteJSONAtomic(file, next, file+".lck", 0700))
	}
	close(done)
	assert.Zero(t, missing.Load(), "netclient.json was missing while it was being replaced")
}
