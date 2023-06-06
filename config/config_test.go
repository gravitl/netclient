package config

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
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
