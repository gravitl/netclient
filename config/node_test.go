package config

import (
	"testing"

	"github.com/gravitl/netmaker/models"
	"github.com/stretchr/testify/assert"
)

func TestAnyNodeConnected(t *testing.T) {
	orig := Nodes
	t.Cleanup(func() { Nodes = orig })

	Nodes = NodeMap{}
	assert.False(t, AnyNodeConnected())

	Nodes = NodeMap{
		"net1": {CommonNode: models.CommonNode{Network: "net1", Connected: false}},
	}
	assert.False(t, AnyNodeConnected())

	Nodes = NodeMap{
		"net1": {CommonNode: models.CommonNode{Network: "net1", Connected: false}},
		"net2": {CommonNode: models.CommonNode{Network: "net2", Connected: true}},
	}
	assert.True(t, AnyNodeConnected())
}
