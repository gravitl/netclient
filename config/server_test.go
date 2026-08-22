package config

import (
	"testing"

	"github.com/gravitl/netmaker/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveServerByAPIAlias(t *testing.T) {
	Servers = map[string]Server{
		"api.example.com": {
			Name: "api.example.com",
			ServerConfig: models.ServerConfig{
				Server: "api.example.com",
				API:    "api.example.com",
			},
		},
	}
	defer func() { Servers = make(map[string]Server) }()

	_, key := ResolveServer("example.com")
	assert.Equal(t, "api.example.com", key)

	_, key = ResolveServer("api.example.com")
	assert.Equal(t, "api.example.com", key)

	server, key := ResolveServer("https://api.example.com")
	require.NotNil(t, server)
	assert.Equal(t, "api.example.com", key)
}
