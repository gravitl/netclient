package uiapi

import (
	"testing"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/models"
	"github.com/stretchr/testify/assert"
)

func TestGetCurrServerNameDoesNotFallbackToSoleServer(t *testing.T) {
	prevServers := config.Servers
	prevCurr := config.CurrServer
	defer func() {
		config.Servers = prevServers
		config.CurrServer = prevCurr
	}()

	config.Servers = map[string]config.Server{
		"nm.example.nip.io": {
			Name: "nm.example.nip.io",
			ServerConfig: models.ServerConfig{
				Server:  "nm.example.nip.io",
				API:     "api.nm.example.nip.io:443",
				APIHost: "api.nm.example.nip.io",
			},
		},
	}
	config.CurrServer = ""

	assert.Empty(t, getCurrServerName())
	assert.Equal(t, "nm.example.nip.io", config.ResolveServerKey(""))
}
