package config

import (
	"testing"

	"github.com/google/uuid"
	"github.com/gravitl/netmaker/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func uuidMustParse(s string) uuid.UUID {
	id, err := uuid.Parse(s)
	if err != nil {
		panic(err)
	}
	return id
}

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

func TestResolveServerDoesNotFallbackToUnrelatedSingleServer(t *testing.T) {
	Servers = map[string]Server{
		"comms.netmaker.io": {
			Name: "comms.netmaker.io",
			ServerConfig: models.ServerConfig{
				Server:  "comms.netmaker.io",
				API:     "api.comms.netmaker.io:443",
				APIHost: "api.comms.netmaker.io",
			},
		},
	}
	defer func() { Servers = make(map[string]Server) }()

	server, key := ResolveServer("nm.137-184-60-234.nip.io")
	assert.Nil(t, server)
	assert.Empty(t, key)

	server, key = ResolveServer("api.nm.137-184-60-234.nip.io")
	assert.Nil(t, server)
	assert.Empty(t, key)

	// Empty id may still resolve the sole configured server (current context).
	server, key = ResolveServer("")
	require.NotNil(t, server)
	assert.Equal(t, "comms.netmaker.io", key)
}

func TestDemoteServerToPartialKeepsDomainAndAPI(t *testing.T) {
	Servers = map[string]Server{
		"example.com": {
			Name: "example.com",
			MQID: uuidMustParse("11111111-1111-1111-1111-111111111111"),
			Nodes: map[string]bool{
				"net1": true,
			},
			ServerConfig: models.ServerConfig{
				Server:  "example.com",
				API:     "api.example.com:443",
				APIHost: "api.example.com",
			},
		},
	}
	CurrServer = "example.com"
	defer func() {
		Servers = make(map[string]Server)
		CurrServer = ""
	}()

	kept := DemoteServerToPartial("example.com")
	require.Equal(t, "example.com", kept)
	srv := GetServer("example.com")
	require.NotNil(t, srv)
	assert.Equal(t, "example.com", srv.Name)
	assert.Equal(t, "api.example.com:443", srv.API)
	assert.Empty(t, srv.Server, "registration identity must clear so re-login re-registers")
	assert.Equal(t, uuid.Nil, srv.MQID)
	assert.Empty(t, srv.Nodes)
}

func TestDemoteServerToPartialMissingReturnsEmpty(t *testing.T) {
	Servers = map[string]Server{}
	defer func() { Servers = make(map[string]Server) }()
	assert.Empty(t, DemoteServerToPartial("missing.example.com"))
}

func TestUpdateServerConfigKeepsMetricsPortWhenPayloadOmitsIt(t *testing.T) {
	Servers = map[string]Server{
		"api.example.com": {
			Name: "api.example.com",
			ServerConfig: models.ServerConfig{
				Server:      "api.example.com",
				API:         "api.example.com",
				MetricsPort: 51821,
			},
		},
	}
	CurrServer = "api.example.com"
	defer func() {
		Servers = make(map[string]Server)
		CurrServer = ""
	}()

	// A register response carries no metrics port; keeping the stored one is
	// what stops the next pull from seeing a change and restarting the daemon.
	UpdateServerConfig(&models.ServerConfig{
		Server: "api.example.com",
		API:    "api.example.com",
	})
	assert.Equal(t, 51821, Servers["api.example.com"].MetricsPort)

	UpdateServerConfig(&models.ServerConfig{
		Server:      "api.example.com",
		API:         "api.example.com",
		MetricsPort: 51822,
	})
	assert.Equal(t, 51822, Servers["api.example.com"].MetricsPort)
}
