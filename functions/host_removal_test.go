package functions

import (
	"testing"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDisposeServerEnrollmentHeadlessDeletes(t *testing.T) {
	prev := GUI.KeepServerDomainForRelogin
	GUI.KeepServerDomainForRelogin = nil
	t.Cleanup(func() {
		GUI.KeepServerDomainForRelogin = prev
		config.Servers = make(map[string]config.Server)
		config.CurrServer = ""
	})

	config.Servers = map[string]config.Server{
		"nm.example.com": {
			Name:  "nm.example.com",
			Nodes: map[string]bool{},
			ServerConfig: models.ServerConfig{
				Server: "nm.example.com",
				API:    "api.nm.example.com:443",
			},
		},
	}
	config.CurrServer = "nm.example.com"

	DisposeServerEnrollment("nm.example.com")

	assert.Nil(t, config.GetServer("nm.example.com"), "headless must delete server entry")
	assert.False(t, config.IsRegisteredToServer("nm.example.com"))
}

func TestDisposeServerEnrollmentDesktopDemotes(t *testing.T) {
	prev := GUI.KeepServerDomainForRelogin
	GUI.KeepServerDomainForRelogin = func() bool { return true }
	t.Cleanup(func() {
		GUI.KeepServerDomainForRelogin = prev
		config.Servers = make(map[string]config.Server)
		config.CurrServer = ""
	})

	config.Servers = map[string]config.Server{
		"nm.example.com": {
			Name:  "nm.example.com",
			Nodes: map[string]bool{},
			ServerConfig: models.ServerConfig{
				Server:   "nm.example.com",
				API:      "api.nm.example.com:443",
				TenantID: "tenant-1",
			},
		},
	}
	config.CurrServer = "nm.example.com"

	DisposeServerEnrollment("nm.example.com")

	srv := config.GetServer("nm.example.com")
	require.NotNil(t, srv, "desktop must keep domain for re-login")
	assert.Empty(t, srv.Server)
	assert.Empty(t, srv.TenantID)
	assert.NotEmpty(t, srv.API)
	assert.False(t, config.IsRegisteredToServer("nm.example.com"))
}

func TestGUIHooksNilMeansNoUIAPI(t *testing.T) {
	// functions tests do not blank-import desktop, so hooks stay nil
	// (same as default headless production builds).
	assert.Nil(t, GUI.StartUIAPI)
	assert.Nil(t, GUI.KeepServerDomainForRelogin)
	assert.False(t, DesktopSessionActive())
}
