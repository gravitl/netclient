package functions

import (
	"errors"
	"testing"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/models"
	"github.com/stretchr/testify/require"
)

func TestIsRegisteredToServer(t *testing.T) {
	config.Servers = map[string]config.Server{
		"api.example.com": {
			Name: "api.example.com",
			ServerConfig: models.ServerConfig{
				API: "api.example.com",
			},
		},
		"other.example.com": {
			Name: "other.example.com",
			ServerConfig: models.ServerConfig{
				API: "other.example.com",
			},
		},
	}
	t.Cleanup(func() { config.Servers = make(map[string]config.Server) })

	require.True(t, IsRegisteredToServer("api.example.com"))
	require.True(t, IsRegisteredToServer("example.com"))
	require.False(t, IsRegisteredToServer("unknown.example.com"))
}

func TestRegisterSession_skipsDeviceRegisterWhenServersJSONHasServer(t *testing.T) {
	config.Servers = map[string]config.Server{
		"api.example.com": {
			Name: "api.example.com",
			ServerConfig: models.ServerConfig{
				API:    "api.example.com",
				Server: "api.example.com",
			},
		},
	}
	config.CurrServer = "api.example.com"
	t.Cleanup(func() {
		config.Servers = make(map[string]config.Server)
		config.CurrServer = ""
	})

	registerCalled := false
	pullCalled := false
	origRegister := registerDeviceOnServerForSession
	origPull := pullForDesktopForSession
	registerDeviceOnServerForSession = func(server, token string) error {
		registerCalled = true
		return nil
	}
	pullForDesktopForSession = func(restart bool, resetIfFailedOvered bool) (models.HostPull, bool, bool, error) {
		pullCalled = true
		return models.HostPull{}, false, false, nil
	}
	t.Cleanup(func() {
		registerDeviceOnServerForSession = origRegister
		pullForDesktopForSession = origPull
	})

	err := RegisterSession("api.example.com", "user", "jwt-token", "")
	require.NoError(t, err)
	require.False(t, registerCalled, "device register must be skipped when servers.json has server")
	require.True(t, pullCalled, "pull must run on re-login")
}

func TestRegisterSession_registersWhenServersJSONEmpty(t *testing.T) {
	config.Servers = make(map[string]config.Server)
	config.CurrServer = "api.example.com"
	t.Cleanup(func() {
		config.Servers = make(map[string]config.Server)
		config.CurrServer = ""
	})

	registerCalled := false
	pullCalled := false
	origRegister := registerDeviceOnServerForSession
	origPull := pullForDesktopForSession
	registerDeviceOnServerForSession = func(server, token string) error {
		registerCalled = true
		config.Servers["api.example.com"] = config.Server{
			Name: "api.example.com",
			ServerConfig: models.ServerConfig{
				API:    "api.example.com",
				Server: "api.example.com",
			},
		}
		return nil
	}
	pullForDesktopForSession = func(restart bool, resetIfFailedOvered bool) (models.HostPull, bool, bool, error) {
		pullCalled = true
		return models.HostPull{}, false, false, nil
	}
	t.Cleanup(func() {
		registerDeviceOnServerForSession = origRegister
		pullForDesktopForSession = origPull
	})

	err := RegisterSession("api.example.com", "user", "jwt-token", "")
	require.NoError(t, err)
	require.True(t, registerCalled, "device register required when servers.json has no entry")
	require.True(t, pullCalled)
}

func TestRegisterSession_ignoresPasswordUsesDevicePath(t *testing.T) {
	config.Servers = map[string]config.Server{
		"api.example.com": {
			Name: "api.example.com",
			ServerConfig: models.ServerConfig{
				API:    "api.example.com",
				Server: "api.example.com",
			},
		},
	}
	config.CurrServer = "api.example.com"
	t.Cleanup(func() {
		config.Servers = make(map[string]config.Server)
		config.CurrServer = ""
	})

	registerCalled := false
	origRegister := registerDeviceOnServerForSession
	origPull := pullForDesktopForSession
	registerDeviceOnServerForSession = func(server, token string) error {
		registerCalled = true
		return nil
	}
	pullForDesktopForSession = func(restart bool, resetIfFailedOvered bool) (models.HostPull, bool, bool, error) {
		return models.HostPull{}, false, false, nil
	}
	t.Cleanup(func() {
		registerDeviceOnServerForSession = origRegister
		pullForDesktopForSession = origPull
	})

	err := RegisterSession("api.example.com", "user", "jwt-token", "legacy-password")
	require.NoError(t, err)
	require.False(t, registerCalled, "password must not trigger WSS/register when already registered")
}

func TestRegisterSession_requiresAuthToken(t *testing.T) {
	err := RegisterSession("api.example.com", "user", "", "")
	require.Error(t, err)
}

func TestRegisterSession_propagatesPullError(t *testing.T) {
	config.Servers = map[string]config.Server{
		"api.example.com": {Name: "api.example.com"},
	}
	config.CurrServer = "api.example.com"
	t.Cleanup(func() {
		config.Servers = make(map[string]config.Server)
		config.CurrServer = ""
	})

	origPull := pullForDesktopForSession
	pullForDesktopForSession = func(restart bool, resetIfFailedOvered bool) (models.HostPull, bool, bool, error) {
		return models.HostPull{}, false, false, errors.New("pull failed")
	}
	t.Cleanup(func() { pullForDesktopForSession = origPull })

	err := RegisterSession("api.example.com", "user", "jwt", "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to sync with server")
}
