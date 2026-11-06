package desktop

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPreviousEnrollmentTenantPrefersServer(t *testing.T) {
	hostID := uuid.New()
	nc := config.Netclient()
	require.NotNil(t, nc)
	prevHostTenant := nc.TenantID
	prevID := nc.ID
	nc.ID = hostID
	nc.TenantID = "host-tenant"
	config.UpdateNetclient(*nc)
	config.Servers = map[string]config.Server{
		"example.com": {
			Name: "example.com",
			ServerConfig: models.ServerConfig{
				Server:   "example.com",
				API:      "api.example.com:443",
				TenantID: "server-tenant",
			},
		},
	}
	t.Cleanup(func() {
		h := config.Netclient()
		h.ID = prevID
		h.TenantID = prevHostTenant
		config.UpdateNetclient(*h)
		config.Servers = make(map[string]config.Server)
	})

	assert.Equal(t, "server-tenant", previousEnrollmentTenant("example.com"))
}

func TestIsHostRegisteredToAnotherTenant(t *testing.T) {
	assert.False(t, isHostRegisteredToAnotherTenant(nil))
	assert.True(t, isHostRegisteredToAnotherTenant(
		errors.New("host already registered to another tenant"),
	))
	assert.False(t, isHostRegisteredToAnotherTenant(errors.New("host does not belong to user")))
}

func TestRegisterSessionLeavesPreviousTenantBeforeRegister(t *testing.T) {
	hostID := uuid.New()
	nc := config.Netclient()
	require.NotNil(t, nc)
	prev := *nc
	nc.ID = hostID
	nc.TenantID = "tenant-a"
	nc.OwnerUsername = "alice"
	config.UpdateNetclient(*nc)
	config.CurrServer = "example.com"
	config.Servers = map[string]config.Server{
		"example.com": {
			Name: "example.com",
			ServerConfig: models.ServerConfig{
				Server:   "example.com",
				API:      "api.example.com:443",
				TenantID: "tenant-a",
			},
		},
	}

	prevRegister := registerDeviceOnServerForSession
	prevLeave := leaveHostOnTenantForSession
	prevPull := pullForSession
	leaveCalls := 0
	registerCalls := 0
	leaveHostOnTenantForSession = func(server, tenantID, userToken string) error {
		leaveCalls++
		assert.Equal(t, "example.com", server)
		assert.Equal(t, "tenant-a", tenantID)
		assert.Equal(t, "jwt", userToken)
		return nil
	}
	registerDeviceOnServerForSession = func(server, token string) error {
		registerCalls++
		assert.Equal(t, "jwt", token)
		// Simulate successful enroll under new tenant.
		h := config.Netclient()
		h.TenantID = "tenant-b"
		config.UpdateNetclient(*h)
		config.Servers["example.com"] = config.Server{
			Name: "example.com",
			ServerConfig: models.ServerConfig{
				Server:   "example.com",
				API:      "api.example.com:443",
				TenantID: "tenant-b",
			},
		}
		return nil
	}
	pullForSession = func(restart, resetIfFailedOvered, refresh bool) (models.HostPull, bool, bool, error) {
		return models.HostPull{}, false, false, nil
	}
	t.Cleanup(func() {
		registerDeviceOnServerForSession = prevRegister
		leaveHostOnTenantForSession = prevLeave
		pullForSession = prevPull
		config.UpdateNetclient(prev)
		config.Servers = make(map[string]config.Server)
		config.CurrServer = ""
	})

	err := RegisterSession("example.com", "alice", "jwt", "", "tenant-b")
	require.NoError(t, err)
	assert.Equal(t, 1, leaveCalls, "must leave tenant-a before register")
	assert.Equal(t, 1, registerCalls)
}

func TestRegisterSessionRetriesLeaveWhenRegisterBlocked(t *testing.T) {
	hostID := uuid.New()
	nc := config.Netclient()
	require.NotNil(t, nc)
	prev := *nc
	nc.ID = hostID
	nc.TenantID = "tenant-a"
	nc.OwnerUsername = "alice"
	config.UpdateNetclient(*nc)
	config.CurrServer = "example.com"
	config.Servers = map[string]config.Server{
		"example.com": {
			Name: "example.com",
			ServerConfig: models.ServerConfig{
				Server:   "example.com",
				API:      "api.example.com:443",
				TenantID: "tenant-a",
			},
		},
	}

	prevRegister := registerDeviceOnServerForSession
	prevLeave := leaveHostOnTenantForSession
	prevPull := pullForSession
	leaveCalls := 0
	registerCalls := 0
	leaveHostOnTenantForSession = func(server, tenantID, userToken string) error {
		leaveCalls++
		assert.Equal(t, "tenant-a", tenantID)
		return nil
	}
	registerDeviceOnServerForSession = func(server, token string) error {
		registerCalls++
		if registerCalls == 1 {
			// First leave "succeeded" locally but server still blocked.
			return errors.New("host already registered to another tenant")
		}
		h := config.Netclient()
		h.TenantID = "tenant-b"
		config.UpdateNetclient(*h)
		config.Servers["example.com"] = config.Server{
			Name: "example.com",
			ServerConfig: models.ServerConfig{
				Server:   "example.com",
				API:      "api.example.com:443",
				TenantID: "tenant-b",
			},
		}
		return nil
	}
	pullForSession = func(restart, resetIfFailedOvered, refresh bool) (models.HostPull, bool, bool, error) {
		return models.HostPull{}, false, false, nil
	}
	t.Cleanup(func() {
		registerDeviceOnServerForSession = prevRegister
		leaveHostOnTenantForSession = prevLeave
		pullForSession = prevPull
		config.UpdateNetclient(prev)
		config.Servers = make(map[string]config.Server)
		config.CurrServer = ""
	})

	err := RegisterSession("example.com", "alice", "jwt", "", "tenant-b")
	require.NoError(t, err)
	assert.Equal(t, 2, leaveCalls)
	assert.Equal(t, 2, registerCalls)
}
