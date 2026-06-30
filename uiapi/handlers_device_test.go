package uiapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	nmConfig "github.com/gravitl/netmaker/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListNetworksHandler(t *testing.T) {
	setStatus(Idle)
	clearSessionForTest()
	setupTestSession("api.example.com", "alice", "token-123")

	SetHandlers(HandlerDeps{
		FetchNetworks: func(server, token string) ([]DeviceNetworkView, error) {
			assert.Equal(t, "api.example.com", server)
			assert.Equal(t, "token-123", token)
			return []DeviceNetworkView{{NetworkID: "net1", Status: "available"}}, nil
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/networks", nil)
	req.Header.Set("x-netmaker-auth-key", loadAuthKey())
	rec := httptest.NewRecorder()
	authMiddleware(http.HandlerFunc(listNetworksHandler)).ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var networks []DeviceNetworkView
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &networks))
	require.Len(t, networks, 1)
	assert.Equal(t, "net1", networks[0].NetworkID)
}

func TestJoinNetworkHandlerRequiresSession(t *testing.T) {
	clearSessionForTest()
	req := httptest.NewRequest(http.MethodPost, "/networks/net1/join", nil)
	req.Header.Set("x-netmaker-auth-key", loadAuthKey())
	req.SetPathValue("network", "net1")
	rec := httptest.NewRecorder()
	authMiddleware(http.HandlerFunc(joinNetworkHandler)).ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestSyncHandler(t *testing.T) {
	setStatus(Idle)
	clearSessionForTest()
	setupTestSession("api.example.com", "alice", "sync-token")

	synced := false
	SetHandlers(HandlerDeps{
		Sync: func(token string) error {
			assert.Equal(t, "sync-token", token)
			synced = true
			return nil
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/sync", nil)
	req.Header.Set("x-netmaker-auth-key", loadAuthKey())
	rec := httptest.NewRecorder()
	authMiddleware(http.HandlerFunc(syncHandler)).ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, synced)
}

func TestCancelJoinHandler(t *testing.T) {
	setStatus(Idle)
	clearSessionForTest()
	setupTestSession("api.example.com", "alice", "token-123")

	cancelled := false
	SetHandlers(HandlerDeps{
		CancelJoin: func(network, server, token string) error {
			assert.Equal(t, "auto-join", network)
			assert.Equal(t, "api.example.com", server)
			assert.Equal(t, "token-123", token)
			cancelled = true
			return nil
		},
	})

	req := httptest.NewRequest(http.MethodDelete, "/networks/auto-join/cancel", nil)
	req.Header.Set("x-netmaker-auth-key", loadAuthKey())
	req.SetPathValue("network", "auto-join")
	rec := httptest.NewRecorder()
	authMiddleware(http.HandlerFunc(cancelJoinHandler)).ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, cancelled)
}

func setupTestSession(server, username, token string) {
	session.mu.Lock()
	session.pendingServer = server
	session.username = username
	session.authToken = token
	session.expiresAt = time.Time{}
	session.mu.Unlock()
}

func clearSessionForTest() {
	session.mu.Lock()
	session.username = ""
	session.authToken = ""
	session.pendingServer = ""
	session.serverConfig = nmConfig.ServerConfig{}
	session.expiresAt = time.Time{}
	session.mu.Unlock()
}
