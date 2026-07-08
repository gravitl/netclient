package uiapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gravitl/netclient/config"
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
	rec := httptest.NewRecorder()
	listNetworksHandler(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var networks []DeviceNetworkView
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &networks))
	require.Len(t, networks, 1)
	assert.Equal(t, "net1", networks[0].NetworkID)
}

func TestJoinNetworkHandlerRequiresSession(t *testing.T) {
	clearSessionForTest()
	req := httptest.NewRequest(http.MethodPost, "/networks/net1/join", nil)
	req.SetPathValue("network", "net1")
	rec := httptest.NewRecorder()
	joinNetworkHandler(rec, req)
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
	rec := httptest.NewRecorder()
	syncHandler(rec, req)

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
	req.SetPathValue("network", "auto-join")
	rec := httptest.NewRecorder()
	cancelJoinHandler(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, cancelled)
}

func TestListExitNodesHandler(t *testing.T) {
	setStatus(Idle)
	clearSessionForTest()
	setupTestSession("api.example.com", "alice", "token-123")

	SetHandlers(HandlerDeps{
		ListExitNodes: func(network, server, token string) ([]DeviceExitNodeView, error) {
			assert.Equal(t, "net1", network)
			assert.Equal(t, "api.example.com", server)
			assert.Equal(t, "token-123", token)
			return []DeviceExitNodeView{{EgressID: "e1", Name: "exit-us", Selected: true}}, nil
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/networks/net1/exit_nodes", nil)
	req.SetPathValue("network", "net1")
	rec := httptest.NewRecorder()
	listExitNodesHandler(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var nodes []DeviceExitNodeView
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &nodes))
	require.Len(t, nodes, 1)
	assert.Equal(t, "e1", nodes[0].EgressID)
	assert.True(t, nodes[0].Selected)
}

func TestSelectExitNodeHandler(t *testing.T) {
	setStatus(Idle)
	clearSessionForTest()
	setupTestSession("api.example.com", "alice", "token-123")

	selected := false
	SetHandlers(HandlerDeps{
		SelectExitNode: func(network, server, token, egressID string) (*DeviceExitNodeView, error) {
			assert.Equal(t, "net1", network)
			assert.Equal(t, "e1", egressID)
			selected = true
			return &DeviceExitNodeView{EgressID: "e1", Name: "exit-us", Selected: true}, nil
		},
	})

	req := httptest.NewRequest(http.MethodPut, "/networks/net1/exit_node", strings.NewReader(`{"egress_id":"e1"}`))
	req.SetPathValue("network", "net1")
	rec := httptest.NewRecorder()
	selectExitNodeHandler(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, selected)
	var node DeviceExitNodeView
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &node))
	assert.Equal(t, "e1", node.EgressID)
}

func TestSelectExitNodeHandlerRequiresSession(t *testing.T) {
	clearSessionForTest()
	req := httptest.NewRequest(http.MethodPut, "/networks/net1/exit_node", strings.NewReader(`{"egress_id":"e1"}`))
	req.SetPathValue("network", "net1")
	rec := httptest.NewRecorder()
	selectExitNodeHandler(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func setupTestSession(server, username, token string) {
	config.CurrServer = server
	session.mu.Lock()
	session.username = username
	session.authToken = token
	session.expiresAt = time.Time{}
	session.mu.Unlock()
}

func clearSessionForTest() {
	config.CurrServer = ""
	session.mu.Lock()
	session.username = ""
	session.authToken = ""
	session.serverConfig = nmConfig.ServerConfig{}
	session.expiresAt = time.Time{}
	session.mu.Unlock()
}

func TestConfigureSessionHandoffDisconnectsPriorUser(t *testing.T) {
	clearSessionForTest()
	setupTestSession("api.example.com", "alice", "alice-token")

	released := false
	registeredUser := ""
	SetHandlers(HandlerDeps{
		ReleaseSession: func(clearServer bool) error {
			released = true
			assert.False(t, clearServer)
			return nil
		},
		RegisterSession: func(server, username, authToken, password string) error {
			registeredUser = username
			assert.Equal(t, "api.example.com", server)
			assert.Equal(t, "bob-token", authToken)
			return nil
		},
	})

	body := `{"username":"bob","auth_token":"bob-token"}`
	req := httptest.NewRequest(http.MethodPut, "/session", strings.NewReader(body))
	rec := httptest.NewRecorder()
	configureSession(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, released, "expected prior user networks to be disconnected before handoff")
	assert.Equal(t, "bob", registeredUser)
}
