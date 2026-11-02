package uiapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gravitl/netclient/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsDesktopServerCompatible(t *testing.T) {
	assert.False(t, IsDesktopServerCompatible(""))
	assert.False(t, IsDesktopServerCompatible("v1.6.0"))
	assert.False(t, IsDesktopServerCompatible("v1.7.0"))
	assert.False(t, IsDesktopServerCompatible("1.7.0"))
	assert.True(t, IsDesktopServerCompatible("v1.7.1"))
	assert.True(t, IsDesktopServerCompatible("v1.8.0"))
	assert.True(t, IsDesktopServerCompatible("dev"))
	assert.False(t, IsDesktopServerCompatible("not-a-version"))
}

func TestConfigureSessionRejectsIncompatibleServer(t *testing.T) {
	clearSessionForTest()
	config.CurrServer = "api.example.com"
	stubCompatibleServerConfig(t, "v1.7.0")

	registered := false
	SetHandlers(HandlerDeps{
		RegisterSession: func(server, username, authToken, password, tenantID string) error {
			registered = true
			return nil
		},
	})

	body := `{"username":"alice","auth_token":"tok"}`
	req := httptest.NewRequest(http.MethodPut, "/session", strings.NewReader(body))
	rec := httptest.NewRecorder()
	configureSession(rec, req)

	require.Equal(t, http.StatusConflict, rec.Code)
	var errBody ErrorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &errBody))
	assert.Equal(t, ErrCodeServerIncompatible, errBody.Code)
	assert.Contains(t, errBody.Message, "newer than")
	assert.False(t, registered, "must not register against an incompatible server")
	assert.False(t, isSessionActive())
}

func TestConfigureServerRejectsIncompatibleServer(t *testing.T) {
	prevFetch := fetchServerStatusVersion
	t.Cleanup(func() { fetchServerStatusVersion = prevFetch })
	fetchServerStatusVersion = func(ctx context.Context, api string) (string, error) {
		return "v1.6.5", nil
	}

	prevServers := config.Servers
	prevCurr := config.CurrServer
	t.Cleanup(func() {
		config.Servers = prevServers
		config.CurrServer = prevCurr
	})
	config.Servers = map[string]config.Server{}
	config.CurrServer = ""

	body := `{"server":"nm.old.example.com"}`
	req := httptest.NewRequest(http.MethodPost, "/server", strings.NewReader(body))
	rec := httptest.NewRecorder()
	configureServer(rec, req)

	require.Equal(t, http.StatusConflict, rec.Code)
	var errBody ErrorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &errBody))
	assert.Equal(t, ErrCodeServerIncompatible, errBody.Code)
	assert.Empty(t, config.CurrServer)
}

func TestConfigureServerAllowsCompatibleServer(t *testing.T) {
	prevFetch := fetchServerStatusVersion
	t.Cleanup(func() { fetchServerStatusVersion = prevFetch })
	fetchServerStatusVersion = func(ctx context.Context, api string) (string, error) {
		return "v1.8.0", nil
	}

	prevServers := config.Servers
	prevCurr := config.CurrServer
	t.Cleanup(func() {
		config.Servers = prevServers
		config.CurrServer = prevCurr
	})
	config.Servers = map[string]config.Server{}
	config.CurrServer = ""

	body := `{"server":"nm.new.example.com"}`
	req := httptest.NewRequest(http.MethodPost, "/server", strings.NewReader(body))
	rec := httptest.NewRecorder()
	// Stub status only — if UpsertPartialServer fails on disk, we still
	// assert we got past the compatibility gate (not 409).
	configureServer(rec, req)

	assert.NotEqual(t, http.StatusConflict, rec.Code)
}
