package uiapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/models"
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

func TestConfigureServerKeepsCustomAPIHostAsTyped(t *testing.T) {
	prevFetch := fetchServerStatusVersion
	t.Cleanup(func() { fetchServerStatusVersion = prevFetch })
	var gotAPI string
	fetchServerStatusVersion = func(ctx context.Context, api string) (string, error) {
		gotAPI = api
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

	// Custom installs may use apinm.<base> (not api.<base>).
	body := `{"server":"apinm.example.com"}`
	req := httptest.NewRequest(http.MethodPost, "/server", strings.NewReader(body))
	rec := httptest.NewRecorder()
	configureServer(rec, req)

	assert.NotEqual(t, http.StatusBadRequest, rec.Code)
	assert.NotEqual(t, http.StatusConflict, rec.Code)
	// Version probe uses the resolved dialable API (before disk persist).
	assert.Equal(t, "apinm.example.com:443", gotAPI)
	if srv := config.GetServer("apinm.example.com"); srv != nil {
		assert.Equal(t, "apinm.example.com:443", srv.API)
		assert.Equal(t, "apinm.example.com", srv.APIHost)
	}
}

func TestConfigureServerKeepsApiPrefixedHostAsTyped(t *testing.T) {
	prevFetch := fetchServerStatusVersion
	t.Cleanup(func() { fetchServerStatusVersion = prevFetch })
	var gotAPI string
	fetchServerStatusVersion = func(ctx context.Context, api string) (string, error) {
		gotAPI = api
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

	body := `{"server":"api.nm.example.com"}`
	req := httptest.NewRequest(http.MethodPost, "/server", strings.NewReader(body))
	rec := httptest.NewRecorder()
	configureServer(rec, req)

	assert.NotEqual(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "api.nm.example.com:443", gotAPI)
	// Map key strips only a leading "api." label.
	if srv := config.GetServer("nm.example.com"); srv != nil {
		assert.Equal(t, "api.nm.example.com:443", srv.API)
		assert.Equal(t, "api.nm.example.com", srv.APIHost)
	}
}

func TestConfigureServerRejectsTenantUUIDWithoutAPI(t *testing.T) {
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

	tenant := "abdc97c9-a332-4979-9220-99d1da3c753b"
	body := `{"server":"` + tenant + `"}`
	req := httptest.NewRequest(http.MethodPost, "/server", strings.NewReader(body))
	rec := httptest.NewRecorder()
	configureServer(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Empty(t, config.CurrServer)
}

func TestConfigureServerAcceptsTenantUUIDWithAPI(t *testing.T) {
	prevFetch := fetchServerStatusVersion
	t.Cleanup(func() { fetchServerStatusVersion = prevFetch })
	var gotAPI string
	fetchServerStatusVersion = func(ctx context.Context, api string) (string, error) {
		gotAPI = api
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

	tenant := "abdc97c9-a332-4979-9220-99d1da3c753b"
	apiHost := "api-" + tenant + ".app.prod.netmaker.io"
	body := `{"server":"` + tenant + `","api":"` + apiHost + `"}`
	req := httptest.NewRequest(http.MethodPost, "/server", strings.NewReader(body))
	rec := httptest.NewRecorder()
	configureServer(rec, req)

	assert.NotEqual(t, http.StatusConflict, rec.Code)
	assert.NotEqual(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, apiHost+":443", gotAPI)
	if srv := config.GetServer(tenant); srv != nil {
		assert.Equal(t, apiHost+":443", srv.API)
		assert.Equal(t, apiHost, srv.APIHost)
	}
}

func TestConfigureServerPreservesTenantAPIOnBareRePOST(t *testing.T) {
	prevFetch := fetchServerStatusVersion
	t.Cleanup(func() { fetchServerStatusVersion = prevFetch })
	fetchServerStatusVersion = func(ctx context.Context, api string) (string, error) {
		return "v1.8.0", nil
	}

	tenant := "abdc97c9-a332-4979-9220-99d1da3c753b"
	apiHost := "api-" + tenant + ".app.prod.netmaker.io"
	prevServers := config.Servers
	prevCurr := config.CurrServer
	t.Cleanup(func() {
		config.Servers = prevServers
		config.CurrServer = prevCurr
	})
	config.Servers = map[string]config.Server{
		tenant: {
			Name: tenant,
			ServerConfig: models.ServerConfig{
				Server:  tenant,
				API:     apiHost + ":443",
				APIHost: apiHost,
			},
		},
	}
	config.CurrServer = tenant

	body := `{"server":"` + tenant + `"}`
	req := httptest.NewRequest(http.MethodPost, "/server", strings.NewReader(body))
	rec := httptest.NewRecorder()
	configureServer(rec, req)

	assert.NotEqual(t, http.StatusBadRequest, rec.Code)
	srv := config.GetServer(tenant)
	require.NotNil(t, srv)
	assert.Equal(t, apiHost+":443", srv.API)
}
