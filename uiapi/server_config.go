package uiapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gravitl/netclient/config"
	nmConfig "github.com/gravitl/netmaker/config"
	"github.com/gravitl/netmaker/scope"
)

func fetchServerConfig(ctx context.Context, server, username, authToken, tenantID string) (nmConfig.ServerConfig, error) {
	var cfg nmConfig.ServerConfig
	if server == "" || authToken == "" {
		return cfg, fmt.Errorf("server or auth token not configured")
	}
	api := ""
	if srv := config.GetServer(server); srv != nil {
		api = srv.API
	}
	if api == "" {
		api = server
	}
	api = config.NormalizeServerAPI(api)
	if api == "" {
		return cfg, fmt.Errorf("server or auth token not configured")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, config.APIBaseURL(api)+"/api/server/getconfig", nil)
	if err != nil {
		return cfg, err
	}
	req.Header.Set("Authorization", "Bearer "+authToken)
	req.Header.Set("X-Application-Name", "netmaker-desktop")
	if tenantID != "" {
		req.Header.Set(scope.HeaderTenantID, tenantID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return cfg, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return cfg, fmt.Errorf("failed to fetch server config: %s", resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return cfg, err
	}
	_ = username
	return cfg, nil
}

func activeServerAddress() string {
	return getCurrServerName()
}

func serverAddress() string {
	return activeServerAddress()
}

func currentNetclientServer() string {
	return getCurrServerName()
}
