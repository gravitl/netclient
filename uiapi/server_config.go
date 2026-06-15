package uiapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	nmConfig "github.com/gravitl/netmaker/config"
)

func fetchServerConfig(ctx context.Context, server, username, authToken string) (nmConfig.ServerConfig, error) {
	var cfg nmConfig.ServerConfig
	if server == "" || authToken == "" {
		return cfg, fmt.Errorf("server or auth token not configured")
	}
	host := server
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+"/api/server/getconfig", nil)
	if err != nil {
		return cfg, err
	}
	req.Header.Set("Authorization", "Bearer "+authToken)
	req.Header.Set("X-Application-Name", "netmaker-desktop")
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

func serverAddress() string {
	server := configuredServer()
	if server != "" {
		return server
	}
	if configCurrServer := currentNetclientServer(); configCurrServer != "" {
		return configCurrServer
	}
	return ""
}

func currentNetclientServer() string {
	// resolved in connections.go via config import
	return getCurrServerName()
}
