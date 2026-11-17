package uiapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gravitl/netclient/config"
	nmConfig "github.com/gravitl/netmaker/config"
	"github.com/gravitl/netmaker/scope"
)

// fetchServerStatusVersion hits the public /api/server/status endpoint so we
// can reject incompatible servers on POST /server before the user logs in.
// Overridable in tests.
var fetchServerStatusVersion = fetchServerStatusVersionHTTP

func fetchServerStatusVersionHTTP(ctx context.Context, api string) (string, error) {
	api = config.NormalizeServerAPI(api)
	if api == "" {
		return "", fmt.Errorf("server API not configured")
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, config.APIBaseURL(api)+"/api/server/status", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Application-Name", "netmaker-desktop")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to fetch server status: %s", resp.Status)
	}
	var body struct {
		Version string `json:"version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", err
	}
	return body.Version, nil
}

// fetchServerConfig is overridable in tests.
var fetchServerConfig = fetchServerConfigHTTP

func fetchServerConfigHTTP(ctx context.Context, server, username, authToken, tenantID string) (nmConfig.ServerConfig, error) {
	var cfg nmConfig.ServerConfig
	if server == "" || authToken == "" {
		fmt.Println("uiapi: getconfig skip server=", server, "token_set=", authToken != "", "user=", username)
		return cfg, fmt.Errorf("server or auth token not configured")
	}
	apiRaw := ""
	apiHost := ""
	if srv := config.GetServer(server); srv != nil {
		apiRaw = srv.API
		apiHost = srv.APIHost
	}
	api := apiRaw
	if api == "" {
		api = server
	}
	api = config.NormalizeServerAPI(api)
	if api == "" {
		fmt.Println("uiapi: getconfig empty api after normalize server=", server, "api_raw=", apiRaw, "api_host=", apiHost)
		return cfg, fmt.Errorf("server or auth token not configured")
	}
	url := config.APIBaseURL(api) + "/api/server/getconfig"
	tenant := strings.TrimSpace(tenantID)
	fmt.Println("uiapi: getconfig request",
		"server=", server,
		"api_raw=", apiRaw,
		"api_host=", apiHost,
		"api=", api,
		"url=", url,
		"user=", username,
		"tenant=", tenant,
		"tenant_header=", tenant != "",
		"token_len=", len(authToken),
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		fmt.Println("uiapi: getconfig build request error:", err.Error())
		return cfg, err
	}
	req.Header.Set("Authorization", "Bearer "+authToken)
	req.Header.Set("X-Application-Name", "netmaker-desktop")
	if tenant != "" {
		req.Header.Set(scope.HeaderTenantID, tenant)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("uiapi: getconfig dial error url=", url, "err=", err.Error())
		return cfg, err
	}
	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		fmt.Println("uiapi: getconfig read body error:", readErr.Error(), "status=", resp.Status)
	}
	if resp.StatusCode != http.StatusOK {
		fmt.Println("uiapi: getconfig failed",
			"status=", resp.StatusCode,
			"status_text=", resp.Status,
			"url=", url,
			"tenant=", tenant,
			"body=", strings.TrimSpace(truncateForLog(body, 2048)),
		)
		return cfg, fmt.Errorf("failed to fetch server config: %s", resp.Status)
	}
	if err := json.Unmarshal(body, &cfg); err != nil {
		fmt.Println("uiapi: getconfig decode error:", err.Error(), "body=", strings.TrimSpace(truncateForLog(body, 2048)))
		return cfg, err
	}
	fmt.Println("uiapi: getconfig ok",
		"url=", url,
		"tenant=", tenant,
		"version=", cfg.Version,
	)
	_ = username
	return cfg, nil
}

func activeServerAddress() string {
	return getCurrServerName()
}

func serverAddress() string {
	return activeServerAddress()
}

// truncateForLog limits error-log body dumps without affecting decode.
func truncateForLog(b []byte, max int) string {
	if max <= 0 || len(b) <= max {
		return string(b)
	}
	return string(b[:max]) + "…"
}
