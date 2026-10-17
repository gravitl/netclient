package posture

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/gravitl/netclient/auth"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/models"
	"github.com/gravitl/netmaker/scope"
)

// FetchStatus queries the host-authenticated posture endpoint on the named
// server. Pass an empty serverName to use the current server. The host's
// JWT is obtained via auth.Authenticate; on 401 the cached token is purged
// and the request is retried once.
func FetchStatus(serverName string) (*models.HostPostureStatus, error) {
	if serverName == "" {
		serverName = config.CurrServer
	}
	if serverName == "" {
		return nil, errors.New("no current server configured")
	}
	server := config.GetServer(serverName)
	if server == nil {
		return nil, fmt.Errorf("server %q not found in config", serverName)
	}
	host := config.Netclient()
	if host == nil {
		return nil, errors.New("no configured host found")
	}

	status, err := postureGet(server, host)
	if err == nil {
		return status, nil
	}

	// Retry once after clearing a stale JWT.
	var statusErr ncutils.ErrStatusNotOk
	if errors.As(err, &statusErr) && statusErr.Status == http.StatusUnauthorized {
		auth.CleanJwtToken()
		return postureGet(server, host)
	}
	return nil, err
}

func postureGet(server *config.Server, host *config.Config) (*models.HostPostureStatus, error) {
	token, err := auth.Authenticate(server, host)
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("https://%s/api/v1/host/%s/posture_status", server.API, host.ID.String())
	headers := make(http.Header)
	headers.Set("Content-Type", "application/json")
	headers.Set("Authorization", "Bearer "+token)
	headers.Set(scope.HeaderTenantID, host.TenantID)
	respBytes, err := ncutils.SendRequest(http.MethodGet, url, headers, nil)
	if err != nil {
		return nil, err
	}
	var out models.HostPostureStatus
	if err := json.Unmarshal(respBytes.Bytes(), &out); err != nil {
		return nil, fmt.Errorf("decode posture status: %w", err)
	}
	return &out, nil
}
