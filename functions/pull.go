package functions

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/gravitl/netclient/auth"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/daemon"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	"github.com/gravitl/netmaker/scope"
)

var pMutex = sync.Mutex{} // used to mutex functions for pull

// fetchHostPull GETs /api/v1/host without applying the response to local config.
// Used by list (server-backed) and by Pull (which then writes config).
func fetchHostPull(resetIfFailedOvered, refresh bool) (models.HostPull, error) {
	server, serverName := config.ResolveServer(config.CurrServer)
	if server == nil {
		return models.HostPull{}, errors.New("server config not found")
	}
	if serverName != config.CurrServer {
		config.CurrServer = serverName
		_ = config.SetCurrServerCtxInFile(serverName)
	}
	// Partial servers.json entries (Desktop Settings) are not enrolled — do not
	// hammer authenticate / spam ERROR logs from mqFallback.
	if strings.TrimSpace(server.Server) == "" {
		return models.HostPull{}, errors.New("not registered to server")
	}
	token, err := auth.AuthenticateWithOptions(server, config.Netclient(), auth.AuthenticateOptions{
		CleanupOnUnauthorized: false,
	})
	if err != nil {
		if ClearEnrollmentIfHostMissing(serverName, err) {
			logger.Log(0, "pull failed for server", serverName, "host missing on server; enrollment cleared")
		}
		return models.HostPull{}, err
	}

	url := fmt.Sprintf("%s/api/v1/host?reset_failovered=%v&refresh=%v",
		config.APIBaseURL(config.NormalizeServerAPI(server.API)), resetIfFailedOvered, refresh)
	headers := make(http.Header)
	headers.Set("Content-Type", "application/json")
	auth.ApplyAPIHeaders(headers, token, config.Netclient())
	headers.Set(scope.HeaderTenantID, config.Netclient().TenantID)
	respBytes, err := ncutils.SendRequest(http.MethodGet, url, headers, nil)
	if err != nil {
		if denyErr := auth.AsMDMDenied(err); errors.Is(denyErr, auth.ErrMDMDenied) {
			fmt.Fprintln(os.Stderr, MDMDeniedMessage)
			return models.HostPull{}, denyErr
		}
		return models.HostPull{}, err
	}

	var pullResponse models.HostPull
	if err := json.Unmarshal(respBytes.Bytes(), &pullResponse); err != nil {
		return models.HostPull{}, err
	}
	return pullResponse, nil
}

// Pull pulls the latest config from the server.
// refresh asks the server to recompute host peer cache on demand (startup only).
// A 401 does not delete local server registration (servers.json).
func Pull(restart bool, resetIfFailedOvered bool, refresh bool) (models.HostPull, bool, bool, error) {
	pMutex.Lock()
	defer pMutex.Unlock()
	logger.Log(0, "host pull starting:", pullCaller(),
		fmt.Sprintf("restart=%v reset_failover=%v refresh=%v", restart, resetIfFailedOvered, refresh))
	resetInterface := false
	replacePeers := false
	pullResponse, err := fetchHostPull(resetIfFailedOvered, refresh)
	if err != nil {
		logger.Log(0, "pull failed:", err.Error())
		return models.HostPull{}, resetInterface, replacePeers, err
	}
	serverName := config.CurrServer
	server := config.GetServer(serverName)
	if server == nil {
		err := errors.New("server config not found")
		logger.Log(0, "pull failed:", err.Error())
		return models.HostPull{}, resetInterface, replacePeers, err
	}
	slog.Debug("host pull response",
		"server", serverName,
		"host_id", pullResponse.Host.ID.String(),
		"host.Nodes", pullResponse.Host.Nodes,
		"pull.Nodes", debugServerNodeSummary(pullResponse.Nodes),
		"peers", len(pullResponse.Peers),
		"local_before_sync", debugLocalNodeSummary())

	// MQTT Fallback Reset Interface
	for _, pullNode := range pullResponse.Nodes {
		nodeMap := config.GetNodes()
		currNode, ok := nodeMap[pullNode.Network]
		if !ok {
			resetInterface = true
			break
		}
		if currNode.Address.IP.String() != pullNode.Address.IP.String() {
			resetInterface = true
			break
		}
		if currNode.Address6.IP.String() != pullNode.Address6.IP.String() {
			resetInterface = true
			break
		}
	}
	if len(config.GetNodes()) != len(pullResponse.Nodes) {
		resetInterface = true
	}
	if config.Netclient().ListenPort != pullResponse.Host.ListenPort {
		resetInterface = true
	}
	// Only a real change needs the metrics listener rebound. 0 means the server
	// did not say, matching every other reader of MetricsPort; without that
	// guard an unset port restarted the daemon on every pull, and on Windows a
	// restart is a service bounce that takes the desktop API down with it.
	if pullResponse.ServerConfig.MetricsPort != 0 && pullResponse.ServerConfig.MetricsPort != server.MetricsPort {
		logger.Log(0, fmt.Sprintf("metrics port changed from %d to %d",
			server.MetricsPort, pullResponse.ServerConfig.MetricsPort))
		restart = true
	}
	replacePeers = wireguard.ShouldReplace(pullResponse.Peers)
	config.UpdateHostPeers(pullResponse.Peers)
	config.UpdateServerConfig(&pullResponse.ServerConfig)
	if srv := config.GetServer(serverName); srv != nil {
		_ = config.RefreshControlPlaneEndpoints(srv)
	}
	config.SyncTenantID(pullResponse.Host.ID, pullResponse.ServerConfig.TenantID)
	// Classic enrollments may have Server set with an empty TenantID until a
	// pull carries one. Backfill servers.json so MSP headers and enrollment
	// checks see the tenant without waiting for another register.
	if tid := strings.TrimSpace(pullResponse.ServerConfig.TenantID); tid != "" {
		if srv := config.GetServer(serverName); srv != nil && strings.TrimSpace(srv.TenantID) == "" {
			srv.TenantID = tid
			config.UpdateServer(srv.Name, *srv)
			if err := config.WriteServerConfig(); err != nil {
				logger.Log(0, "pull for server", serverName, "failed to backfill tenant id:", err.Error())
			}
		}
	}
	PreserveConnectionsAfterSync(pullResponse.Nodes)
	config.UpdateHost(&pullResponse.Host)
	server, serverName = config.ResolveServer(serverName)
	if server == nil {
		err := errors.New("server config not found")
		logger.Log(0, "pull failed:", err.Error())
		return models.HostPull{}, resetInterface, replacePeers, err
	}
	UpdateHostFromServer(&pullResponse.Host)
	server = config.GetServer(serverName)
	server.DnsNameservers = FilterDnsNameservers(pullResponse.DnsNameservers)
	slog.Debug("host pull sync complete",
		"server", serverName,
		"local", debugLocalNodeSummary(),
		"peers", len(config.Netclient().HostPeers))
	logger.Log(0, "completed pull for server", serverName)
	config.UpdateServer(server.Name, *server)
	if err := config.WriteServerConfig(); err != nil {
		logger.Log(0, "pull for server", serverName, "failed to write server config:", err.Error())
	}
	if err := config.WriteNetclientConfig(); err != nil {
		logger.Log(0, "pull for server", serverName, "failed to write host config:", err.Error())
	}
	if err := config.WriteNodeConfig(); err != nil {
		logger.Log(0, "pull for server", serverName, "failed to write node config:", err.Error())
	}
	if restart {
		logger.Log(0, "restarting daemon after pull")
		if err := daemon.Restart(); err != nil {
			logger.Log(0, "restart after pull failed:", err.Error())
			return models.HostPull{}, resetInterface, replacePeers, err
		}
		return models.HostPull{}, resetInterface, replacePeers, nil
	}
	return pullResponse, resetInterface, replacePeers, nil
}

// pullCaller names who requested the host pull (skips this file's frames).
func pullCaller() string {
	for skip := 2; skip < 8; skip++ {
		pc, file, line, ok := runtime.Caller(skip)
		if !ok {
			break
		}
		if filepath.Base(file) == "pull.go" {
			continue
		}
		name := "unknown"
		if fn := runtime.FuncForPC(pc); fn != nil {
			name = fn.Name()
		}
		return fmt.Sprintf("%s (%s:%d)", name, filepath.Base(file), line)
	}
	return "unknown"
}
