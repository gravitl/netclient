package functions

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
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

// Pull pulls the latest config from the server.
// refresh asks the server to recompute host peer cache on demand (startup only).
// A 401 does not delete local server registration (servers.json).
func Pull(restart bool, resetIfFailedOvered bool, refresh bool) (models.HostPull, bool, bool, error) {
	pMutex.Lock()
	defer pMutex.Unlock()
	resetInterface := false
	replacePeers := false
	server, serverName := config.ResolveServer(config.CurrServer)
	if server == nil {
		return models.HostPull{}, resetInterface, replacePeers, errors.New("server config not found")
	}
	if serverName != config.CurrServer {
		config.CurrServer = serverName
		_ = config.SetCurrServerCtxInFile(serverName)
	}
	token, err := auth.AuthenticateWithOptions(server, config.Netclient(), auth.AuthenticateOptions{
		CleanupOnUnauthorized: false,
	})
	if err != nil {
		return models.HostPull{}, resetInterface, replacePeers, err
	}

	url := fmt.Sprintf("%s/api/v1/host?reset_failovered=%v&refresh=%v",
		config.APIBaseURL(config.NormalizeServerAPI(server.API)), resetIfFailedOvered, refresh)
	headers := make(http.Header)
	headers.Set("Content-Type", "application/json")
	headers.Set("Authorization", "Bearer "+token)
	headers.Set(scope.HeaderTenantID, config.Netclient().TenantID)
	respBytes, err := ncutils.SendRequest(http.MethodGet, url, headers, nil)
	if err != nil {
		if denyErr := auth.AsMDMDenied(err); errors.Is(denyErr, auth.ErrMDMDenied) {
			fmt.Fprintln(os.Stderr, MDMDeniedMessage)
			return models.HostPull{}, resetInterface, replacePeers, denyErr
		}
		return models.HostPull{}, resetInterface, replacePeers, err
	}

	var pullResponse models.HostPull
	err = json.Unmarshal(respBytes.Bytes(), &pullResponse)
	if err != nil {
		return models.HostPull{}, resetInterface, replacePeers, err
	}

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
	config.SyncTenantID(pullResponse.Host.ID, pullResponse.ServerConfig.TenantID)
	keepDisconnected := locallyDisconnectedNetworks()
	keepConnected := locallyConnectedNetworks()
	config.SetNodes(pullResponse.Nodes)
	keepLocallyDisconnected(keepDisconnected)
	keepLocallyConnected(keepConnected)
	reassertDesiredConnectedFlags()
	config.UpdateHost(&pullResponse.Host)
	server, serverName = config.ResolveServer(serverName)
	if server == nil {
		return models.HostPull{}, resetInterface, replacePeers, errors.New("server config not found")
	}
	UpdateHostFromServer(&pullResponse.Host)
	server = config.GetServer(serverName)
	server.DnsNameservers = FilterDnsNameservers(pullResponse.DnsNameservers)
	fmt.Printf("completed pull for server %s\n", serverName)
	config.UpdateServer(server.Name, *server)
	_ = config.WriteServerConfig()
	_ = config.WriteNetclientConfig()
	_ = config.WriteNodeConfig()
	if restart {
		logger.Log(0, "restarting daemon after pull")
		return models.HostPull{}, resetInterface, replacePeers, daemon.Restart()
	}
	return pullResponse, resetInterface, replacePeers, nil
}
