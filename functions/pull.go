package functions

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/gravitl/netclient/auth"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/daemon"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
)

var pMutex = sync.Mutex{} // used to mutex functions for pull

// Pull - pulls the latest config from the server, if manual it will overwrite
func Pull(restart bool, resetIfFailedOvered bool) (models.HostPull, bool, bool, error) {
	pMutex.Lock()
	defer pMutex.Unlock()
	resetInterface := false
	replacePeers := false
	serverName := config.CurrServer
	server := config.GetServer(serverName)
	if server == nil {
		return models.HostPull{}, resetInterface, replacePeers, errors.New("server config not found")
	}
	token, err := auth.Authenticate(server, config.Netclient())
	if err != nil {
		return models.HostPull{}, resetInterface, replacePeers, err
	}

	url := fmt.Sprintf("https://%s/api/v1/host?reset_failovered=%v", server.API, resetIfFailedOvered)
	headers := make(http.Header)
	headers.Set("Content-Type", "application/json")
	headers.Set("Authorization", "Bearer "+token)
	respBytes, err := ncutils.SendRequest(http.MethodGet, url, headers, nil)
	if err != nil {
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
	if server.MetricsPort != pullResponse.ServerConfig.MetricsPort {
		restart = true
	}
	replacePeers = wireguard.ShouldReplace(pullResponse.Peers)
	config.UpdateHostPeers(pullResponse.Peers)
	config.UpdateServerConfig(&pullResponse.ServerConfig)
	config.SetNodes(pullResponse.Nodes)
	config.UpdateHost(&pullResponse.Host)
	server = config.GetServer(serverName)
	server.DnsNameservers = FilterDnsNameservers(pullResponse.DnsNameservers)
	fmt.Printf("completed pull for server %s\n", serverName)
	config.UpdateServer(server.Name, *server)
	_ = config.WriteServerConfig()
	_ = config.WriteNetclientConfig()
	_ = config.WriteNodeConfig()
	if restart {
		logger.Log(3, "restarting daemon")
		return models.HostPull{}, resetInterface, replacePeers, daemon.Restart()
	}
	return pullResponse, resetInterface, replacePeers, nil
}
