package functions

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"

	"github.com/devilcove/httpclient"
	"github.com/gravitl/netclient/auth"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/daemon"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
)

var pMutex = sync.Mutex{} // used to mutex functions for pull

// Pull - pulls the latest config from the server, if manual it will overwrite
func Pull(restart bool) (models.HostPull, bool, bool, error) {
	TraceCaller()
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
	endpoint := httpclient.JSONEndpoint[models.HostPull, models.ErrorResponse]{
		URL:           "https://" + server.API,
		Route:         "/api/v1/host",
		Method:        http.MethodGet,
		Authorization: "Bearer " + token,
		Response:      models.HostPull{},
		ErrorResponse: models.ErrorResponse{},
	}
	pullResponse, errData, err := endpoint.GetJSON(models.HostPull{}, models.ErrorResponse{})
	if err != nil {
		if errors.Is(err, httpclient.ErrStatus) {
			logger.Log(0, "error pulling server", serverName, strconv.Itoa(errData.Code), errData.Message)
		}
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
	fmt.Printf("completed pull for server %s\n", serverName)
	_ = config.WriteServerConfig()
	_ = config.WriteNetclientConfig()
	_ = config.WriteNodeConfig()
	if restart {
		logger.Log(3, "restarting daemon")
		return models.HostPull{}, resetInterface, replacePeers, daemon.Restart()
	}
	return pullResponse, resetInterface, replacePeers, nil
}
