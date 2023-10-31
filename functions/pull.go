package functions

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/devilcove/httpclient"
	"github.com/gravitl/netclient/auth"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/daemon"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
)

// Pull - pulls the latest config from the server, if manual it will overwrite
func Pull(restart bool) (models.HostPull, error) {

	serverName := config.CurrServer
	server := config.GetServer(serverName)
	if server == nil {
		return models.HostPull{}, errors.New("server config not found")
	}
	token, err := auth.Authenticate(server, config.Netclient())
	if err != nil {
		return models.HostPull{}, err
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
		return models.HostPull{}, err
	}
	_ = config.UpdateHostPeers(pullResponse.Peers)
	pullResponse.ServerConfig.MQPassword = server.MQPassword // pwd can't change currently
	config.UpdateServerConfig(&pullResponse.ServerConfig)
	config.SetNodes(pullResponse.Nodes)
	config.UpdateHost(&pullResponse.Host)
	fmt.Printf("completed pull for server %s\n", serverName)
	_ = config.WriteServerConfig()
	_ = config.WriteNetclientConfig()
	_ = config.WriteNodeConfig()
	if restart {
		logger.Log(3, "restarting daemon")
		return models.HostPull{}, daemon.Restart()
	}
	return pullResponse, nil
}
