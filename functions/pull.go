package functions

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/devilcove/httpclient"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
)

// Pull - pulls the latest config from the server, if manual it will overwrite
func Pull(network string, iface bool) (*config.Node, error) {
	node, ok := config.Nodes[network]
	if !ok {
		return nil, errors.New("no such network")
	}
	server := config.Servers[node.Server]
	token, err := Authenticate(&node, &config.Netclient)
	if err != nil {
		return nil, err
	}
	endpoint := httpclient.JSONEndpoint[models.NodeGet, models.ErrorResponse]{
		URL:           "https://" + server.API,
		Route:         "/api/nodes/" + node.Network + "/" + node.ID,
		Method:        http.MethodGet,
		Authorization: "Bearer " + token,
		Response:      models.NodeGet{},
		ErrorResponse: models.ErrorResponse{},
	}
	response, err := endpoint.GetJSON(models.NodeGet{}, models.ErrorResponse{})
	if err != nil {
		if err == httpclient.ErrStatus {
			errors := response.(models.ErrorResponse)
			logger.Log(0, "errror getting node", strconv.Itoa(errors.Code), errors.Message)
		}
		return nil, err
	}
	nodeGet := response.(models.NodeGet)
	newNode, newServer, newHost := config.ConvertNode(&nodeGet)
	//why???
	//if nodeGet.Peers == nil {
	//nodeGet.Peers = []wgtypes.PeerConfig{}
	//}
	//update map and save
	config.Nodes[newNode.Network] = *newNode
	config.Servers[newNode.Server] = *newServer
	if err = config.WriteNodeConfig(); err != nil {
		return nil, err
	}
	config.SaveServer(newNode.Server, *newServer)
	config.WriteNodeConfig()
	config.WriteNetclientConfig()
	//update wg config
	peers := newNode.Peers
	for _, node := range config.Nodes {
		if node.Connected {
			peers = append(peers, node.Peers...)
		}
	}
	internetGateway, err := wireguard.UpdateWgPeers(peers)
	if internetGateway != nil && err != nil {
		newHost.InternetGateway = *internetGateway
		config.WriteNetclientConfig()
	}
	logger.Log(1, "node settings for network ", network)
	return newNode, err
}
