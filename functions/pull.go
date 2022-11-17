package functions

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/devilcove/httpclient"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/local"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Pull - pulls the latest config from the server, if manual it will overwrite
func Pull(network string, iface bool) (*config.Node, error) {
	node, ok := config.Nodes[network]
	if !ok {
		return nil, errors.New("no such network")
	}
	server := config.Servers[node.Server]
	if config.Netclient.IPForwarding && !ncutils.IsWindows() {
		if err := local.SetIPForwarding(); err != nil {
			return nil, err
		}
	}
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
	newNode, _, _ := config.ConvertNode(&nodeGet)
	if nodeGet.Peers == nil {
		nodeGet.Peers = []wgtypes.PeerConfig{}
	}

	if nodeGet.ServerConfig.API != "" && nodeGet.ServerConfig.MQPort != "" {
		config.ConvertServerCfg(&nodeGet.ServerConfig)
		if err := config.WriteServerConfig(); err != nil {
			logger.Log(0, "unable to update server config: "+err.Error())
		}
	}
	if int(nodeGet.Node.ListenPort) != node.LocalListenPort {
		nc := wireguard.NewNCIface(newNode)
		if err := nc.Close(); err != nil {
			logger.Log(0, "error remove interface", node.Interface, err.Error())
		}
		err = config.ModPort(newNode, &config.Netclient)
		if err != nil {
			return nil, err
		}
		informPortChange(newNode)
	}
	//update map and save
	config.Nodes[newNode.Network] = *newNode
	if err = config.WriteNodeConfig(); err != nil {
		return nil, err
	}

	return newNode, err
}

func informPortChange(node *config.Node) {
	if config.Netclient.ListenPort == 0 {
		logger.Log(0, "network:", node.Network, "UDP hole punching enabled for node", config.Netclient.Name)
	} else {
		logger.Log(0, "network:", node.Network, "node", config.Netclient.Name, "is using port", strconv.Itoa(int(config.Netclient.ListenPort)))
	}
}
