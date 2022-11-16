package functions

import (
	"errors"
	"net/http"
	"os"
	"strconv"

	"github.com/devilcove/httpclient"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/local"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	"github.com/kr/pretty"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Pull - pulls the latest config from the server, if manual it will overwrite
func Pull(network string, iface bool) (*config.Node, error) {
	node, ok := config.Nodes[network]
	if !ok {
		return nil, errors.New("no such network")
	}
	server := config.Servers[node.Server]
	pretty.Println(server)
	if config.Netclient.IPForwarding && !ncutils.IsWindows() {
		if err := local.SetIPForwarding(); err != nil {
			return nil, err
		}
	}
	token, err := Authenticate(&node)
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
	newNode := config.ConvertNode(&nodeGet.Node)
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
		if err := wireguard.RemoveConf(node.Interface, false); err != nil {
			logger.Log(0, "error remove interface", node.Interface, err.Error())
		}
		err = config.ModPort(newNode)
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
	if iface {
		if err = wireguard.SetWGConfig(network, false, nodeGet.Peers[:]); err != nil {
			return nil, err
		}
	} else {
		if err = wireguard.SetWGConfig(network, true, nodeGet.Peers[:]); err != nil {
			if errors.Is(err, os.ErrNotExist) && !ncutils.IsFreeBSD() {
				return Pull(network, true)
			} else {
				return nil, err
			}
		}
	}
	return newNode, err
}

func informPortChange(node *config.Node) {
	if node.ListenPort == 0 {
		logger.Log(0, "network:", node.Network, "UDP hole punching enabled for node", node.Name)
	} else {
		logger.Log(0, "network:", node.Network, "node", node.Name, "is using port", strconv.Itoa(int(node.ListenPort)))
	}
}
