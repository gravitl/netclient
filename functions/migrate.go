package functions

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/devilcove/httpclient"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/daemon"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	"github.com/kr/pretty"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Migrate update data from older versions of netclient to new format
func Migrate() {
	delete := true
	if _, err := os.Stat("/etc/netclient/config"); err != nil {
		//nothing to migrate ... exiting"
		return
	}
	logger.Log(0, "migration to v0.18.0 started")
	networks, err := config.GetSystemNetworks()
	if err != nil {
		fmt.Println("error reading network data ", err.Error())
		return
	}
	if err := daemon.Stop(); err != nil {
		logger.Log(0, "failed to stop daemon", err.Error())
	}
	for _, network := range networks {
		logger.Log(0, "migrating", network)
		cfg, err := config.ReadConfig(network)
		if err != nil {
			logger.Log(0, "failed to read config for network", network, "skipping ...")
			continue
		}
		nodeGet := models.NodeGet{
			Node: cfg.Node,
		}
		pass, err := os.ReadFile(config.GetNetclientPath() + "config/secret-" + network)
		if err != nil {
			logger.Log(0, "could not read secrets file", err.Error())
			continue
		}
		node, _, _ := config.ConvertOldNode(&nodeGet)
		server := config.ConvertOldServerCfg(&cfg.Server)
		node.Server = server.Name
		migrationData := models.MigrationData{
			JoinData: models.JoinData{
				Node: models.Node{
					CommonNode: node.CommonNode,
				},
				Host: config.Netclient().Host,
			},
			LegacyNodeID: cfg.Node.ID,
			Password:     string(pass),
		}
		//call migrate node
		if config.Netclient().Debug {
			fmt.Println("calling migration endpoint for node", cfg.Node.ID)
			pretty.Println(migrationData)
		}
		api := httpclient.JSONEndpoint[models.NodeJoinResponse, models.ErrorResponse]{
			URL:    "https://" + cfg.Server.API,
			Route:  "/api/nodes/" + cfg.Node.Network + "/" + cfg.Node.ID + "/migrate",
			Method: http.MethodPost,
			Headers: []httpclient.Header{
				{
					Name:  "requestfrom",
					Value: "node",
				},
			},
			Data:          migrationData,
			Response:      models.NodeJoinResponse{},
			ErrorResponse: models.ErrorResponse{},
		}
		joinResponse, errData, err := api.GetJSON(models.NodeJoinResponse{}, models.ErrorResponse{})
		if err != nil {
			logger.Log(0, "err migrating data", err.Error())
			if errors.Is(err, httpclient.ErrStatus) {
				logger.Log(0, "error joining network", strconv.Itoa(errData.Code), errData.Message)
				delete = false
				continue
			}
		}
		//process server response
		if !IsVersionComptatible(joinResponse.ServerConfig.Version) {
			logger.Log(0, "incompatible server version")
			delete = false
			continue
		}
		logger.Log(1, "network:", node.Network, "node created on remote server...updating configs")
		// reset attributes that should not be changed by server
		server = config.GetServer(joinResponse.ServerConfig.Server)
		// if new server, populate attributes
		if server == nil {
			server = &config.Server{}
			server.ServerConfig = joinResponse.ServerConfig
			server.Name = joinResponse.ServerConfig.Server
			server.MQID = config.Netclient().ID
			server.Nodes = make(map[string]bool)
		}
		server.Nodes[joinResponse.Node.Network] = true
		newNode := config.Node{}
		newNode.CommonNode = joinResponse.Node.CommonNode
		newNode.Connected = true
		config.UpdateHostPeers(server.Name, joinResponse.Peers)
		internetGateway, err := wireguard.UpdateWgPeers(joinResponse.Peers)
		if err != nil {
			logger.Log(0, "failed to update wg peers", err.Error())
		}
		if internetGateway != nil {
			config.Netclient().InternetGateway = *internetGateway
		}
		//save new configurations
		config.UpdateNodeMap(node.Network, *node)
		config.UpdateServer(node.Server, *server)
		if err := config.SaveServer(node.Server, *server); err != nil {
			logger.Log(0, "failed to save server", err.Error())
		}
		if err := config.WriteNetclientConfig(); err != nil {
			logger.Log(0, "error saving netclient config", err.Error())
		}
		if err := config.WriteNodeConfig(); err != nil {
			logger.Log(0, "error saving node map", err.Error())
		}
		if err := wireguard.WriteWgConfig(config.Netclient(), config.GetNodes()); err != nil {
			logger.Log(0, "error saving wireguard conf", err.Error())
		}
		_ = removeHostDNS(network)
		legacyPeers, err := wireguard.GetDevicePeers(cfg.Node.Interface)
		if err != nil {
			logger.Log(0, "failed to obtain wg info for legacy interface", cfg.Node.Interface)
		}
		peers := []wgtypes.PeerConfig{}
		for _, peer := range legacyPeers {
			log.Println("processing peer", peer.PublicKey)
			peerConfig := wgtypes.PeerConfig{
				PublicKey:         peer.PublicKey,
				Endpoint:          peer.Endpoint,
				AllowedIPs:        peer.AllowedIPs,
				ReplaceAllowedIPs: true,
			}
			peers = append(peers, peerConfig)
		}
		config.UpdateHostPeers(server.Name, peers)
		if err := config.WriteNetclientConfig(); err != nil {
			logger.Log(0, "error saving netclient config", err.Error())
		}
		wireguard.DeleteOldInterface(cfg.Node.Interface)
	}
	//delete old config dir
	if delete {
		logger.Log(3, "removing old config files")
		if err := os.RemoveAll(config.GetNetclientPath() + "config/"); err != nil {
			logger.Log(0, "failed to delete old configuration files ", err.Error())
		}
	}
}
