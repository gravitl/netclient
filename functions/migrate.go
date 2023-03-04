package functions

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/devilcove/httpclient"
	"github.com/google/uuid"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/daemon"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	"github.com/kr/pretty"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Migrate update data from older versions of netclient to new format
// TODO fix it
func Migrate() {
	delete := true
	config_dir := config.GetNetclientPath() + "config"
	if _, err := os.Stat(config_dir); err != nil {
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
		pass, err := os.ReadFile(config.GetNetclientPath() + "config/secret-" + network)
		if err != nil {
			logger.Log(0, "could not read secrets file", err.Error())
			continue
		}
		node, netclient := config.ConvertOldNode(&cfg.Node)
		node.Server = strings.Replace(cfg.Server.Server, "broker.", "", 1)
		serverHost, serverNode := config.Convert(netclient, node)
		ip, err := getInterfaces()
		if err != nil {
			logger.Log(0, "failed to retrieve local interfaces", err.Error())
		} else {
			// just in case getInterfaces() returned nil, nil
			if ip != nil {
				serverHost.Interfaces = *ip
			}
		}
		defaultInterface, err := getDefaultInterface()
		if err != nil {
			logger.Log(0, "default gateway not found", err.Error())
		} else {
			serverHost.DefaultInterface = defaultInterface
		}
		serverNode.ID = uuid.Nil
		migrationData := models.MigrationData{
			JoinData: models.JoinData{
				Node: serverNode,
				Host: serverHost,
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
			logger.Log(0, "incompatible server version", joinResponse.ServerConfig.Version)
			delete = false
			continue
		}
		logger.Log(1, "network:", node.Network, "node created on remote server...updating configs")
		if config.Netclient().Debug {
			pretty.Println(joinResponse)
			log.Println(joinResponse.Node.ID)
		}
		// reset attributes that should not be changed by server
		config.UpdateServerConfig(&joinResponse.ServerConfig)
		server := config.GetServer(joinResponse.ServerConfig.Server)
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
		config.UpdateNodeMap(newNode.Network, newNode)
		config.UpdateServer(newNode.Server, *server)
		if err := config.SaveServer(newNode.Server, *server); err != nil {
			logger.Log(0, "failed to save server", err.Error())
		}
		if err := config.WriteNetclientConfig(); err != nil {
			logger.Log(0, "error saving netclient config", err.Error())
		}
		if config.Netclient().Debug {
			pretty.Println(newNode)
			log.Println(newNode.ID)
			pretty.Println(config.Nodes)
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
