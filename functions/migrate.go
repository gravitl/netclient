package functions

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/devilcove/httpclient"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/daemon"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
)

// Migrate update data from older versions of netclient to new format
// TODO fix it
func Migrate() {
	delete := true
	config_dir := config.GetNetclientPath()
	if !ncutils.IsWindows() {
		config_dir += "config"
	}
	if _, err := os.Stat(config_dir); err != nil {
		//nothing to migrate ... exiting"
		return
	}
	logger.Log(0, "migration to v0.18 started")
	networks, err := config.GetSystemNetworks()
	if err != nil {
		fmt.Println("error reading network data ", err.Error())
		return
	}
	if len(networks) == 0 { // nothing to migrate
		return
	}
	logger.Log(0, "stopping daemon")
	if err := daemon.Stop(); err != nil {
		logger.Log(0, "failed to stop daemon", err.Error())
	}

	logger.Log(0, "networks to be migrated", strings.Join(networks, " "))
	var legacyNodes = []models.LegacyNode{}
	var servers = map[string]struct{}{}
	var newHost models.Host
	if config.Netclient().ListenPort == 0 {
		config.Netclient().ListenPort = 51821
	}
	if config.Netclient().ProxyListenPort == 0 {
		config.Netclient().ProxyListenPort = 51722
	}
	for _, network := range networks {
		logger.Log(0, "migrating", network)
		cfg, err := config.ReadConfig(network)
		if err != nil {
			logger.Log(0, "failed to read config for network", network, "skipping ...")
			continue
		}
		oldIface := cfg.Node.Interface
		secretPath := config.GetNetclientPath() + "config/secret-" + network
		if ncutils.IsWindows() {
			secretPath = config.GetNetclientPath() + "secret-" + network
		}
		pass, err := os.ReadFile(secretPath)
		if err != nil {
			logger.Log(0, "could not read secrets file", err.Error())
			continue
		}
		cfg.Node.Password = string(pass)
		legacyNodes = append(legacyNodes, cfg.Node)
		node, netclient := config.ConvertOldNode(&cfg.Node)
		node.Server = strings.Replace(cfg.Server.Server, "broker.", "", 1)
		servers[cfg.Server.API] = struct{}{}
		newHost, _ = config.Convert(netclient, node)
		newHost.PublicKey = netclient.PrivateKey.PublicKey()
		ip, err := getInterfaces()
		if err != nil {
			logger.Log(0, "failed to retrieve local interfaces", err.Error())
		} else {
			if ip != nil {
				newHost.Interfaces = *ip
			}
		}
		defaultInterface, err := getDefaultInterface()
		if err != nil {
			logger.Log(0, "default gateway not found", err.Error())
		} else {
			newHost.DefaultInterface = defaultInterface
		}
		wireguard.DeleteOldInterface(oldIface)
	}
	if newHost.ListenPort == 0 {
		newHost.ListenPort = config.Netclient().ListenPort
	}
	if newHost.ProxyListenPort == 0 {
		newHost.ProxyListenPort = config.Netclient().ProxyListenPort
	}
	var serversToWrite = []models.ServerConfig{}
	var hostToWrite *models.Host
	for k := range servers {
		server := k
		logger.Log(0, "migrating for server", server)
		migrationData := models.MigrationData{
			LegacyNodes: legacyNodes,
			NewHost:     newHost,
		}
		api := httpclient.JSONEndpoint[models.RegisterResponse, models.ErrorResponse]{
			URL:    "https://" + server,
			Route:  "/api/v1/nodes/migrate",
			Method: http.MethodPost,
			Headers: []httpclient.Header{
				{
					Name:  "requestfrom",
					Value: "node",
				},
			},
			Data:          migrationData,
			Response:      models.RegisterResponse{},
			ErrorResponse: models.ErrorResponse{},
		}
		migrateResponse, errData, err := api.GetJSON(models.RegisterResponse{}, models.ErrorResponse{})
		if err != nil {
			logger.Log(0, "err migrating data", err.Error())
			if errors.Is(err, httpclient.ErrStatus) {
				logger.Log(0, "error migrating server", server, strconv.Itoa(errData.Code), errData.Message)
				delete = false
				continue
			}
		}
		if !IsVersionComptatible(migrateResponse.ServerConf.Version) {
			logger.Log(0, "incompatible server version", migrateResponse.ServerConf.Version)
			delete = false
			continue
		}
		serversToWrite = append(serversToWrite, migrateResponse.ServerConf)
		newHost.ListenPort = migrateResponse.RequestedHost.ListenPort
		newHost.ProxyListenPort = migrateResponse.RequestedHost.ProxyListenPort
		if hostToWrite == nil || newHost.ListenPort != hostToWrite.ListenPort {
			config.Netclient().ListenPort = newHost.ListenPort
			config.Netclient().ProxyListenPort = newHost.ProxyListenPort
		}
	}

	for i := range legacyNodes {
		network := legacyNodes[i].Network
		_ = removeHostDNS(network) // remove old DNS
	}

	if delete {
		logger.Log(3, "removing old config files")
		if err := os.RemoveAll(config.GetNetclientPath()); err != nil {
			logger.Log(0, "failed to delete old configuration files ", err.Error())
		}
	}

	for i := range serversToWrite {
		serverValue := serversToWrite[i]
		config.UpdateServerConfig(&serverValue)
		newServerConfig := config.GetServer(serverValue.Server)
		config.UpdateServer(serverValue.Server, *newServerConfig)
		if err := config.SaveServer(serverValue.Server, *newServerConfig); err != nil {
			logger.Log(0, "failed to save server", err.Error())
		} else {
			logger.Log(0, "saved server", serverValue.Server)
		}
	}

	if config.Netclient().ListenPort == 0 {
		config.Netclient().ListenPort = 51821
	}
	if config.Netclient().ProxyListenPort == 0 {
		config.Netclient().ProxyListenPort = 51722
	}

	if err := config.WriteNetclientConfig(); err != nil {
		logger.Log(0, "error saving netclient config during migrate", err.Error())
	}

	_ = daemon.Restart()
}
