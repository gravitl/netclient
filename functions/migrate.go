package functions

import (
	"errors"
	"net/http"
	"os"
	"runtime"
	"strings"

	"github.com/devilcove/httpclient"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/daemon"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/models"
	"golang.org/x/exp/slog"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Migrate update data from older versions of netclient to new format
func Migrate() {
	servers := make(map[string][]models.LegacyNode)
	slog.Debug("migration func")
	delete := true
	hostname, err := os.Hostname()
	if err != nil {
		slog.Warn("set hostname", "error", err)
	}
	config_dir := config.GetNetclientPath() + "config/"
	if _, err := os.Stat(config_dir); err != nil {
		//nothing to migrate ... exiting"
		return
	}
	networks, err := config.GetSystemNetworks()
	if err != nil {
		slog.Error("reading network data", "error", err)
		return
	}
	if len(networks) == 0 { // nothing to migrate
		slog.Warn("no networks, nothing to migrate")
		return
	}
	slog.Info("stopping daemon")
	if err := daemon.Stop(); err != nil {
		slog.Warn("stopping daemon failed", "error", err)
	}

	slog.Info("networks to be migrated " + strings.Join(networks, " "))

	for _, network := range networks {
		slog.Info("migrating " + network)
		if err := removeHostDNS(network); err != nil {
			slog.Error("remove host DNS", "error", err)
		}
		cfg, err := config.ReadConfig(network)
		if err != nil {
			slog.Error("skipping network, could not read config", "network", network, "error", err)
			continue
		}
		serverName := strings.Replace(cfg.Server.Server, "broker.", "", 1)
		oldIface := cfg.Node.Interface
		secretPath := config.GetNetclientPath() + "config/secret-" + network
		if ncutils.IsWindows() {
			secretPath = config.GetNetclientPath() + "secret-" + network
		}
		pass, err := os.ReadFile(secretPath)
		if err != nil {
			slog.Error("read secrets file", "error", err)
			continue
		}
		cfg.Node.Password = string(pass)
		cfg.Node.Server = serverName
		wireguard.DeleteOldInterface(oldIface)
		nodes := servers[serverName]
		servers[serverName] = append(nodes, cfg.Node)
	}
	hostSet := false
	for k, v := range servers {
		//server := k
		slog.Info("server migration", "server", k)
		migrationData := models.MigrationData{
			HostName:    hostname,
			Password:    v[0].Password,
			OS:          runtime.GOOS,
			LegacyNodes: v,
		}
		api := httpclient.JSONEndpoint[models.HostPull, models.ErrorResponse]{
			URL:    "https://api." + k,
			Route:  "/api/v1/nodes/migrate",
			Method: http.MethodPost,
			Headers: []httpclient.Header{
				{
					Name:  "requestfrom",
					Value: "node",
				},
			},
			Data:          migrationData,
			Response:      models.HostPull{},
			ErrorResponse: models.ErrorResponse{},
		}
		migrateResponse, errData, err := api.GetJSON(models.HostPull{}, models.ErrorResponse{})
		if err != nil {
			slog.Error("migration response", "error", err)
			if errors.Is(err, httpclient.ErrStatus) {
				slog.Error("status error", "code", errData.Code, "message", errData.Message)
			}
			delete = false
			continue
		}
		if !IsVersionComptatible(migrateResponse.ServerConfig.Version) {
			slog.Error("incompatible server version", "server", migrateResponse.ServerConfig.Version, "client", config.Netclient().Version)
			delete = false
			continue
		}
		if len(migrateResponse.Nodes) == 0 {
			slog.Error("no nodes returned")
			delete = false
			continue
		}
		if !hostSet {
			slog.Info("setting host")
			netclient := config.Netclient()
			netclient.Host = migrateResponse.Host
			netclient.PrivateKey = getWGPrivateKey(migrateResponse.Nodes[0].Network)
			netclient.TrafficKeyPrivate = getOldTrafficKey(migrateResponse.Nodes[0].Network)
			netclient.HostPass = getOldPassword(migrateResponse.Nodes[0].Network)

			if err := config.WriteNetclientConfig(); err != nil {
				slog.Error("write config", "error", err)
			}
			hostSet = true
		}
		slog.Info("updating server config")
		config.SaveServer(k, config.Server{
			ServerConfig: migrateResponse.ServerConfig,
			Name:         k,
			MQID:         migrateResponse.Host.ID,
		})
		slog.Info("updating node")
		config.SetNodes(migrateResponse.Nodes)
		if err := config.WriteNodeConfig(); err != nil {
			slog.Error("save node config", "error", err)
		}
		slog.Info("publish host update", "server", k, "update", models.UpdateHost)
		server := config.GetServer(k)
		if err := setupMQTTSingleton(server, true); err != nil {
			slog.Error("mqtt setup", "error", err)
			continue
		}
		if err := PublishHostUpdate(k, models.UpdateHost); err != nil {
			slog.Error("pub host update", "server", k, "error", err)
		}
	}

	if delete {
		if ncutils.IsWindows() {
			moveWindowsFiles()
		} else {
			slog.Info("removing old config files")
			if err := os.Rename(config.GetNetclientPath()+"/config", config.GetNetclientPath()+"/config.old"); err != nil {
				//if err := os.RemoveAll(config.GetNetclientPath()); err != nil {
				slog.Error("deleting config files", "error", err)
			}
		}
	}

	_ = daemon.Restart()
}

func getWGPrivateKey(network string) wgtypes.Key {
	keypath := config.GetNetclientPath() + "config/wgkey-" + network
	if ncutils.IsWindows() {
		keypath = config.GetNetclientPath() + "wgkey-" + network
	}
	data, err := os.ReadFile(keypath)
	if err != nil {
		slog.Error("read wireguard key", "error", err)
		return wgtypes.Key{}
	}
	key, err := wgtypes.ParseKey(string(data))
	if err != nil {
		slog.Error("parse key", "error", err)
		return wgtypes.Key{}
	}
	return key
}

func getOldTrafficKey(network string) []byte {
	trafficpath := config.GetNetclientPath() + "config/traffic-" + network
	if ncutils.IsWindows() {
		trafficpath = config.GetNetclientPath() + "traffic-" + network
	}
	data, err := os.ReadFile(trafficpath)
	if err != nil {
		slog.Error("read old traffic key", "error", err)
	}
	return data
}

func getOldPassword(network string) string {
	passpath := config.GetNetclientPath() + "config/secret-" + network
	if ncutils.IsWindows() {
		passpath = config.GetNetclientPath() + "secret-" + network
	}
	data, err := os.ReadFile(passpath)
	if err != nil {
		slog.Error("read password", "error", err)
	}
	return string(data)
}

func moveWindowsFiles() {
	//move all v0.17.1 config files to config dir so that it is the same as other os's
	path := config.GetNetclientPath()
	configPath := path + "config.old"
	if err := os.MkdirAll(configPath, 0755); err != nil {
		slog.Error("mkdir", "error", err)
		return
	}
	dir, err := os.ReadDir(path)
	if err != nil {
		slog.Error("read dir", "error", err)
		return
	}
	for _, entry := range dir {
		if strings.Contains(entry.Name(), "netconfig-") {
			if err := os.Rename(path+entry.Name(), configPath+"\\"+entry.Name()); err != nil {
				slog.Error("rename netconfig", "error", err)
			}
		}
		if strings.Contains(entry.Name(), "secret-") {
			if err := os.Rename(path+entry.Name(), configPath+"\\"+entry.Name()); err != nil {
				slog.Error("rename secret", "error", err)
			}
		}
		if strings.Contains(entry.Name(), "traffic-") {
			if err := os.Rename(path+entry.Name(), configPath+"\\"+entry.Name()); err != nil {
				slog.Error("rename traffic", "error", err)
			}
		}
		if strings.Contains(entry.Name(), "wgkey-") {
			if err := os.Rename(path+entry.Name(), configPath+"\\"+entry.Name()); err != nil {
				slog.Error("rename wgkey", "error", err)
			}
		}
	}
	os.Remove(path + "config")
	slog.Info("old config files backed up")
}
