package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/devilcove/httpclient"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/models"
	"gopkg.in/yaml.v3"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// ClientConfig - struct for dealing with client configuration
type ClientConfig struct {
	Server          OldNetmakerServerConfig `yaml:"server"`
	Node            models.LegacyNode       `yaml:"node"`
	NetworkSettings models.Network          `yaml:"networksettings"`
	Network         string                  `yaml:"network"`
	Daemon          string                  `yaml:"daemon"`
	OperatingSystem string                  `yaml:"operatingsystem"`
	AccessKey       string                  `yaml:"accesskey"`
	PublicIPService string                  `yaml:"publicipservice"`
	SsoServer       string                  `yaml:"sso"`
}

// ReadConfig - reads a config of a older version of client from disk for specified network
func ReadConfig(network string) (*ClientConfig, error) {
	if network == "" {
		err := errors.New("no network provided - exiting")
		return nil, err
	}
	home := GetNetclientPath() + "config/"
	if ncutils.IsWindows() {
		//for some reason windows does not use the config dir although it exists
		home = GetNetclientPath()
	}
	file := fmt.Sprintf(home + "netconfig-" + network)
	log.Println("processing ", file)
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var cfg ClientConfig
	decoder := yaml.NewDecoder(f)
	err = decoder.Decode(&cfg)
	if err != nil {
		return nil, err
	}
	return &cfg, err
}

// GetSystemNetworks - get networks for older version (pre v0.18.0) of netclient
func GetSystemNetworks() ([]string, error) {
	var networks []string
	confPath := GetNetclientPath() + "config/netconfig-*"
	if ncutils.IsWindows() {
		//for some reason windows does not use the config dir although it exists
		confPath = GetNetclientPath() + "netconfig-*"
	}
	files, err := filepath.Glob(confPath)
	if err != nil {
		return nil, err
	}
	for _, file := range files {
		//don't want files such as *.bak, *.swp
		if filepath.Ext(file) != "" {
			continue
		}
		file := filepath.Base(file)
		temp := strings.Split(file, "-")
		networks = append(networks, strings.Join(temp[1:], "-"))
	}
	return networks, nil
}

// OldAuthenticate authenticates with netmaker api to permit subsequent interactions with the api
func OldAuthenticate(node *Node, host *Config) (string, error) {
	pass, err := os.ReadFile(GetNetclientPath() + "config/secret-" + node.Network)
	if err != nil {
		return "", fmt.Errorf("could not read secrets file %w", err)
	}
	data := models.AuthParams{
		MacAddress: host.MacAddress.String(),
		ID:         node.ID.String(),
		Password:   string(pass),
	}
	server := GetServer(node.Server)
	endpoint := httpclient.Endpoint{
		URL:    "https://" + server.API,
		Route:  "/api/nodes/adm/" + node.Network + "/authenticate",
		Method: http.MethodPost,
		Data:   data,
	}
	response, err := endpoint.GetResponse()
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		bodybytes, _ := io.ReadAll(response.Body)
		return "", fmt.Errorf("failed to authenticate %s %s", response.Status, string(bodybytes))
	}
	resp := models.SuccessResponse{}
	if err := json.NewDecoder(response.Body).Decode(&resp); err != nil {
		return "", fmt.Errorf("error decoding respone %w", err)
	}
	tokenData := resp.Response.(map[string]interface{})
	token := tokenData["AuthToken"]
	return token.(string), nil
}

// ConvertOldServerCfg converts a netmaker ServerConfig to netclient server struct
func ConvertOldServerCfg(cfg *models.ServerConfig) *Server {
	var server Server
	serverName := strings.Replace(cfg.Server, "broker.", "", 1)
	server.Name = serverName
	server.Version = cfg.Version
	server.Broker = cfg.Server
	server.MQPort = cfg.MQPort
	server.MQID = netclient.ID
	server.API = cfg.API
	server.CoreDNSAddr = cfg.CoreDNSAddr
	server.IsPro = cfg.IsPro
	server.StunList = cfg.StunList
	server.StunPort = cfg.StunPort
	server.DNSMode = cfg.DNSMode
	server.Nodes = make(map[string]bool)
	return &server
}
