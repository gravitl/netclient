package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/devilcove/httpclient"
	"github.com/google/uuid"
	"github.com/gravitl/netmaker/models"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"gopkg.in/yaml.v3"
)

// ClientConfig - struct for dealing with client configuration
type ClientConfig struct {
	Server          models.ServerConfig `yaml:"server"`
	Node            models.LegacyNode   `yaml:"node"`
	NetworkSettings models.Network      `yaml:"networksettings"`
	Network         string              `yaml:"network"`
	Daemon          string              `yaml:"daemon"`
	OperatingSystem string              `yaml:"operatingsystem"`
	AccessKey       string              `yaml:"accesskey"`
	PublicIPService string              `yaml:"publicipservice"`
	SsoServer       string              `yaml:"sso"`
}

// ReadConfig - reads a config of a older version of client from disk for specified network
func ReadConfig(network string) (*ClientConfig, error) {
	if network == "" {
		err := errors.New("no network provided - exiting")
		return nil, err
	}
	home := GetNetclientPath() + "config/"
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
	files, err := filepath.Glob(GetNetclientPath() + "config/netconfig-*")
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

// ConvertOldNode accepts a netmaker node struct and converts to the structs used by netclient
func ConvertOldNode(nodeGet *models.NodeGet) (*Node, *Server, *Config) {
	var node Node
	host := Netclient()
	netmakerNode := nodeGet.Node
	//server := GetServer(netmakerNode.Server)
	//if server == nil {
	server := ConvertOldServerCfg(&nodeGet.ServerConfig)
	//}
	node.ID, _ = uuid.Parse(netmakerNode.ID)
	//n.Name = s.Name
	node.Network = netmakerNode.Network
	//node.Password = netmakerNode.Password
	server.AccessKey = netmakerNode.AccessKey
	node.NetworkRange = ToIPNet(netmakerNode.NetworkSettings.AddressRange)
	node.NetworkRange6 = ToIPNet(netmakerNode.NetworkSettings.AddressRange6)
	node.InternetGateway = ToUDPAddr(netmakerNode.InternetGateway)
	host.Interfaces = netmakerNode.Interfaces
	host.ProxyEnabled = netmakerNode.Proxy
	//n.Interface = s.Interface
	node.Server = server.Name
	server.TrafficKey = netmakerNode.TrafficKeys.Server
	host.EndpointIP = net.ParseIP(netmakerNode.Endpoint)
	node.Connected = ParseBool(netmakerNode.Connected)
	//node.MacAddress, _ = net.ParseMAC(netmakerNode.MacAddress)
	host.ListenPort = int(netmakerNode.ListenPort)
	host.MTU = int(netmakerNode.MTU)
	host.PublicKey, _ = wgtypes.ParseKey(netmakerNode.PublicKey)

	// node settings
	node.ID, _ = uuid.Parse(netmakerNode.ID)
	node.Network = netmakerNode.Network
	node.NetworkRange = ToIPNet(netmakerNode.NetworkSettings.AddressRange)
	node.NetworkRange6 = ToIPNet(netmakerNode.NetworkSettings.AddressRange6)
	node.InternetGateway = ToUDPAddr(netmakerNode.InternetGateway)
	host.Interfaces = netmakerNode.Interfaces
	node.Server = server.Name
	host.EndpointIP = net.ParseIP(netmakerNode.Endpoint)
	node.Connected = ParseBool(netmakerNode.Connected)
	node.Address.IP = net.ParseIP(netmakerNode.Address)
	node.Address.Mask = node.NetworkRange.Mask
	node.Address6.IP = net.ParseIP(netmakerNode.Address6)
	node.Address6.Mask = node.NetworkRange6.Mask
	node.PersistentKeepalive = time.Second * time.Duration(netmakerNode.PersistentKeepalive)
	node.Action = netmakerNode.Action
	node.IsLocal = ParseBool(netmakerNode.IsLocal)
	node.IsEgressGateway = ParseBool(netmakerNode.IsEgressGateway)
	node.IsIngressGateway = ParseBool(netmakerNode.IsIngressGateway)
	host.IsStatic = ParseBool(netmakerNode.IsStatic)
	node.DNSOn = ParseBool(netmakerNode.DNSOn)
	//node.Peers = nodeGet.Peers
	//add items not provided by server
	return &node, server, host
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
	server.Password = netclient.HostPass
	server.API = cfg.API
	server.CoreDNSAddr = cfg.CoreDNSAddr
	server.Is_EE = cfg.Is_EE
	server.StunHost = cfg.StunHost
	server.StunPort = cfg.StunPort
	server.DNSMode = cfg.DNSMode
	server.Nodes = make(map[string]bool)
	return &server
}
