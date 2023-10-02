// Package config provides functions for reading the config.
package config

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	"gopkg.in/yaml.v3"
)

var serverCtxFile = ".serverctx"

// CurrServer - holds the value of current server of client
var CurrServer string

// Servers is map of servers indexed by server name
var Servers map[string]Server

// ServerLockFile is a lockfile for controlling access to the server map file on disk
const ServerLockfile = "netclient-servers.lck"

// Server represents a server configuration
type Server struct {
	models.ServerConfig
	Name      string          `json:"name" yaml:"name"`
	MQID      uuid.UUID       `json:"mqid" yaml:"mqid"`
	Nodes     map[string]bool `json:"nodes" yaml:"nodes"`
	AccessKey string          `json:"accesskey" yaml:"accesskey"`
}

// OldNetmakerServerConfig - pre v0.18.0 server configuration
type OldNetmakerServerConfig struct {
	CoreDNSAddr string `yaml:"corednsaddr"`
	API         string `yaml:"api"`
	APIPort     string `yaml:"apiport"`
	ClientMode  string `yaml:"clientmode"`
	DNSMode     string `yaml:"dnsmode"`
	Version     string `yaml:"version"`
	MQPort      string `yaml:"mqport"`
	Server      string `yaml:"server"`
	Is_EE       bool   `yaml:"isee"`
}

// TurnConfig - struct to hold turn server config
type TurnConfig struct {
	Server string
	Domain string
	Port   int
}

// ReadServerConf reads the servers configuration file and populates the server map
func ReadServerConf() error {
	lockfile := filepath.Join(os.TempDir(), ServerLockfile)
	file := GetNetclientPath() + "servers.yml"
	if err := Lock(lockfile); err != nil {
		return err
	}
	defer Unlock(lockfile)
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	for k := range Servers {
		delete(Servers, k)
	}
	if err := yaml.NewDecoder(f).Decode(&Servers); err != nil {
		return err
	}
	return nil
}

// WriteServerConfig writes server map to disk
func WriteServerConfig() error {
	lockfile := filepath.Join(os.TempDir(), ServerLockfile)
	file := GetNetclientPath() + "servers.yml"
	if _, err := os.Stat(file); err != nil {
		if os.IsNotExist(err) {
			if err := os.MkdirAll(GetNetclientPath(), os.ModePerm); err != nil {
				return err
			}
			if err := os.Chmod(GetNetclientPath(), 0775); err != nil {
				logger.Log(0, "Error setting permissions on "+GetNetclientPath(), err.Error())
			}
		} else if err != nil {
			return err
		}
	}
	if err := Lock(lockfile); err != nil {
		return err
	}
	defer Unlock(lockfile)
	f, err := os.OpenFile(file, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0700)
	if err != nil {
		return err
	}
	defer f.Close()
	err = yaml.NewEncoder(f).Encode(Servers)
	if err != nil {
		return err
	}
	return f.Sync()
}

// SaveServer updates the server map with current server struct and writes map to disk
func SaveServer(name string, server Server) error {
	Servers[name] = server
	return WriteServerConfig()
}

// UpdateServer updates the in-memory server map
func UpdateServer(name string, server Server) {
	Servers[name] = server
}

// GetServer returns the server struct for the given server name
func GetServer(name string) *Server {
	if server, ok := Servers[name]; ok {
		return &server
	}
	return nil
}

// GetServers - gets all the server names host has registered to.
func GetServers() (servers []string) {
	for _, server := range Servers {
		servers = append(servers, server.Name)
	}
	return
}

// GetCurrServerCtxFromFile - gets current server context from file
func GetCurrServerCtxFromFile() (string, error) {
	d, err := os.ReadFile(filepath.Join(GetNetclientPath(), serverCtxFile))
	if err != nil {
		return "", err
	}
	return string(d), nil
}

// SetCurrServerCtxInFile - sets the current server context in the file
func SetCurrServerCtxInFile(server string) error {
	return os.WriteFile(filepath.Join(GetNetclientPath(), serverCtxFile), []byte(server), os.ModePerm)
}

// SetServerCtx - sets netclient's server context
func SetServerCtx() {
	// sets server context on startup
	setDefault := false
	currServer, err := GetCurrServerCtxFromFile()
	if err != nil || currServer == "" {
		setDefault = true
	} else {
		if GetServer(currServer) == nil {
			setDefault = true
		} else {
			CurrServer = currServer
		}

	}
	if setDefault {
		servers := GetServers()
		if len(servers) > 0 {
			CurrServer = servers[0]
			SetCurrServerCtxInFile(CurrServer)
		}
	}
}

// DeleteServer deletes the specified server name from the server map
func DeleteServer(k string) {
	delete(Servers, k)
}

// ConvertServerCfg converts a netmaker ServerConfig to netclient server struct
func ConvertServerCfg(cfg *OldNetmakerServerConfig) *Server {
	var server Server
	server.Name = strings.Replace(cfg.Server, "broker.", "", 1)
	server.Version = cfg.Version
	server.Broker = cfg.Server
	server.MQPort = cfg.MQPort
	server.MQID = netclient.ID
	server.API = cfg.API
	server.CoreDNSAddr = cfg.CoreDNSAddr
	server.IsPro = cfg.Is_EE
	server.DNSMode = cfg.DNSMode
	server.Nodes = make(map[string]bool)
	return &server
}

// UpdateServerConfig updates the in memory server map with values provided from netmaker server
func UpdateServerConfig(cfg *models.ServerConfig) {
	if cfg == nil {
		return
	}
	server, ok := Servers[cfg.Server]
	if !ok {
		server = Server{}
		server.Nodes = make(map[string]bool)
	}
	server.Name = cfg.Server
	server.MQID = netclient.ID
	server.ServerConfig = *cfg

	Servers[cfg.Server] = server
}

// GetAllTurnConfigs - fetches all turn configs from all servers
func GetAllTurnConfigs() (turnList []TurnConfig) {
	turnMap := make(map[string]struct{})
	server := GetServer(CurrServer)
	if server == nil || !server.UseTurn {
		return
	}
	if _, ok := turnMap[server.TurnDomain]; !ok {
		turnList = append(turnList, TurnConfig{
			Server: CurrServer,
			Domain: server.TurnDomain,
			Port:   server.TurnPort,
		})
		turnMap[server.TurnDomain] = struct{}{}
	}

	return
}
