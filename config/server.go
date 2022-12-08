// Package config provides functions for reading the config.
package config

import (
	"os"
	"path/filepath"
	"strconv"

	"github.com/gravitl/netmaker/models"
	"gopkg.in/yaml.v3"
)

// Servers is map of servers indexed by server name
var Servers map[string]Server

// ServerNodes is a map of node names for a server
var ServerNodes map[string]struct{}

// ServerLockFile is a lockfile for controlling access to the server map file on disk
const ServerLockfile = "netclient-servers.lck"

// Server represents a server configuration
type Server struct {
	Name        string          `json:"name" yaml:"name"`
	Version     string          `json:"verson" yaml:"version"`
	API         string          `json:"api" yaml:"api"`
	CoreDNSAddr string          `json:"corednsaddress" yaml:"corednsaddress"`
	Broker      string          `json:"broker" yaml:"broker"`
	MQPort      string          `json:"mqport" yaml:"mqport"`
	MQID        string          `json:"mqid" yaml:"mqid"`
	Password    string          `json:"password" yaml:"password"`
	DNSMode     bool            `json:"dnsmode" yaml:"dnsmode"`
	IsEE        bool            `json:"isee" yaml:"isee"`
	Nodes       map[string]bool `json:"nodes" yaml:"nodes"`
	TrafficKey  []byte          `json:"traffickey" yaml:"traffickey"`
	AccessKey   string          `json:"accesskey" yaml:"accesskey"`
	StunPort    int             `json:"stun_port" yaml:"stun_port"`
	StunHost    string          `json:"stun_host" yaml:"stun_host"`
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
			os.MkdirAll(GetNetclientPath(), os.ModePerm)
		} else if err != nil {
			return err
		}
	}
	if err := Lock(lockfile); err != nil {
		return err
	}
	defer Unlock(lockfile)
	f, err := os.OpenFile(file, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.ModePerm)
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

// GetServer returns the server struct for the given server name
func GetServer(name string) *Server {
	if server, ok := Servers[name]; ok {
		return &server
	}
	return nil
}

// DeleteServer deletes the specified server name from the server map
func DeleteServer(k string) {
	delete(Servers, k)
}

// ConvertServerCfg converts a netmaker ServerConfig to netclient server struct
func ConvertServerCfg(cfg *models.ServerConfig) *Server {
	var server Server
	server.Name = cfg.Server
	server.Version = cfg.Version
	server.Broker = cfg.Broker
	server.MQPort = cfg.MQPort
	server.MQID = netclient.HostID
	server.Password = netclient.HostPass
	server.API = cfg.API
	server.CoreDNSAddr = cfg.CoreDNSAddr
	server.IsEE = cfg.Is_EE
	server.StunHost = cfg.StunHost
	server.StunPort = cfg.StunPort
	server.DNSMode, _ = strconv.ParseBool(cfg.DNSMode)
	server.Nodes = make(map[string]bool)
	return &server
}

// UpdateServerConfig updates the in memory server map with values provided from netmaker server
func UpdateServerConfig(cfg *models.ServerConfig) {
	server, ok := Servers[cfg.Server]
	if !ok {
		server = Server{}
		server.Nodes = make(map[string]bool)
	}
	server.Name = cfg.Server
	server.Version = cfg.Version
	server.Broker = cfg.Broker
	server.MQPort = cfg.MQPort
	server.MQID = netclient.HostID
	server.Password = netclient.HostPass
	server.API = cfg.API
	server.CoreDNSAddr = cfg.CoreDNSAddr
	server.IsEE = cfg.Is_EE
	server.DNSMode, _ = strconv.ParseBool(cfg.DNSMode)
	Servers[cfg.Server] = server
}
