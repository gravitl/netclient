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
	Name        string
	Version     string
	API         string
	CoreDNSAddr string
	Broker      string
	MQPort      string
	MQID        string
	Password    string
	DNSMode     bool
	IsEE        bool
	Nodes       map[string]bool
	TrafficKey  []byte
	AccessKey   string
}

// ReadServerConf reads the servers configuration file and populates the server map
func ReadServerConf() error {
	lockfile := filepath.Join(os.TempDir()) + ServerLockfile
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
	if err := yaml.NewDecoder(f).Decode(&Servers); err != nil {
		return err
	}
	return nil
}

// WriteServerConfig writes server map to disk
func WriteServerConfig() error {
	lockfile := filepath.Join(os.TempDir()) + ServerLockfile
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
func GetServer(network string) *Server {
	if server, ok := Servers[network]; ok {
		return &server
	}
	return nil
}

// ConvertServerCfg converts a netmaker ServerConfig to netclient server struct
func ConvertServerCfg(cfg *models.ServerConfig) *Server {
	var server Server
	server.Name = cfg.Server
	server.Version = cfg.Version
	server.Broker = cfg.Broker
	server.MQPort = cfg.MQPort
	server.MQID = Netclient.HostID
	server.Password = Netclient.HostPass
	server.API = cfg.API
	server.CoreDNSAddr = cfg.CoreDNSAddr
	server.IsEE = cfg.Is_EE
	server.DNSMode, _ = strconv.ParseBool(cfg.DNSMode)
	return &server
}
