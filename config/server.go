// Package config provides functions for reading the config.
package config

import (
	"os"
	"path/filepath"
	"strconv"

	"github.com/gravitl/netmaker/models"
	"gopkg.in/yaml.v3"
)

var Servers map[string]Server
var ServerNodes map[string]struct{}

const ServerLockfile = "netclient-servers.lck"

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
}

// ReadServerConf reads a server configuration file and returns it as a
// Server instance. If no configuration file is found, nil and no error will be
// returned. The configuration must live in one of the directories specified in
// with AddConfigPath()
//
// In case multiple configuration files are found, the one in the most specific
// or "closest" directory will be preferred.
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
