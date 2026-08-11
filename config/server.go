// Package config provides functions for reading the config.
package config

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"sync"

	"github.com/google/uuid"
	"github.com/gravitl/netmaker/models"
	"github.com/gravitl/netmaker/schema"
	"golang.org/x/exp/slog"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var serverMutex sync.RWMutex

var deletedServers = make(map[string]bool)

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
	HostIDs        map[string]uuid.UUID `json:"host_ids"`
	Name           string               `json:"name" yaml:"name"`
	Nodes          map[string]bool      `json:"nodes" yaml:"nodes"`
	AccessKey      string               `json:"accesskey" yaml:"accesskey"`
	NameServers    []string             `json:"name_servers"`
	DnsNameservers []models.Nameserver  `json:"dns_nameservers"`
}

// TurnConfig - struct to hold turn server config
type TurnConfig struct {
	Server string
	Domain string
	Port   int
}

// ReadServerConf reads the servers configuration file and populates the server map
func ReadServerConf() error {
	serversI := make(map[string]Server)
	var err error
	defer func() {
		if err == nil {
			serverMutex.Lock()
			Servers = serversI
			deletedServers = make(map[string]bool)
			serverMutex.Unlock()
		}
	}()
	lockfile := filepath.Join(os.TempDir(), ServerLockfile)
	file := GetNetclientPath() + "servers.json"
	if err = Lock(lockfile); err != nil {
		return err
	}
	defer Unlock(lockfile)
	f, ferr := os.Open(file)
	if ferr != nil {
		err = ferr
		return err
	}
	defer f.Close()
	if err = json.NewDecoder(f).Decode(&serversI); err != nil {
		return err
	}
	return nil
}

// WriteServerConfig writes server map to disk
func WriteServerConfig() error {
	serverMutex.Lock()
	defer serverMutex.Unlock()

	lockfile := filepath.Join(os.TempDir(), ServerLockfile)
	if err := Lock(lockfile); err != nil {
		return err
	}
	defer Unlock(lockfile)

	merged := make(map[string]Server)
	if f, err := os.Open(GetNetclientPath() + "servers.json"); err == nil {
		_ = json.NewDecoder(f).Decode(&merged)
		f.Close()
	}
	maps.Copy(merged, Servers)
	for k := range deletedServers {
		delete(merged, k)
	}
	Servers = merged
	deletedServers = make(map[string]bool)

	return writeJSONAtomicLocked(
		filepath.Join(GetNetclientPath(), "servers.json"),
		Servers,
		0700,
	)
}

// SaveServer updates the server map with current server struct and writes map to disk
func SaveServer(name string, server Server) error {
	serverMutex.Lock()
	Servers[name] = server
	delete(deletedServers, name)
	serverMutex.Unlock()
	return WriteServerConfig()
}

// UpdateServer updates the in-memory server map
func UpdateServer(name string, server Server) {
	serverMutex.Lock()
	defer serverMutex.Unlock()
	Servers[name] = server
	delete(deletedServers, name)
}

// GetServer returns the server struct for the given server name
func GetServer(name string) *Server {
	serverMutex.RLock()
	defer serverMutex.RUnlock()
	if server, ok := Servers[name]; ok {
		return &server
	}
	return nil
}

func GetServerByAPIHost(apiHost string) *Server {
	serverMutex.RLock()
	defer serverMutex.RUnlock()
	for _, server := range Servers {
		if server.APIHost == apiHost {
			return &server
		}
	}
	return nil
}

// GetServers - gets all the server names host has registered to.
func GetServers() (servers []string) {
	serverMutex.RLock()
	defer serverMutex.RUnlock()
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
		} else {
			CurrServer = ""
		}
	}
}

// DeleteServer deletes the specified server name from the server map
func DeleteServer(k string) {
	serverMutex.Lock()
	defer serverMutex.Unlock()
	delete(Servers, k)
	deletedServers[k] = true
}

// UpdateServerConfig updates the in memory server map with values provided from netmaker server
func UpdateServerConfig(cfg *models.ServerConfig, host *schema.Host) {
	serverMutex.Lock()
	defer serverMutex.Unlock()
	if cfg == nil {
		return
	}
	server, ok := Servers[cfg.Server]
	if !ok {
		server = Server{}
		server.Nodes = make(map[string]bool)
	}
	if server.HostIDs == nil {
		server.HostIDs = make(map[string]uuid.UUID)
	}
	server.HostIDs[host.TenantID] = host.ID
	server.Name = cfg.Server
	server.ServerConfig = *cfg
	Servers[cfg.Server] = server
	delete(deletedServers, cfg.Server)
}

func SwitchToRemainingServer(leftServer *Server, serverRemoved bool) {
	netclient := Netclient()

	if !serverRemoved {
		for tenantID, hostID := range leftServer.HostIDs {
			netclient.ID = hostID
			netclient.TenantID = tenantID
			netclient.HostPeers = []wgtypes.PeerConfig{}
			return
		}
	}

	for _, name := range GetServers() {
		srvCfg := GetServer(name)
		if srvCfg == nil || len(srvCfg.HostIDs) == 0 {
			continue
		}
		tenantID := srvCfg.TenantID
		hostID, ok := srvCfg.HostIDs[tenantID]
		if !ok {
			for tid, hid := range srvCfg.HostIDs {
				tenantID, hostID, ok = tid, hid, true
				break
			}
		}
		_ = SetCurrServerCtxInFile(name)
		CurrServer = name
		netclient.ID = hostID
		netclient.TenantID = tenantID
		netclient.HostPeers = []wgtypes.PeerConfig{}
		slog.Info("switched netclient server context", "server", name)
		return
	}

	// no servers left to switch to; clear the stale context
	_ = SetCurrServerCtxInFile("")
	netclient.ID = uuid.Nil
	netclient.TenantID = ""
}
