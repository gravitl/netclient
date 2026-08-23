// Package config provides functions for reading the config.
package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/gravitl/netmaker/models"
	"golang.org/x/exp/slog"
)

var serverMutex sync.RWMutex

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
	Name           string              `json:"name" yaml:"name"`
	MQID           uuid.UUID           `json:"mqid" yaml:"mqid"`
	Nodes          map[string]bool     `json:"nodes" yaml:"nodes"`
	AccessKey      string              `json:"accesskey" yaml:"accesskey"`
	NameServers    []string            `json:"name_servers"`
	DnsNameservers []models.Nameserver `json:"dns_nameservers"`
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
	serversI = migrateServersMapKeys(serversI)
	return nil
}

// migrateServersMapKeys rewrites legacy host:port map keys to bare domain.
func migrateServersMapKeys(in map[string]Server) map[string]Server {
	if len(in) == 0 {
		return in
	}
	out := make(map[string]Server, len(in))
	for key, server := range in {
		nk := NormalizeServerHost(key)
		if nk == "" {
			nk = key
		}
		server.Name = nk
		if server.API != "" {
			server.API = NormalizeServerAPI(server.API)
		}
		if server.Server != "" {
			server.Server = NormalizeServerHost(server.Server)
		}
		if existing, ok := out[nk]; ok {
			// Prefer the entry that is fully registered (Server set) or has more nodes.
			if existing.Server != "" && server.Server == "" {
				continue
			}
			if existing.Server == "" && server.Server != "" {
				out[nk] = server
				continue
			}
			if len(existing.Nodes) >= len(server.Nodes) {
				if existing.API == "" && server.API != "" {
					existing.API = server.API
					out[nk] = existing
				}
				continue
			}
		}
		out[nk] = server
	}
	return out
}

// WriteServerConfig writes server map to disk
func WriteServerConfig() error {
	serverMutex.Lock()
	defer serverMutex.Unlock()
	return WriteJSONAtomic(
		filepath.Join(GetNetclientPath(), "servers.json"),
		Servers,
		filepath.Join(os.TempDir(), ServerLockfile),
		0700,
	)
}

// SaveServer updates the server map with current server struct and writes map to disk
func SaveServer(name string, server Server) error {
	serverMutex.Lock()
	Servers[name] = server
	serverMutex.Unlock()
	return WriteServerConfig()
}

// UpdateServer updates the in-memory server map
func UpdateServer(name string, server Server) {
	serverMutex.Lock()
	defer serverMutex.Unlock()
	Servers[name] = server
}

// GetServer returns the server struct for the given server name
func GetServer(name string) *Server {
	server, _ := ResolveServer(name)
	return server
}

// ResolveServerKey returns the servers.json map key for the given identifier.
func ResolveServerKey(id string) string {
	_, key := ResolveServer(id)
	return key
}

// ResolveServer finds a server by map key or by API/Name/Server fields.
// The returned key is always a bare domain (no port) for MQTT / .serverctx identity.
func ResolveServer(id string) (*Server, string) {
	id = normalizeServerID(id)
	serverMutex.RLock()
	defer serverMutex.RUnlock()
	if id != "" {
		if server, ok := Servers[id]; ok {
			return copyServerPtr(server), NormalizeServerHost(id)
		}
		for key, server := range Servers {
			if serverIdentifierMatches(server, id) {
				return copyServerPtr(server), NormalizeServerHost(key)
			}
		}
		if !strings.HasPrefix(id, "api.") {
			if server, ok := Servers["api."+id]; ok {
				return copyServerPtr(server), "api." + id
			}
		}
	}
	if len(Servers) == 1 {
		for key, server := range Servers {
			return copyServerPtr(server), NormalizeServerHost(key)
		}
	}
	return nil, ""
}

func copyServerPtr(server Server) *Server {
	s := server
	return &s
}

// NormalizeServerHost returns a server identity with no scheme and no port.
// Used for .serverctx, servers.json keys, Name, and MQTT topics.
func NormalizeServerHost(id string) string {
	id = stripServerInput(id)
	if id == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(id); err == nil {
		return host
	}
	if strings.HasPrefix(id, "[") && strings.HasSuffix(id, "]") {
		return strings.Trim(id, "[]")
	}
	return id
}

// NormalizeServerAPI returns host:port for HTTPS API calls.
// If the input has no port, :443 is appended.
func NormalizeServerAPI(id string) string {
	id = stripServerInput(id)
	if id == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(id); err == nil {
		return id
	}
	if strings.HasPrefix(id, "[") && strings.HasSuffix(id, "]") {
		return id + ":443"
	}
	return id + ":443"
}

// APIBaseURL returns https://<api> where api is host:port.
func APIBaseURL(api string) string {
	api = strings.TrimSpace(api)
	api = strings.TrimPrefix(api, "https://")
	api = strings.TrimPrefix(api, "http://")
	if api == "" {
		return ""
	}
	return "https://" + api
}

func stripServerInput(id string) string {
	id = strings.TrimSpace(id)
	id = strings.TrimPrefix(id, "https://")
	id = strings.TrimPrefix(id, "http://")
	if i := strings.Index(id, "/"); i >= 0 {
		id = id[:i]
	}
	return strings.TrimSuffix(id, "/")
}

func normalizeServerID(id string) string {
	return NormalizeServerHost(id)
}

func serverIdentifierMatches(srv Server, id string) bool {
	id = NormalizeServerHost(id)
	if id == "" {
		return false
	}
	for _, candidate := range []string{srv.Name, srv.Server, srv.API} {
		if NormalizeServerHost(candidate) == id {
			return true
		}
	}
	return false
}

func canonicalServerKey(values ...string) string {
	for _, value := range values {
		if id := NormalizeServerHost(value); id != "" {
			return id
		}
	}
	return ""
}

// UpsertPartialServer stores domain identity + API host:port before full registration.
// Leaves ServerConfig.Server empty so IsRegisteredToServer stays false until register.
// domain is stored without a leading "api." label (Name / map key); api keeps the full API host.
func UpsertPartialServer(domain, api string) error {
	domain = NormalizeServerHost(domain)
	domain = strings.TrimPrefix(domain, "api.")
	api = NormalizeServerAPI(api)
	if domain == "" || api == "" {
		return fmt.Errorf("server domain and API are required")
	}
	serverMutex.Lock()
	existing, ok := Servers[domain]
	if !ok {
		existing = Server{Nodes: make(map[string]bool)}
	}
	existing.Name = domain
	existing.API = api
	if host, _, err := net.SplitHostPort(api); err == nil {
		existing.APIHost = host
	} else {
		existing.APIHost = api
	}
	Servers[domain] = existing
	// Drop legacy host:port keys for the same domain.
	for key := range Servers {
		if key != domain && NormalizeServerHost(key) == domain {
			delete(Servers, key)
		}
	}
	serverMutex.Unlock()
	return WriteServerConfig()
}

// AlignCurrServer sets CurrServer to the resolved servers.json key when possible.
func AlignCurrServer() {
	if _, key := ResolveServer(CurrServer); key != "" {
		if CurrServer != key {
			CurrServer = key
			_ = SetCurrServerCtxInFile(key)
		}
		return
	}
	serverMutex.RLock()
	var onlyKey string
	for key := range Servers {
		onlyKey = key
		break
	}
	serverMutex.RUnlock()
	if onlyKey != "" {
		CurrServer = onlyKey
		_ = SetCurrServerCtxInFile(onlyKey)
	}
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
	for key := range Servers {
		servers = append(servers, key)
	}
	return
}

// GetCurrServerCtxFromFile - gets current server context from file
func GetCurrServerCtxFromFile() (string, error) {
	d, err := os.ReadFile(filepath.Join(GetNetclientPath(), serverCtxFile))
	if err != nil {
		return "", err
	}
	return normalizeServerID(string(d)), nil
}

// SetCurrServerCtxInFile - sets the current server context in the file
func SetCurrServerCtxInFile(server string) error {
	return os.WriteFile(filepath.Join(GetNetclientPath(), serverCtxFile), []byte(server), os.ModePerm)
}

// SetServerCtx - sets netclient's server context
func SetServerCtx() {
	currServer, err := GetCurrServerCtxFromFile()
	if err == nil && currServer != "" {
		if _, key := ResolveServer(currServer); key != "" {
			CurrServer = key
			if key != currServer {
				_ = SetCurrServerCtxInFile(key)
			}
			return
		}
	}
	AlignCurrServer()
}

// DeleteServer deletes the specified server name from the server map
func DeleteServer(k string) {
	serverMutex.Lock()
	defer serverMutex.Unlock()
	delete(Servers, k)
}

// UpdateServerConfig updates the in memory server map with values provided from netmaker server
func UpdateServerConfig(cfg *models.ServerConfig) {
	serverMutex.Lock()
	defer serverMutex.Unlock()
	if cfg == nil {
		return
	}
	key := canonicalServerKey(CurrServer, cfg.Server, cfg.API)
	if key == "" {
		return
	}
	cfg.Server = key
	server, ok := Servers[key]
	if !ok {
		for existingKey, existing := range Servers {
			if !serverIdentifierMatches(existing, key) {
				continue
			}
			server = existing
			ok = true
			// Migrate off legacy host:port map keys.
			if existingKey != key {
				delete(Servers, existingKey)
			}
			break
		}
	}
	if !ok {
		server = Server{}
		server.Nodes = make(map[string]bool)
	}
	api := NormalizeServerAPI(cfg.API)
	if api == "" {
		api = NormalizeServerAPI(server.API)
	}
	if api == "" {
		api = NormalizeServerAPI(key)
	}
	// Prefer existing host:port when register response returns bare host.
	if server.API != "" && NormalizeServerHost(server.API) == NormalizeServerHost(api) {
		api = NormalizeServerAPI(server.API)
	}
	cfg.API = api
	server.Name = key
	server.MQID = netclient.ID
	server.ServerConfig = *cfg
	Servers[key] = server
}

func SwitchToRemainingServer() {
	for _, name := range GetServers() {
		srvCfg := GetServer(name)
		if srvCfg == nil {
			continue
		}
		_ = SetCurrServerCtxInFile(name)
		CurrServer = name
		SetNetclientServerContext(srvCfg.MQID, srvCfg.TenantID)
		slog.Info("switched netclient server context", "server", name)
		return
	}

	// no servers left to switch to; clear the stale context
	_ = SetCurrServerCtxInFile("")
	CurrServer = ""
	SetNetclientServerContext(uuid.Nil, "")
}
