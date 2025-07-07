// Package config provides functions for reading the config.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	"github.com/sasha-s/go-deadlock"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	// LinuxAppDataPath - linux path
	LinuxAppDataPath = "/etc/netclient/"
	// MacAppDataPath - mac path
	MacAppDataPath = "/Applications/Netclient/"
	// WindowsAppDataPath - windows path
	WindowsAppDataPath = "C:\\Program Files (x86)\\Netclient\\"
	// Timeout timelimit for obtaining/releasing lockfile
	Timeout = time.Second * 5
	// ConfigLockfile lockfile to control access to config file
	ConfigLockfile = "config.lck"
	// MaxNameLength maximum length of a node name
	MaxNameLength = 62
	// DefaultListenPort default port for wireguard
	DefaultListenPort = 51821
	// DefaultMTU default MTU for wireguard
	DefaultMTU = 1420
)

const (
	UnKnown InitType = iota
	Systemd
	SysVInit
	Runit
	OpenRC
	Initd
)

const (
	// DefaultHostID {0EF230F0-2EAD-4370-B0F9-AFC2D2A039E6} is a fixed string,
	// for creating the unique GUID. It's a meaningless unique GUID here to
	// make sure only one network profile is created.
	DefaultHostID = "0EF230F0-2EAD-4370-B0F9-AFC2D2A039E6"
)

// Initype - the type of init system in use
type InitType int

// String - returns the string representation of the init type
func (i InitType) String() string {
	return [...]string{"unknown", "systemd", "sysvinit", "runit", "openrc", "initd"}[i]
}

var (
	netclientCfgMutex = &deadlock.RWMutex{}
	netclient         Config // netclient contains the netclient config
	// Version - default version string
	Version = "dev"
	// FwClose - firewall manager shutdown func
	FwClose func() = func() {}
	// WgPublicListenPort - host's wireguard public listen port
	WgPublicListenPort int
	// HostPublicIP - host's public ipv4 endpoint
	HostPublicIP net.IP
	// HostPublicIP6 - host's public ipv6 endpoint
	HostPublicIP6 net.IP
	// HostNatType - host's NAT type
	HostNatType string
)

// Config configuration for netclient and host as a whole
type Config struct {
	models.Host
	PrivateKey        wgtypes.Key          `json:"privatekey" yaml:"privatekey"`
	TrafficKeyPrivate []byte               `json:"traffickeyprivate" yaml:"traffickeyprivate"`
	HostPeers         []wgtypes.PeerConfig `json:"-" yaml:"-"`
	InitType          InitType             `json:"inittype" yaml:"inittype"`
	//for Internet gateway
	OriginalDefaultGatewayIp net.IP `json:"original_default_gateway_ip_old" yaml:"original_default_gateway_ip_old"`
	CurrGwNmIP               net.IP `json:"curr_gw_nm_ip" yaml:"curr_gw_nm_ip"`
	//for manage DNS
	DNSManagerType string   `json:"dns_manager_type" yaml:"dns_manager_type"`
	NameServers    []string `json:"name_servers" yaml:"name_servers"`
	DNSSearch      string   `json:"dns_search" yaml:"dns_search"`
	DNSOptions     string   `json:"dns_options" yaml:"dns_options"`
}

func init() {
	Servers = make(map[string]Server)
	Nodes = make(map[string]Node)
}

// UpdateNetclient updates the in memory version of the host configuration
func UpdateNetclient(c Config) {
	netclientCfgMutex.Lock()
	defer netclientCfgMutex.Unlock()
	if c.Verbosity != logger.Verbosity {
		slog.Info("Logging verbosity updated to", "verbosity", strconv.Itoa(logger.Verbosity))
	}
	logger.Verbosity = c.Verbosity
	ncutils.SetVerbosity(c.Verbosity)
	netclient = c
}

func UpdateHost(host *models.Host) (resetInterface, restart, sendHostUpdate bool) {
	hostCfg := Netclient()
	if hostCfg == nil || host == nil {
		return
	}
	if host.ListenPort != 0 && hostCfg.ListenPort != host.ListenPort {
		// check if new port is free, otherwise don't update
		if !ncutils.IsPortFree(host.ListenPort) {
			// send the host update to server with actual port on the interface
			host.ListenPort = hostCfg.ListenPort
			sendHostUpdate = true
		}
		restart = true
	}
	if host.MTU != 0 && hostCfg.MTU != host.MTU {
		resetInterface = true
	}
	// do not update fields that should not be changed by server
	host.OS = hostCfg.OS
	host.FirewallInUse = hostCfg.FirewallInUse
	host.DaemonInstalled = hostCfg.DaemonInstalled
	host.ID = hostCfg.ID
	host.Version = hostCfg.Version
	host.MacAddress = hostCfg.MacAddress
	host.PublicKey = hostCfg.PublicKey
	host.TrafficKeyPublic = hostCfg.TrafficKeyPublic
	// don't update any public ports coming from server,overwrite the values
	host.WgPublicListenPort = hostCfg.WgPublicListenPort
	if !host.IsStatic {
		// don't update nil endpoint
		if host.EndpointIP == nil {
			host.EndpointIP = hostCfg.EndpointIP
		}
		if host.EndpointIPv6 == nil {
			host.EndpointIPv6 = hostCfg.EndpointIPv6
		}
	}

	// store password before updating
	host.HostPass = hostCfg.HostPass
	hostCfg.Host = *host
	UpdateNetclient(*hostCfg)
	WriteNetclientConfig()
	return
}

// Netclient returns a pointer to the im memory version of the host configuration
func Netclient() *Config {
	netclientCfgMutex.RLock()
	defer netclientCfgMutex.RUnlock()
	return &netclient
}

// UpdateHostPeers - updates host peer map in the netclient config
func UpdateHostPeers(peers []wgtypes.PeerConfig) {
	netclientCfgMutex.Lock()
	defer netclientCfgMutex.Unlock()
	netclient.HostPeers = peers
}

// DeleteServerHostPeerCfg - deletes the host peers for the server
func DeleteServerHostPeerCfg() {
	netclientCfgMutex.Lock()
	defer netclientCfgMutex.Unlock()
	netclient.HostPeers = []wgtypes.PeerConfig{}
}

// DeleteClientNodes - delete the nodes in client config
func DeleteClientNodes() {
	netclientCfgMutex.Lock()
	defer netclientCfgMutex.Unlock()
	netclient.Nodes = []string{}
}

// RemoveServerHostPeerCfg - sets remove flag for all peers on the given server peers
func RemoveServerHostPeerCfg() {
	netclient := Netclient()
	if netclient.HostPeers == nil {
		netclient.HostPeers = []wgtypes.PeerConfig{}
		return
	}
	peers := netclient.HostPeers
	for i := range peers {
		peer := peers[i]
		peer.Remove = true
		peers[i] = peer
	}
	netclient.HostPeers = peers
	UpdateNetclient(*netclient)
	_ = WriteNetclientConfig()
}

// SetVersion - sets version for use by other packages
func SetVersion(ver string) {
	Version = ver
}

// ReadNetclientConfig reads the host configuration file and returns it as an instance.
func ReadNetclientConfig() (*Config, error) {
	netclientl := Config{}
	var err error
	defer func() {
		if err == nil {
			netclientCfgMutex.Lock()
			netclient = Config{}
			netclient = netclientl
			netclientCfgMutex.Unlock()
		}
	}()
	lockfile := filepath.Join(os.TempDir(), ConfigLockfile)
	file := GetNetclientPath() + "netclient.json"
	if _, err := os.Stat(file); err != nil {
		if os.IsNotExist(err) {
			if err := os.MkdirAll(GetNetclientPath(), os.ModePerm); err != nil {
				slog.Info("error creating netclient config directory", "error", err.Error())
			}
			if err := os.Chmod(GetNetclientPath(), 0775); err != nil {
				slog.Info("error setting permissions on netclient config directory", "error", err.Error())
			}
			err = WriteNetclientConfig()
			if err != nil {
				logger.FatalLog("failed to initialize netclient config", err.Error())
			}
		} else {
			return nil, err
		}
	}
	if err = Lock(lockfile); err != nil {
		return nil, err
	}
	defer Unlock(lockfile)
	f, ferr := os.Open(file)
	if ferr != nil {
		err = ferr
		return nil, err
	}
	defer f.Close()
	if err = json.NewDecoder(f).Decode(&netclientl); err != nil {
		return nil, err
	}
	return &netclientl, nil
}

// WriteNetclientConfiig writes the in memory host configuration to disk

func WriteNetclientConfig() error {
	lockfile := filepath.Join(os.TempDir(), ConfigLockfile)
	configDir := GetNetclientPath()
	file := filepath.Join(configDir, "netclient.json")
	tmpFile := file + ".tmp"
	backupFile := file + ".bak"

	// Ensure config directory exists
	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		if err := os.MkdirAll(configDir, os.ModePerm); err != nil {
			return fmt.Errorf("failed to create config directory: %w", err)
		}
		if err := os.Chmod(configDir, 0775); err != nil {
			return fmt.Errorf("failed to chmod config directory: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("error checking config directory: %w", err)
	}

	// Acquire lock
	if lerr := Lock(lockfile); lerr != nil {
		return fmt.Errorf("failed to obtain lockfile: %w", lerr)
	}
	defer Unlock(lockfile)

	// Open temp file
	f, err := os.OpenFile(tmpFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0700)
	if err != nil {
		return fmt.Errorf("failed to create temp config file: %w", err)
	}

	// Get config safely
	netclientCfgMutex.Lock()
	netclientI := netclient
	netclientCfgMutex.Unlock()

	// Write JSON
	j := json.NewEncoder(f)
	j.SetIndent("", "   ")
	if err := j.Encode(netclientI); err != nil {
		f.Close()
		return fmt.Errorf("failed to encode config: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("failed to sync config to disk: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	// Optional delay for Windows to release file handles
	if runtime.GOOS == "windows" {
		time.Sleep(50 * time.Millisecond)
		_ = os.Remove(file)
	}

	// Remove previous backup if it exists
	_ = os.Remove(backupFile)

	// Backup existing config
	if _, err := os.Stat(file); err == nil {
		if err := os.Rename(file, backupFile); err != nil {
			return fmt.Errorf("failed to backup existing config: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("error checking existing config: %w", err)
	}

	// Rename temp -> final
	if err := os.Rename(tmpFile, file); err != nil {
		return fmt.Errorf("failed to move temp config into place: %w", err)
	}

	return nil
}

// GetNetclientPath - returns path to netclient config directory
func GetNetclientPath() string {
	if runtime.GOOS == "windows" {
		return WindowsAppDataPath
	} else if runtime.GOOS == "darwin" {
		return MacAppDataPath
	} else {
		return LinuxAppDataPath
	}
}

// GetNetclientInstallPath returns the full path where netclient should be installed based on OS
func GetNetclientInstallPath() string {
	switch runtime.GOOS {
	case "windows":
		return GetNetclientPath() + "netclient.exe"
	case "macos":
		return "/usr/local/bin/netclient"
	default:
		return "/usr/bin/netclient"
	}
}

// Lock creates a lockfile with pid as contents
// if lockfile exists but belongs to defunct process
// the existing lockfile will be deleted and new one created
// if unable to create within TIMEOUT returns error
func Lock(lockfile string) error {
	debug := netclient.Debug
	start := time.Now()
	pid := os.Getpid()
	if debug {
		logger.Log(0, "lock try")
	}
	for {
		if _, err := os.Stat(lockfile); !errors.Is(err, os.ErrNotExist) {
			if debug {
				logger.Log(0, "file exists")
			}
			bytes, err := os.ReadFile(lockfile)
			if err != nil || len(bytes) == 0 {
				_ = os.Remove(lockfile)
			} else {
				var owner int
				if err := json.Unmarshal(bytes, &owner); err != nil {
					_ = os.Remove(lockfile)
				} else {
					if IsPidDead(owner) {
						if err := os.Remove(lockfile); err != nil && debug {
							logger.Log(0, "error removing lockfile", err.Error())
						}
					}
				}
			}
		} else {
			bytes, _ := json.Marshal(pid)
			if err := os.WriteFile(lockfile, bytes, os.ModePerm); err != nil && debug {
				logger.Log(0, "unable to write to lockfile: ", err.Error())
			} else {
				return nil
			}
		}
		if debug {
			logger.Log(0, "unable to get lock")
		}
		if time.Since(start) > Timeout {
			return errors.New("TIMEOUT")
		}
		time.Sleep(time.Millisecond * 100)
	}
}

// Unlock removes a lockfile if contents of lockfile match current pid
// also removes lockfile if owner process is no longer running
// will return TIMEOUT error if timeout exceeded
func Unlock(lockfile string) error {
	var pid int
	debug := netclient.Debug
	start := time.Now()
	if debug {
		logger.Log(0, "unlock try")
	}
	for {
		bytes, err := os.ReadFile(lockfile)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			if debug {
				logger.Log(0, "error reading file", err.Error())
			}
			return err
		}
		if debug {
			logger.Log(0, "lockfile exists")
		}
		if err := json.Unmarshal(bytes, &pid); err == nil {
			if pid == os.Getpid() {
				if err := os.Remove(lockfile); err == nil {
					if debug {
						logger.Log(0, "removed lockfile")

					}
					return nil
				} else {
					if debug {
						logger.Log(0, "error removing file", err.Error())
					}
				}
			} else {
				if debug {
					logger.Log(0, "wrong pid")
				}
				if IsPidDead(pid) {
					if err := os.Remove(lockfile); err != nil && debug {
						logger.Log(0, "error removing lockfile", err.Error())
					}
				}
			}
		} else {
			if debug {
				logger.Log(0, "unmarshal err ", err.Error())
			}
		}
		if debug {
			logger.Log(0, "unable to unlock")
		}
		if time.Since(start) > Timeout {
			return errors.New("TIMEOUT")
		}
		time.Sleep(time.Millisecond * 100)
	}
}

// IsPidDead checks if given pid is not running
func IsPidDead(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return true
	}
	//FindProcess always returns err = nil on linux
	err = process.Signal(syscall.Signal(0))
	return errors.Is(err, os.ErrProcessDone)
}

// FormatName ensures name is in character set and is proper length
// Sets name to blank on failure
func FormatName(name string) string {
	if !InCharSet(name) {
		name = ncutils.DNSFormatString(name)
	}
	if len(name) > MaxNameLength {
		name = ncutils.ShortenString(name, MaxNameLength)
	}
	if !InCharSet(name) || len(name) > MaxNameLength {
		logger.Log(1, "could not properly format name, setting to blank")
		name = ""
	}
	return name
}

// InCharSet verifies if all chars in string are part of defined charset
func InCharSet(name string) bool {
	charset := "abcdefghijklmnopqrstuvwxyz1234567890-"
	for _, char := range name {
		if !strings.Contains(charset, strings.ToLower(string(char))) {
			return false
		}
	}
	return true
}

// Convert converts netclient host/node struct to netmaker host/node structs
func Convert(h *Config, n *Node) (models.Host, models.Node) {
	var host models.Host
	var node models.Node
	temp, err := json.Marshal(h)
	if err != nil {
		logger.Log(0, "host marshal error", h.Name, err.Error())
	}
	if err := json.Unmarshal(temp, &host); err != nil {
		logger.Log(0, "host unmarshal err", h.Name, err.Error())
	}
	temp, err = json.Marshal(n)
	if err != nil {
		logger.Log(0, "node marshal error", h.Name, err.Error())
	}
	if err := json.Unmarshal(temp, &node); err != nil {
		logger.Log(0, "node unmarshal err", h.Name, err.Error())
	}
	return host, node
}

// setFirewall - determine and record firewall in use
func SetFirewall() {
	if ncutils.IsLinux() {
		if ncutils.IsIPTablesPresent() {
			netclient.FirewallInUse = models.FIREWALL_IPTABLES
		} else if ncutils.IsNFTablesPresent() {
			netclient.FirewallInUse = models.FIREWALL_NFTABLES
		} else {
			netclient.FirewallInUse = models.FIREWALL_NONE
		}
	} else {
		netclient.FirewallInUse = models.FIREWALL_NONE
	}
}

// FirewallHasChanged - checks if the firewall has changed
func FirewallHasChanged() bool {
	if netclient.FirewallInUse == models.FIREWALL_NONE && !ncutils.IsLinux() {
		return false
	}
	if netclient.FirewallInUse == models.FIREWALL_IPTABLES && ncutils.IsIPTablesPresent() {
		return false
	}
	if netclient.FirewallInUse == models.FIREWALL_NFTABLES && ncutils.IsNFTablesPresent() {
		return false
	}
	return true
}
